use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket, lookup_host};
use tokio::time::timeout;

use picky_krb::messages::KrbError;

use super::KerberosError;

pub const DEFAULT_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
pub const DEFAULT_OPERATION_TIMEOUT: Duration = Duration::from_secs(20);
pub const DEFAULT_UDP_TIMEOUT: Duration = Duration::from_secs(2);
pub const DEFAULT_MAX_RESPONSE_SIZE: usize = 16 * 1024 * 1024;
pub const DEFAULT_MAX_UDP_RESPONSE_SIZE: usize = 65_507;

/// Network transports available for KDC exchanges.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KdcTransportPolicy {
    /// Prefer RFC 4120 UDP and retry the same request over TCP when UDP cannot
    /// deliver a complete response.
    UdpThenTcp,
    TcpOnly,
    UdpOnly,
}

/// Limits and endpoint used for one KDC TCP exchange.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KdcTransportConfig {
    pub endpoint: String,
    pub connect_timeout: Duration,
    pub operation_timeout: Duration,
    pub udp_timeout: Duration,
    pub max_response_size: usize,
    pub max_udp_response_size: usize,
    pub policy: KdcTransportPolicy,
}

impl KdcTransportConfig {
    #[must_use]
    pub fn new(endpoint: impl Into<String>) -> Self {
        Self {
            endpoint: normalize_endpoint(endpoint.into()),
            connect_timeout: DEFAULT_CONNECT_TIMEOUT,
            operation_timeout: DEFAULT_OPERATION_TIMEOUT,
            udp_timeout: DEFAULT_UDP_TIMEOUT,
            max_response_size: DEFAULT_MAX_RESPONSE_SIZE,
            max_udp_response_size: DEFAULT_MAX_UDP_RESPONSE_SIZE,
            policy: KdcTransportPolicy::UdpThenTcp,
        }
    }
}

fn normalize_endpoint(endpoint: String) -> String {
    let endpoint = endpoint.trim();
    if endpoint.is_empty() {
        return String::new();
    }
    if endpoint.starts_with('[') {
        return if endpoint.contains("]:") {
            endpoint.to_owned()
        } else {
            format!("{endpoint}:88")
        };
    }
    if endpoint
        .rsplit_once(':')
        .is_some_and(|(_, port)| port.parse::<u16>().is_ok())
    {
        endpoint.to_owned()
    } else {
        format!("{endpoint}:88")
    }
}

/// Stateless KDC UDP/TCP transport. Each exchange uses a fresh socket so a
/// timed-out or malformed peer cannot poison later assessment requests.
#[derive(Debug, Clone)]
pub struct KdcTransport {
    config: KdcTransportConfig,
}

impl KdcTransport {
    /// Validate and construct a KDC transport.
    pub fn new(config: KdcTransportConfig) -> Result<Self, KerberosError> {
        if config.endpoint.is_empty()
            || config.max_response_size == 0
            || config.max_udp_response_size == 0
            || config.max_udp_response_size > DEFAULT_MAX_UDP_RESPONSE_SIZE
        {
            return Err(KerberosError::InvalidEndpoint(config.endpoint));
        }
        Ok(Self { config })
    }

    #[must_use]
    pub fn config(&self) -> &KdcTransportConfig {
        &self.config
    }

    /// Send one DER message and return exactly one bounded DER reply.
    pub async fn exchange(&self, request: &[u8]) -> Result<Vec<u8>, KerberosError> {
        if request.is_empty() || request.len() > u32::MAX as usize {
            return Err(KerberosError::InvalidMessage(format!(
                "request length {} cannot be framed",
                request.len()
            )));
        }

        match self.config.policy {
            KdcTransportPolicy::TcpOnly => self.exchange_tcp(request).await,
            KdcTransportPolicy::UdpOnly => self.exchange_udp(request).await,
            KdcTransportPolicy::UdpThenTcp => match self.exchange_udp(request).await {
                Ok(response) if !response_requires_tcp(&response) => Ok(response),
                Ok(_) | Err(_) => self.exchange_tcp(request).await,
            },
        }
    }

    async fn exchange_tcp(&self, request: &[u8]) -> Result<Vec<u8>, KerberosError> {
        let endpoint = self.config.endpoint.clone();
        let mut stream = timeout(self.config.connect_timeout, TcpStream::connect(&endpoint))
            .await
            .map_err(|_| KerberosError::ConnectTimeout {
                endpoint: endpoint.clone(),
            })?
            .map_err(|source| KerberosError::io(&endpoint, source))?;

        timeout(self.config.operation_timeout, async {
            stream
                .write_all(&(request.len() as u32).to_be_bytes())
                .await
                .map_err(|source| KerberosError::io(&endpoint, source))?;
            stream
                .write_all(request)
                .await
                .map_err(|source| KerberosError::io(&endpoint, source))?;
            stream
                .flush()
                .await
                .map_err(|source| KerberosError::io(&endpoint, source))?;

            let mut header = [0_u8; 4];
            stream
                .read_exact(&mut header)
                .await
                .map_err(|source| KerberosError::io(&endpoint, source))?;
            let announced = u32::from_be_bytes(header) as usize;
            if announced == 0 {
                return Err(KerberosError::EmptyFrame);
            }
            if announced > self.config.max_response_size {
                return Err(KerberosError::ResponseTooLarge {
                    announced,
                    limit: self.config.max_response_size,
                });
            }

            let mut response = vec![0_u8; announced];
            stream
                .read_exact(&mut response)
                .await
                .map_err(|source| KerberosError::io(&endpoint, source))?;
            Ok(response)
        })
        .await
        .map_err(|_| KerberosError::OperationTimeout { endpoint })?
    }

    async fn exchange_udp(&self, request: &[u8]) -> Result<Vec<u8>, KerberosError> {
        if request.len() > self.config.max_udp_response_size {
            return Err(KerberosError::ResponseTooLarge {
                announced: request.len(),
                limit: self.config.max_udp_response_size,
            });
        }
        let endpoint = self.config.endpoint.clone();
        timeout(self.config.udp_timeout, async {
            let remote = lookup_host(&endpoint)
                .await
                .map_err(|source| KerberosError::io(&endpoint, source))?
                .next()
                .ok_or_else(|| KerberosError::InvalidEndpoint(endpoint.clone()))?;
            let bind_address = if remote.is_ipv4() {
                "0.0.0.0:0"
            } else {
                "[::]:0"
            };
            let socket = UdpSocket::bind(bind_address)
                .await
                .map_err(|source| KerberosError::io(&endpoint, source))?;
            socket
                .connect(remote)
                .await
                .map_err(|source| KerberosError::io(&endpoint, source))?;
            socket
                .send(request)
                .await
                .map_err(|source| KerberosError::io(&endpoint, source))?;
            let mut response = vec![0_u8; self.config.max_udp_response_size];
            let received = socket
                .recv(&mut response)
                .await
                .map_err(|source| KerberosError::io(&endpoint, source))?;
            if received == 0 {
                return Err(KerberosError::EmptyFrame);
            }
            // `recv` does not expose MSG_TRUNC. Filling the entire bounded
            // buffer is therefore treated as truncation so UdpThenTcp retries.
            if received == response.len() {
                return Err(KerberosError::ResponseTooLarge {
                    announced: received.saturating_add(1),
                    limit: response.len(),
                });
            }
            response.truncate(received);
            Ok(response)
        })
        .await
        .map_err(|_| KerberosError::OperationTimeout { endpoint })?
    }
}

fn response_requires_tcp(response: &[u8]) -> bool {
    const KRB_ERROR_TAG: u8 = 0x7e;
    const KRB_ERR_RESPONSE_TOO_BIG: i32 = 52;
    if response.first() != Some(&KRB_ERROR_TAG) {
        return false;
    }
    picky_asn1_der::from_bytes::<KrbError>(response)
        .is_ok_and(|error| error.0.error_code.0 as i32 == KRB_ERR_RESPONSE_TOO_BIG)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::{TcpListener, UdpSocket};

    async fn server_for(response_header: [u8; 4], response_parts: Vec<Vec<u8>>) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = listener.local_addr().unwrap().to_string();
        tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut header = [0_u8; 4];
            stream.read_exact(&mut header).await.unwrap();
            let mut request = vec![0; u32::from_be_bytes(header) as usize];
            stream.read_exact(&mut request).await.unwrap();
            assert_eq!(request, b"request");
            for byte in response_header {
                stream.write_all(&[byte]).await.unwrap();
            }
            for part in response_parts {
                stream.write_all(&part).await.unwrap();
            }
        });
        endpoint
    }

    #[test]
    fn endpoint_defaults_to_tcp_88() {
        assert_eq!(
            KdcTransportConfig::new("dc.example.test").endpoint,
            "dc.example.test:88"
        );
        assert_eq!(
            KdcTransportConfig::new("127.0.0.1:1088").endpoint,
            "127.0.0.1:1088"
        );
        assert_eq!(KdcTransportConfig::new("[::1]").endpoint, "[::1]:88");
    }

    #[tokio::test]
    async fn reads_fragmented_header_and_payload() {
        let endpoint = server_for(5_u32.to_be_bytes(), vec![b"he".to_vec(), b"llo".to_vec()]).await;
        let transport = KdcTransport::new(KdcTransportConfig::new(endpoint)).unwrap();
        let mut config = transport.config().clone();
        config.policy = KdcTransportPolicy::TcpOnly;
        let transport = KdcTransport::new(config).unwrap();
        assert_eq!(transport.exchange(b"request").await.unwrap(), b"hello");
    }

    #[tokio::test]
    async fn rejects_empty_and_oversized_frames_before_allocating() {
        let endpoint = server_for(0_u32.to_be_bytes(), vec![]).await;
        let mut config = KdcTransportConfig::new(endpoint);
        config.policy = KdcTransportPolicy::TcpOnly;
        let transport = KdcTransport::new(config).unwrap();
        assert!(matches!(
            transport.exchange(b"request").await,
            Err(KerberosError::EmptyFrame)
        ));

        let endpoint = server_for(9_u32.to_be_bytes(), vec![]).await;
        let mut config = KdcTransportConfig::new(endpoint);
        config.policy = KdcTransportPolicy::TcpOnly;
        config.max_response_size = 8;
        let transport = KdcTransport::new(config).unwrap();
        assert!(matches!(
            transport.exchange(b"request").await,
            Err(KerberosError::ResponseTooLarge {
                announced: 9,
                limit: 8
            })
        ));
    }

    #[tokio::test]
    async fn reports_eof_during_payload() {
        let endpoint = server_for(5_u32.to_be_bytes(), vec![b"no".to_vec()]).await;
        let mut config = KdcTransportConfig::new(endpoint);
        config.policy = KdcTransportPolicy::TcpOnly;
        let transport = KdcTransport::new(config).unwrap();
        assert!(matches!(
            transport.exchange(b"request").await,
            Err(KerberosError::Io { .. })
        ));
    }

    #[tokio::test]
    async fn udp_exchange_has_no_tcp_record_prefix() {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let endpoint = socket.local_addr().unwrap().to_string();
        tokio::spawn(async move {
            let mut request = [0_u8; 32];
            let (received, peer) = socket.recv_from(&mut request).await.unwrap();
            assert_eq!(&request[..received], b"request");
            socket.send_to(b"response", peer).await.unwrap();
        });
        let mut config = KdcTransportConfig::new(endpoint);
        config.policy = KdcTransportPolicy::UdpOnly;
        let transport = KdcTransport::new(config).unwrap();
        assert_eq!(transport.exchange(b"request").await.unwrap(), b"response");
    }

    #[tokio::test]
    async fn udp_timeout_falls_back_to_tcp() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = listener.local_addr().unwrap().to_string();
        tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut header = [0_u8; 4];
            stream.read_exact(&mut header).await.unwrap();
            let mut request = vec![0_u8; u32::from_be_bytes(header) as usize];
            stream.read_exact(&mut request).await.unwrap();
            stream.write_all(&8_u32.to_be_bytes()).await.unwrap();
            stream.write_all(b"fallback").await.unwrap();
        });
        let mut config = KdcTransportConfig::new(endpoint);
        config.udp_timeout = Duration::from_millis(25);
        let transport = KdcTransport::new(config).unwrap();
        assert_eq!(transport.exchange(b"request").await.unwrap(), b"fallback");
    }
}
