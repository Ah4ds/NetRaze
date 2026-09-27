use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

use super::KerberosError;

pub const DEFAULT_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
pub const DEFAULT_OPERATION_TIMEOUT: Duration = Duration::from_secs(20);
pub const DEFAULT_MAX_RESPONSE_SIZE: usize = 16 * 1024 * 1024;

/// Limits and endpoint used for one KDC TCP exchange.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KdcTransportConfig {
    pub endpoint: String,
    pub connect_timeout: Duration,
    pub operation_timeout: Duration,
    pub max_response_size: usize,
}

impl KdcTransportConfig {
    #[must_use]
    pub fn new(endpoint: impl Into<String>) -> Self {
        Self {
            endpoint: normalize_endpoint(endpoint.into()),
            connect_timeout: DEFAULT_CONNECT_TIMEOUT,
            operation_timeout: DEFAULT_OPERATION_TIMEOUT,
            max_response_size: DEFAULT_MAX_RESPONSE_SIZE,
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

/// Stateless KDC TCP transport. Each exchange uses a fresh connection so a
/// timed-out or malformed peer cannot poison later assessment requests.
#[derive(Debug, Clone)]
pub struct KdcTransport {
    config: KdcTransportConfig,
}

impl KdcTransport {
    /// Validate and construct a KDC transport.
    pub fn new(config: KdcTransportConfig) -> Result<Self, KerberosError> {
        if config.endpoint.is_empty() || config.max_response_size == 0 {
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpListener;

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
        assert_eq!(transport.exchange(b"request").await.unwrap(), b"hello");
    }

    #[tokio::test]
    async fn rejects_empty_and_oversized_frames_before_allocating() {
        let endpoint = server_for(0_u32.to_be_bytes(), vec![]).await;
        let transport = KdcTransport::new(KdcTransportConfig::new(endpoint)).unwrap();
        assert!(matches!(
            transport.exchange(b"request").await,
            Err(KerberosError::EmptyFrame)
        ));

        let endpoint = server_for(9_u32.to_be_bytes(), vec![]).await;
        let mut config = KdcTransportConfig::new(endpoint);
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
        let transport = KdcTransport::new(KdcTransportConfig::new(endpoint)).unwrap();
        assert!(matches!(
            transport.exchange(b"request").await,
            Err(KerberosError::Io { .. })
        ));
    }
}
