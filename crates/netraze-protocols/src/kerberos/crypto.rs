//! Kerberos encryption profiles used by Active Directory.
//!
//! AES delegates to the audited RFC 3962 implementation in `picky-krb`.
//! RC4-HMAC is implemented here because that crate deliberately omits enctype
//! 23, which remains necessary for NT-hash authentication and legacy AD ticket
//! assessment.

use hmac::{Hmac, Mac};
use md5::{Digest, Md5};
use picky_krb::crypto::{ChecksumSuite, CipherSuite};
use rand::{CryptoRng, RngCore};

use super::KerberosError;
use crate::ntlm::crypto::nt_hash_from_password;
use crate::smb::crypto::rc4_transform;

type HmacMd5 = Hmac<Md5>;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum KerberosEncryptionType {
    Aes256CtsHmacSha196,
    Aes128CtsHmacSha196,
    Rc4Hmac,
}

impl KerberosEncryptionType {
    pub const AES256_NUMBER: i32 = 18;
    pub const AES128_NUMBER: i32 = 17;
    pub const RC4_NUMBER: i32 = 23;

    #[must_use]
    pub const fn number(self) -> i32 {
        match self {
            Self::Aes256CtsHmacSha196 => Self::AES256_NUMBER,
            Self::Aes128CtsHmacSha196 => Self::AES128_NUMBER,
            Self::Rc4Hmac => Self::RC4_NUMBER,
        }
    }

    #[must_use]
    pub const fn key_len(self) -> usize {
        match self {
            Self::Aes256CtsHmacSha196 => 32,
            Self::Aes128CtsHmacSha196 | Self::Rc4Hmac => 16,
        }
    }

    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Aes256CtsHmacSha196 => "AES256-CTS-HMAC-SHA1-96",
            Self::Aes128CtsHmacSha196 => "AES128-CTS-HMAC-SHA1-96",
            Self::Rc4Hmac => "RC4-HMAC",
        }
    }

    pub fn from_number(number: i32) -> Result<Self, KerberosError> {
        match number {
            Self::AES256_NUMBER => Ok(Self::Aes256CtsHmacSha196),
            Self::AES128_NUMBER => Ok(Self::Aes128CtsHmacSha196),
            Self::RC4_NUMBER => Ok(Self::Rc4Hmac),
            _ => Err(KerberosError::Crypto(format!(
                "unsupported Kerberos encryption type {number}"
            ))),
        }
    }
}

impl core::fmt::Display for KerberosEncryptionType {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str(self.name())
    }
}

pub fn derive_password_key(
    encryption_type: KerberosEncryptionType,
    password: &str,
    salt: &[u8],
) -> Result<Vec<u8>, KerberosError> {
    match encryption_type {
        KerberosEncryptionType::Rc4Hmac => Ok(nt_hash_from_password(password).to_vec()),
        KerberosEncryptionType::Aes128CtsHmacSha196 => CipherSuite::Aes128CtsHmacSha196
            .cipher()
            .generate_key_from_password(password.as_bytes(), salt)
            .map_err(|error| KerberosError::Crypto(error.to_string())),
        KerberosEncryptionType::Aes256CtsHmacSha196 => CipherSuite::Aes256CtsHmacSha196
            .cipher()
            .generate_key_from_password(password.as_bytes(), salt)
            .map_err(|error| KerberosError::Crypto(error.to_string())),
    }
}

pub fn encrypt<R: RngCore + CryptoRng>(
    encryption_type: KerberosEncryptionType,
    key: &[u8],
    key_usage: i32,
    plaintext: &[u8],
    rng: &mut R,
) -> Result<Vec<u8>, KerberosError> {
    validate_key(encryption_type, key)?;
    match encryption_type {
        KerberosEncryptionType::Rc4Hmac => {
            let mut confounder = [0_u8; 8];
            rng.fill_bytes(&mut confounder);
            rc4_encrypt_with_confounder(key, key_usage, plaintext, &confounder)
        }
        KerberosEncryptionType::Aes128CtsHmacSha196 => CipherSuite::Aes128CtsHmacSha196
            .cipher()
            .encrypt(key, key_usage, plaintext)
            .map_err(|error| KerberosError::Crypto(error.to_string())),
        KerberosEncryptionType::Aes256CtsHmacSha196 => CipherSuite::Aes256CtsHmacSha196
            .cipher()
            .encrypt(key, key_usage, plaintext)
            .map_err(|error| KerberosError::Crypto(error.to_string())),
    }
}

pub fn decrypt(
    encryption_type: KerberosEncryptionType,
    key: &[u8],
    key_usage: i32,
    ciphertext: &[u8],
) -> Result<Vec<u8>, KerberosError> {
    validate_key(encryption_type, key)?;
    match encryption_type {
        KerberosEncryptionType::Rc4Hmac => rc4_decrypt(key, key_usage, ciphertext),
        KerberosEncryptionType::Aes128CtsHmacSha196 => CipherSuite::Aes128CtsHmacSha196
            .cipher()
            .decrypt(key, key_usage, ciphertext)
            .map_err(|error| KerberosError::Crypto(error.to_string())),
        KerberosEncryptionType::Aes256CtsHmacSha196 => CipherSuite::Aes256CtsHmacSha196
            .cipher()
            .decrypt(key, key_usage, ciphertext)
            .map_err(|error| KerberosError::Crypto(error.to_string())),
    }
}

/// Compute the keyed checksum carried by a TGS authenticator.
///
/// AES uses the RFC 3961 HMAC-SHA1-96 profiles. RC4 uses the RFC 4757
/// `HMAC_MD5` checksum, whose signed checksum type is `-138` on the wire.
pub(crate) fn keyed_checksum(
    encryption_type: KerberosEncryptionType,
    key: &[u8],
    key_usage: i32,
    payload: &[u8],
) -> Result<(i32, Vec<u8>), KerberosError> {
    validate_key(encryption_type, key)?;
    match encryption_type {
        KerberosEncryptionType::Aes256CtsHmacSha196 => Ok((
            16,
            ChecksumSuite::HmacSha196Aes256
                .hasher()
                .checksum(key, key_usage, payload)
                .map_err(|error| KerberosError::Crypto(error.to_string()))?,
        )),
        KerberosEncryptionType::Aes128CtsHmacSha196 => Ok((
            15,
            ChecksumSuite::HmacSha196Aes128
                .hasher()
                .checksum(key, key_usage, payload)
                .map_err(|error| KerberosError::Crypto(error.to_string()))?,
        )),
        KerberosEncryptionType::Rc4Hmac => {
            let signing_key = hmac_md5(key, b"signaturekey\0")?;
            let mut digest_input = Vec::with_capacity(4 + payload.len());
            digest_input.extend_from_slice(&rc4_usage(key_usage).to_le_bytes());
            digest_input.extend_from_slice(payload);
            let digest = Md5::digest(&digest_input);
            Ok((-138, hmac_md5(&signing_key, &digest)?.to_vec()))
        }
    }
}

fn validate_key(encryption_type: KerberosEncryptionType, key: &[u8]) -> Result<(), KerberosError> {
    let expected = encryption_type.key_len();
    if key.len() != expected {
        return Err(KerberosError::InvalidKeyLength {
            encryption_type: encryption_type.name(),
            expected,
            actual: key.len(),
        });
    }
    Ok(())
}

fn rc4_usage(key_usage: i32) -> i32 {
    match key_usage {
        3 => 8,
        23 => 13,
        usage => usage,
    }
}

fn hmac_md5(key: &[u8], data: &[u8]) -> Result<[u8; 16], KerberosError> {
    let mut mac = <HmacMd5 as Mac>::new_from_slice(key)
        .map_err(|error| KerberosError::Crypto(error.to_string()))?;
    mac.update(data);
    Ok(mac.finalize().into_bytes().into())
}

fn rc4_encrypt_with_confounder(
    key: &[u8],
    key_usage: i32,
    plaintext: &[u8],
    confounder: &[u8; 8],
) -> Result<Vec<u8>, KerberosError> {
    let usage = rc4_usage(key_usage).to_le_bytes();
    let integrity_key = hmac_md5(key, &usage)?;
    let mut basic_plaintext = Vec::with_capacity(8 + plaintext.len());
    basic_plaintext.extend_from_slice(confounder);
    basic_plaintext.extend_from_slice(plaintext);
    let checksum = hmac_md5(&integrity_key, &basic_plaintext)?;
    let encryption_key = hmac_md5(&integrity_key, &checksum)?;
    let encrypted =
        rc4_transform(&basic_plaintext, &encryption_key).map_err(KerberosError::Crypto)?;
    let mut output = Vec::with_capacity(16 + encrypted.len());
    output.extend_from_slice(&checksum);
    output.extend_from_slice(&encrypted);
    Ok(output)
}

fn rc4_decrypt(key: &[u8], key_usage: i32, ciphertext: &[u8]) -> Result<Vec<u8>, KerberosError> {
    if ciphertext.len() < 24 {
        return Err(KerberosError::CiphertextTooShort {
            encryption_type: KerberosEncryptionType::Rc4Hmac.name(),
            actual: ciphertext.len(),
        });
    }
    let checksum = &ciphertext[..16];
    let integrity_key = hmac_md5(key, &rc4_usage(key_usage).to_le_bytes())?;
    let encryption_key = hmac_md5(&integrity_key, checksum)?;
    let plaintext =
        rc4_transform(&ciphertext[16..], &encryption_key).map_err(KerberosError::Crypto)?;
    let expected = hmac_md5(&integrity_key, &plaintext)?;
    if !constant_time_eq(checksum, &expected) {
        return Err(KerberosError::Integrity);
    }
    Ok(plaintext[8..].to_vec())
}

fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    left.iter()
        .zip(right)
        .fold(0_u8, |difference, (left, right)| {
            difference | (left ^ right)
        })
        == 0
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::{CryptoRng, RngCore};

    struct FixedRng([u8; 8]);

    impl RngCore for FixedRng {
        fn next_u32(&mut self) -> u32 {
            u32::from_le_bytes(self.0[..4].try_into().unwrap())
        }

        fn next_u64(&mut self) -> u64 {
            u64::from_le_bytes(self.0)
        }

        fn fill_bytes(&mut self, destination: &mut [u8]) {
            for (index, byte) in destination.iter_mut().enumerate() {
                *byte = self.0[index % self.0.len()];
            }
        }

        fn try_fill_bytes(&mut self, destination: &mut [u8]) -> Result<(), rand::Error> {
            self.fill_bytes(destination);
            Ok(())
        }
    }

    impl CryptoRng for FixedRng {}

    #[test]
    fn rc4_hmac_matches_impacket_known_answer() {
        let key = (0_u8..16).collect::<Vec<_>>();
        let plaintext = b"NetRaze Kerberos RFC 4757";
        let mut rng = FixedRng(*b"12345678");
        let ciphertext = encrypt(
            KerberosEncryptionType::Rc4Hmac,
            &key,
            1,
            plaintext,
            &mut rng,
        )
        .unwrap();
        assert_eq!(
            to_hex(&ciphertext),
            "416fe2ba807a4ef1f25c0967ab9fe1f84b8fe3be8d563cff1958c7f4098544c6c73299ad00817fe889ef237f297c59875b"
        );
        assert_eq!(
            decrypt(KerberosEncryptionType::Rc4Hmac, &key, 1, &ciphertext).unwrap(),
            plaintext
        );
    }

    #[test]
    fn rc4_rejects_modified_ciphertext() {
        let key = [7_u8; 16];
        let mut rng = FixedRng([9_u8; 8]);
        let mut ciphertext = encrypt(
            KerberosEncryptionType::Rc4Hmac,
            &key,
            1,
            b"message",
            &mut rng,
        )
        .unwrap();
        *ciphertext.last_mut().unwrap() ^= 1;
        assert!(matches!(
            decrypt(KerberosEncryptionType::Rc4Hmac, &key, 1, &ciphertext),
            Err(KerberosError::Integrity)
        ));
    }

    #[test]
    fn rc4_keyed_checksum_matches_impacket_fixture() {
        let key = (0_u8..16).collect::<Vec<_>>();
        let (checksum_type, checksum) = keyed_checksum(
            KerberosEncryptionType::Rc4Hmac,
            &key,
            6,
            b"NetRaze TGS body fixture",
        )
        .unwrap();
        assert_eq!(checksum_type, -138);
        assert_eq!(to_hex(&checksum), "2eb4b8038f1046dbd9cb50628a502669");
    }

    #[test]
    fn aes_string_to_key_matches_rfc_3962_vectors() {
        let salt = b"ATHENA.MIT.EDUraeburn";
        let aes128 = derive_password_key(
            KerberosEncryptionType::Aes128CtsHmacSha196,
            "password",
            salt,
        )
        .unwrap();
        let aes256 = derive_password_key(
            KerberosEncryptionType::Aes256CtsHmacSha196,
            "password",
            salt,
        )
        .unwrap();
        assert_eq!(to_hex(&aes128), "fca822951813fb252154c883f5ee1cf4");
        assert_eq!(
            to_hex(&aes256),
            "01b897121d933ab44b47eb5494db15e50eb74530dbdae9b634d65020ff5d88c1"
        );
    }

    fn to_hex(value: &[u8]) -> String {
        value.iter().map(|byte| format!("{byte:02x}")).collect()
    }
}
