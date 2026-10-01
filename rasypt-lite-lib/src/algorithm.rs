use strum::{Display, EnumIter, IntoEnumIterator, IntoStaticStr};

pub(crate) const DEFAULT_AES_ITERATIONS: u32 = 1_000;
pub(crate) const DEFAULT_SM_ITERATIONS: u32 = 10_000;

/// Supported password-based encryption algorithms.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Display, EnumIter, IntoStaticStr)]
#[allow(non_camel_case_types)]
pub enum Algorithm {
    /// PBEWithHMACSHA512AndAES_256 — Jasypt-compatible, AES-256-CBC with PBKDF2-HMAC-SHA512.
    #[default]
    PBEWithHMACSHA512AndAES_256,
    /// PBEWithHMACSM3AndSM4_GCM — SM4-GCM AEAD with HMAC-SM3 key commitment.
    PBEWithHMACSM3AndSM4_GCM,
    /// PBEWithHMACSM3AndSM4_CBC — SM4-CBC with Encrypt-then-HMAC-SM3.
    PBEWithHMACSM3AndSM4_CBC,
}

impl std::str::FromStr for Algorithm {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "PBEWithHMACSHA512AndAES_256" => Ok(Algorithm::PBEWithHMACSHA512AndAES_256),
            "PBEWithHMACSM3AndSM4_GCM" => Ok(Algorithm::PBEWithHMACSM3AndSM4_GCM),
            "PBEWithHMACSM3AndSM4_CBC" => Ok(Algorithm::PBEWithHMACSM3AndSM4_CBC),
            _ => {
                let names: Vec<String> = Algorithm::iter().map(|a| a.to_string()).collect();
                Err(format!(
                    "unknown algorithm: {s}. valid: {}",
                    names.join(", ")
                ))
            }
        }
    }
}

impl Algorithm {
    /// Iterate over all supported algorithms.
    pub fn all() -> impl Iterator<Item = Algorithm> {
        Algorithm::iter()
    }

    pub(crate) fn default_iterations(self) -> u32 {
        match self {
            Algorithm::PBEWithHMACSHA512AndAES_256 => DEFAULT_AES_ITERATIONS,
            _ => DEFAULT_SM_ITERATIONS,
        }
    }
}
