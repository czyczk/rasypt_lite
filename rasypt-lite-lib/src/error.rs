use thiserror::Error;

/// Errors produced by decryption and `ENC(...)` handling.
///
/// All algorithm-level authentication failures collapse into
/// [`Error::DecryptionFailed`] to avoid leaking *why* a decryption failed.
#[derive(Debug, Error)]
pub enum Error {
    #[error("Ciphertext too short")]
    CiphertextTooShort,
    #[error("Failed to decode base64: {0}")]
    FailedToDecodeBase64(#[from] base64::DecodeError),
    #[error("Failed to decrypt (bad padding or wrong password): {0}")]
    FailedToDecryptDueToBadPaddingOrWrongPassword(cbc::cipher::block_padding::Error),
    #[error("Invalid decryption result: {0}")]
    InvalidDecryptionResult(#[from] std::string::FromUtf8Error),
    #[error("Not an ENC(...) value")]
    NotEncValue,
    #[error("Decryption failed")]
    DecryptionFailed,
}
