//! Best-effort erasure of in-memory secrets.

use zeroize::Zeroize;

/// Clear a `String`'s heap buffer by zeroizing its bytes and replacing it with an empty string.
pub fn clear_string(s: &mut String) {
    let mut bytes = std::mem::take(s).into_bytes();
    bytes.zeroize();
}

/// Clear an `Option<String>` by zeroizing the inner string (if present) and setting it to `None`.
pub fn clear_option_string(o: &mut Option<String>) {
    if let Some(s) = o.take() {
        let mut bytes = s.into_bytes();
        bytes.zeroize();
    }
}
