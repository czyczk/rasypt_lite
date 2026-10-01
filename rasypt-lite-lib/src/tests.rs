use base64::{engine::general_purpose::STANDARD as B64, Engine};
use strum::IntoEnumIterator;

use super::*;
use crate::constants::{
    HMAC_SM3_OUTPUT_SIZE, SALT_SIZE, SM4_BLOCK_SIZE, SM4_GCM_NONCE_SIZE, SM4_GCM_TAG_SIZE,
};
use crate::sm4::{sm4_gcm_decrypt, sm4_gcm_encrypt};

const TEST_PASSWORD: &str = "mySecretPassword";
const TEST_PLAINTEXT: &str = "Hello, World! This is a test message.";

// ── AES-256-CBC ──────────────────────────────────────────────

#[test]
fn aes_round_trip() {
    let encrypted = encrypt_with(
        Algorithm::PBEWithHMACSHA512AndAES_256,
        TEST_PASSWORD,
        TEST_PLAINTEXT,
    );
    let decrypted = decrypt_with(
        Algorithm::PBEWithHMACSHA512AndAES_256,
        TEST_PASSWORD,
        &encrypted,
    )
    .unwrap();
    assert_eq!(decrypted, TEST_PLAINTEXT);
}

#[test]
fn aes_backward_compat_round_trip() {
    // Old API still works
    let encrypted = encrypt(TEST_PASSWORD, TEST_PLAINTEXT);
    let decrypted = decrypt(TEST_PASSWORD, &encrypted).unwrap();
    assert_eq!(decrypted, TEST_PLAINTEXT);
}

#[test]
fn aes_enc_wrapper() {
    let encrypted = encrypt(TEST_PASSWORD, "secret");
    let wrapped = format!("ENC({})", encrypted);
    let decrypted = decrypt_enc(&wrapped, TEST_PASSWORD).unwrap();
    assert_eq!(decrypted, "secret");
}

#[test]
fn aes_different_encryptions_differ() {
    let e1 = encrypt(TEST_PASSWORD, TEST_PLAINTEXT);
    let e2 = encrypt(TEST_PASSWORD, TEST_PLAINTEXT);
    assert_ne!(e1, e2);
}

#[test]
fn aes_rejects_too_short() {
    let too_short = B64.encode([0u8; SALT_SIZE + SALT_SIZE]);
    let err = decrypt_with(
        Algorithm::PBEWithHMACSHA512AndAES_256,
        TEST_PASSWORD,
        &too_short,
    )
    .unwrap_err();
    assert!(matches!(err, Error::CiphertextTooShort));
}

// ── SM4-GCM ──────────────────────────────────────────────────

#[test]
fn sm4_gcm_round_trip() {
    let encrypted = encrypt_with(
        Algorithm::PBEWithHMACSM3AndSM4_GCM,
        TEST_PASSWORD,
        TEST_PLAINTEXT,
    );
    let decrypted = decrypt_with(
        Algorithm::PBEWithHMACSM3AndSM4_GCM,
        TEST_PASSWORD,
        &encrypted,
    )
    .unwrap();
    assert_eq!(decrypted, TEST_PLAINTEXT);
}

#[test]
fn sm4_gcm_different_encryptions_differ() {
    let e1 = encrypt_with(
        Algorithm::PBEWithHMACSM3AndSM4_GCM,
        TEST_PASSWORD,
        TEST_PLAINTEXT,
    );
    let e2 = encrypt_with(
        Algorithm::PBEWithHMACSM3AndSM4_GCM,
        TEST_PASSWORD,
        TEST_PLAINTEXT,
    );
    assert_ne!(e1, e2);
}

#[test]
fn sm4_gcm_wrong_password() {
    let encrypted = encrypt_with(
        Algorithm::PBEWithHMACSM3AndSM4_GCM,
        TEST_PASSWORD,
        TEST_PLAINTEXT,
    );
    let result = decrypt_with(
        Algorithm::PBEWithHMACSM3AndSM4_GCM,
        "wrongPassword",
        &encrypted,
    );
    assert!(result.is_err());
}

#[test]
fn sm4_gcm_tampered_ciphertext() {
    let encrypted = encrypt_with(
        Algorithm::PBEWithHMACSM3AndSM4_GCM,
        TEST_PASSWORD,
        TEST_PLAINTEXT,
    );
    let mut data = B64.decode(&encrypted).unwrap();
    // Tamper with the ciphertext (after salt+nonce, before tag+commitment)
    let tamper_pos = SALT_SIZE + SM4_GCM_NONCE_SIZE + 2;
    if tamper_pos < data.len() - SM4_GCM_TAG_SIZE - HMAC_SM3_OUTPUT_SIZE {
        data[tamper_pos] ^= 0x01;
    }
    let tampered = B64.encode(&data);
    let result = decrypt_with(
        Algorithm::PBEWithHMACSM3AndSM4_GCM,
        TEST_PASSWORD,
        &tampered,
    );
    assert!(result.is_err());
}

#[test]
fn sm4_gcm_empty_plaintext() {
    let encrypted = encrypt_with(Algorithm::PBEWithHMACSM3AndSM4_GCM, TEST_PASSWORD, "");
    let decrypted = decrypt_with(
        Algorithm::PBEWithHMACSM3AndSM4_GCM,
        TEST_PASSWORD,
        &encrypted,
    )
    .unwrap();
    assert_eq!(decrypted, "");
}

#[test]
fn sm4_gcm_long_plaintext() {
    let long_input = "A".repeat(10_000);
    let encrypted = encrypt_with(
        Algorithm::PBEWithHMACSM3AndSM4_GCM,
        TEST_PASSWORD,
        &long_input,
    );
    let decrypted = decrypt_with(
        Algorithm::PBEWithHMACSM3AndSM4_GCM,
        TEST_PASSWORD,
        &encrypted,
    )
    .unwrap();
    assert_eq!(decrypted, long_input);
}

#[test]
fn sm4_gcm_rejects_too_short() {
    let too_short = B64.encode([0u8; SALT_SIZE + SM4_GCM_NONCE_SIZE]);
    let err = decrypt_with(
        Algorithm::PBEWithHMACSM3AndSM4_GCM,
        TEST_PASSWORD,
        &too_short,
    )
    .unwrap_err();
    assert!(matches!(err, Error::CiphertextTooShort));
}

#[test]
fn sm4_gcm_cross_algorithm_rejection() {
    // SM4-GCM ciphertext should not decrypt as AES
    let encrypted = encrypt_with(
        Algorithm::PBEWithHMACSM3AndSM4_GCM,
        TEST_PASSWORD,
        TEST_PLAINTEXT,
    );
    let result = decrypt_with(
        Algorithm::PBEWithHMACSHA512AndAES_256,
        TEST_PASSWORD,
        &encrypted,
    );
    assert!(result.is_err());
}

// ── SM4-CBC ──────────────────────────────────────────────────

#[test]
fn sm4_cbc_round_trip() {
    let encrypted = encrypt_with(
        Algorithm::PBEWithHMACSM3AndSM4_CBC,
        TEST_PASSWORD,
        TEST_PLAINTEXT,
    );
    let decrypted = decrypt_with(
        Algorithm::PBEWithHMACSM3AndSM4_CBC,
        TEST_PASSWORD,
        &encrypted,
    )
    .unwrap();
    assert_eq!(decrypted, TEST_PLAINTEXT);
}

#[test]
fn sm4_cbc_different_encryptions_differ() {
    let e1 = encrypt_with(
        Algorithm::PBEWithHMACSM3AndSM4_CBC,
        TEST_PASSWORD,
        TEST_PLAINTEXT,
    );
    let e2 = encrypt_with(
        Algorithm::PBEWithHMACSM3AndSM4_CBC,
        TEST_PASSWORD,
        TEST_PLAINTEXT,
    );
    assert_ne!(e1, e2);
}

#[test]
fn sm4_cbc_wrong_password() {
    let encrypted = encrypt_with(
        Algorithm::PBEWithHMACSM3AndSM4_CBC,
        TEST_PASSWORD,
        TEST_PLAINTEXT,
    );
    let result = decrypt_with(
        Algorithm::PBEWithHMACSM3AndSM4_CBC,
        "wrongPassword",
        &encrypted,
    );
    assert!(result.is_err());
}

#[test]
fn sm4_cbc_tampered_ciphertext() {
    let encrypted = encrypt_with(
        Algorithm::PBEWithHMACSM3AndSM4_CBC,
        TEST_PASSWORD,
        TEST_PLAINTEXT,
    );
    let mut data = B64.decode(&encrypted).unwrap();
    // Tamper with the ciphertext (after salt+iv, before mac)
    let tamper_pos = SALT_SIZE + SM4_BLOCK_SIZE + 2;
    if tamper_pos < data.len() - HMAC_SM3_OUTPUT_SIZE {
        data[tamper_pos] ^= 0x01;
    }
    let tampered = B64.encode(&data);
    let result = decrypt_with(
        Algorithm::PBEWithHMACSM3AndSM4_CBC,
        TEST_PASSWORD,
        &tampered,
    );
    assert!(result.is_err());
}

#[test]
fn sm4_cbc_rejects_too_short() {
    let too_short = B64.encode([0u8; SALT_SIZE + SM4_BLOCK_SIZE]);
    let err = decrypt_with(
        Algorithm::PBEWithHMACSM3AndSM4_CBC,
        TEST_PASSWORD,
        &too_short,
    )
    .unwrap_err();
    assert!(matches!(err, Error::CiphertextTooShort));
}

// ── SM4 cross-mode rejection ─────────────────────────────────

#[test]
fn sm4_gcm_rejects_cbc_ciphertext() {
    let cbc_enc = encrypt_with(
        Algorithm::PBEWithHMACSM3AndSM4_CBC,
        TEST_PASSWORD,
        TEST_PLAINTEXT,
    );
    let result = decrypt_with(Algorithm::PBEWithHMACSM3AndSM4_GCM, TEST_PASSWORD, &cbc_enc);
    assert!(result.is_err());
}

#[test]
fn sm4_cbc_rejects_gcm_ciphertext() {
    let gcm_enc = encrypt_with(
        Algorithm::PBEWithHMACSM3AndSM4_GCM,
        TEST_PASSWORD,
        TEST_PLAINTEXT,
    );
    let result = decrypt_with(Algorithm::PBEWithHMACSM3AndSM4_CBC, TEST_PASSWORD, &gcm_enc);
    assert!(result.is_err());
}

// ── RFC 8998 Appendix A.1 SM4-GCM test vector ────────────────

fn decode_hex<const N: usize>(s: &str) -> [u8; N] {
    let clean: String = s.chars().filter(|c| !c.is_whitespace()).collect();
    let mut r = [0u8; N];
    for i in 0..N {
        r[i] = u8::from_str_radix(&clean[i * 2..i * 2 + 2], 16).unwrap();
    }
    r
}

fn decode_hex_vec(s: &str) -> Vec<u8> {
    let clean: String = s.chars().filter(|c| !c.is_whitespace()).collect();
    (0..clean.len() / 2)
        .map(|i| u8::from_str_radix(&clean[i * 2..i * 2 + 2], 16).unwrap())
        .collect()
}

#[test]
fn sm4_gcm_rfc8998_test_vector() {
    let key: [u8; 16] = decode_hex("0123456789ABCDEFFEDCBA9876543210");
    let nonce: [u8; 12] = decode_hex("00001234567800000000ABCD");
    let plaintext = decode_hex_vec(
        "\
        AAAAAAAA AAAAAAAA BBBBBBBB BBBBBBBB \
        CCCCCCCC CCCCCCCC DDDDDDDD DDDDDDDD \
        EEEEEEEE EEEEEEEE FFFFFFFF FFFFFFFF \
        EEEEEEEE EEEEEEEE AAAAAAAA AAAAAAAA",
    );
    let aad = decode_hex_vec("FEEDFACEDEADBEEFFEEDFACEDEADBEEFABADDAD2");
    let expected_ct = decode_hex_vec(
        "\
        17F399F0 8C67D5EE 19D0DC99 69C4BB7D \
        5FD46FD3 75648906 9157B282 BB200735 \
        D82710CA 5C22F0CC FA7CBF93 D496AC15 \
        A56834CB CF98C397 B4024A26 91233B8D",
    );
    let expected_tag: [u8; 16] = decode_hex("83DE3541E4C2B58177E065A9BF7B62EC");

    let (ciphertext, tag) = sm4_gcm_encrypt(&key, &nonce, &aad, &plaintext);

    assert_eq!(
        ciphertext,
        expected_ct,
        "Ciphertext mismatch.\nGot:      {}\nExpected: {}",
        ciphertext
            .iter()
            .map(|b| format!("{:02X}", b))
            .collect::<Vec<_>>()
            .join(""),
        expected_ct
            .iter()
            .map(|b| format!("{:02X}", b))
            .collect::<Vec<_>>()
            .join(""),
    );
    assert_eq!(tag, expected_tag, "Tag mismatch");

    // Decrypt round-trip
    let decrypted = sm4_gcm_decrypt(&key, &nonce, &aad, &ciphertext, &tag).unwrap();
    assert_eq!(decrypted, plaintext);
}

// ── Memory helpers ───────────────────────────────────────────

#[test]
fn clear_string_works() {
    let mut s = String::from("secret");
    clear_string(&mut s);
    assert_eq!(s, "");
}

#[test]
fn clear_option_string_works() {
    let mut o = Some(String::from("secret"));
    clear_option_string(&mut o);
    assert_eq!(o, None);
}

// ── Unicode password ─────────────────────────────────────────

#[test]
fn unicode_password_round_trip_all_algorithms() {
    let password = "パスワード🔒";
    let plaintext = "unicode test";

    for alg in Algorithm::iter() {
        let enc = encrypt_with(alg, password, plaintext);
        let dec = decrypt_with(alg, password, &enc).unwrap();
        assert_eq!(dec, plaintext, "Failed for {alg}");
    }
}

// ── Custom iterations ────────────────────────────────────────

#[test]
fn custom_iterations_round_trip() {
    for alg in Algorithm::iter() {
        let enc = encrypt_with_iterations(alg, TEST_PASSWORD, TEST_PLAINTEXT, 10_000);
        let dec = decrypt_with_iterations(alg, TEST_PASSWORD, &enc, 10_000).unwrap();
        assert_eq!(dec, TEST_PLAINTEXT, "Failed for {alg}");
    }
}

#[test]
fn iteration_mismatch_fails() {
    let enc = encrypt_with_iterations(
        Algorithm::PBEWithHMACSM3AndSM4_GCM,
        TEST_PASSWORD,
        TEST_PLAINTEXT,
        10_000,
    );
    let result = decrypt_with_iterations(
        Algorithm::PBEWithHMACSM3AndSM4_GCM,
        TEST_PASSWORD,
        &enc,
        20_000,
    );
    assert!(result.is_err());
}

// ── Is it ENC? ───────────────────────────────────────────────

#[test]
fn is_enc_detection() {
    assert!(is_enc_value("ENC(...)"));
    assert!(is_enc_value("  ENC(foo)  "));
    assert!(!is_enc_value("not_wrapped"));
    assert!(!is_enc_value("ENC("));
    assert!(!is_enc_value(")"));
}

// ── Error display ────────────────────────────────────────────

#[test]
fn error_display_messages() {
    let e = Error::CiphertextTooShort;
    assert_eq!(e.to_string(), "Ciphertext too short");
    let e = Error::DecryptionFailed;
    assert_eq!(e.to_string(), "Decryption failed");
}
