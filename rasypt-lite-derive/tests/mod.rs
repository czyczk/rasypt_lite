#[cfg(test)]
mod tests {
    use rasypt_lite_derive::RasyptDecrypt;

    #[derive(RasyptDecrypt)]
    struct DemoConfig {
        #[rasypt(encrypted)]
        pub api_key: Option<String>, // Some("ENC(base64...)")
    }

    #[test]
    fn test_macro() {
        let mut config = DemoConfig {
            api_key: Some(
                "ENC(7yGfmac+qQ3zViRwxQqWGuKXfiiI1ibWAj3L6xMP+OkaUa8rwTUJNseT4qBjbpIz)".into(),
            ),
        };

        config.decrypt_enc_fields("pwd").expect("decryption failed");
        assert_eq!(config.api_key, Some("abc".into()));
    }

    #[test]
    fn test_non_tagged_fields_are_ignored() {
        #[derive(RasyptDecrypt)]
        struct BadConfig {
            pub secret: String,
        }

        let mut cfg = BadConfig {
            // this field is intentionally not tagged.
            secret: "not wrapped".into(),
        };

        cfg.decrypt_enc_fields("pwd").expect("decrypt should no-op");
        assert_eq!(cfg.secret, "not wrapped");
    }

    #[cfg(feature = "zeroize")]
    #[test]
    fn test_derive_generates_drop() {
        #[derive(RasyptDecrypt)]
        struct Foo {
            #[rasypt(encrypted)]
            secret: String,
        }

        // ensure Foo has a nontrivial destructor – the generated Drop impl
        // should make `needs_drop` return true.
        assert!(std::mem::needs_drop::<Foo>());
    }

    #[test]
    fn test_clear_sensitive_fields() {
        #[derive(RasyptDecrypt)]
        struct ClearDemo {
            #[rasypt(encrypted)]
            pub api_key: Option<String>,
            #[rasypt(encrypted)]
            pub token: String,
            pub untouched: String,
        }

        let mut cfg = ClearDemo {
            api_key: Some("secret".into()),
            token: "value".into(),
            untouched: "keep".into(),
        };

        cfg.clear_sensitive_fields();
        assert_eq!(cfg.api_key, None);
        assert_eq!(cfg.token, "");
        assert_eq!(cfg.untouched, "keep");
    }

    #[test]
    fn test_algorithm_param() {
        use rasypt_lite_lib::{encrypt_with, Algorithm};

        #[derive(RasyptDecrypt)]
        struct SmConfig {
            #[rasypt(encrypted, algorithm = "PBEWithHMACSM3AndSM4_GCM")]
            pub secret: String,
        }

        let ct = encrypt_with(
            Algorithm::PBEWithHMACSM3AndSM4_GCM,
            "password",
            "hello sm4-gcm",
        );
        let mut cfg = SmConfig {
            secret: format!("ENC({})", ct),
        };

        cfg.decrypt_enc_fields("password").expect("decrypt failed");
        assert_eq!(cfg.secret, "hello sm4-gcm");
    }

    #[test]
    fn test_mixed_algorithms() {
        use rasypt_lite_lib::{encrypt_with, Algorithm};

        #[derive(RasyptDecrypt)]
        struct MixedConfig {
            #[rasypt(encrypted)]
            pub aes_field: String,
            #[rasypt(encrypted, algorithm = "PBEWithHMACSM3AndSM4_GCM")]
            pub sm_field: String,
        }

        let aes_ct = encrypt_with(Algorithm::PBEWithHMACSHA512AndAES_256, "pass", "aes-value");
        let sm_ct = encrypt_with(Algorithm::PBEWithHMACSM3AndSM4_GCM, "pass", "sm-value");

        let mut cfg = MixedConfig {
            aes_field: format!("ENC({})", aes_ct),
            sm_field: format!("ENC({})", sm_ct),
        };

        cfg.decrypt_enc_fields("pass").expect("decrypt failed");
        assert_eq!(cfg.aes_field, "aes-value");
        assert_eq!(cfg.sm_field, "sm-value");
    }
}
