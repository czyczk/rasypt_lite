#[cfg(test)]
mod tests {
    use rasypt_lite_derive::RasyptDecrypt;

    #[derive(RasyptDecrypt)]
    struct DemoConfig {
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
    fn test_decrypt_error_propagation() {
        #[derive(RasyptDecrypt)]
        struct BadConfig {
            pub secret: String,
        }

        let mut cfg = BadConfig {
            // not an ENC(...) value; should return NotEncValue error
            secret: "not wrapped".into(),
        };

        let err = cfg.decrypt_enc_fields("pwd").unwrap_err();
        assert!(matches!(err, ::rasypt_lite_lib::Error::NotEncValue));
    }

    #[cfg(feature = "zeroize")]
    #[test]
    fn test_derive_generates_drop() {
        #[derive(RasyptDecrypt)]
        struct Foo {
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
            pub api_key: Option<String>,
            pub token: String,
        }

        let mut cfg = ClearDemo {
            api_key: Some("secret".into()),
            token: "value".into(),
        };

        cfg.clear_sensitive_fields();
        assert_eq!(cfg.api_key, None);
        assert_eq!(cfg.token, "");
    }
}
