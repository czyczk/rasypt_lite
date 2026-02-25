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

        config.decrypt_enc_fields("pwd");
        assert_eq!(config.api_key, Some("abc".into()));
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
