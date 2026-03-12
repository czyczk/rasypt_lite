//! Derive macro `RasyptDecrypt` for structs.
//!
//! Generates a `fn decrypt_enc_fields(&mut self, password: &str)` method that
//! walks every `String` and `Option<String>` field and, if the value matches
//! `ENC(...)`, replaces it with the decrypted plaintext.
//!
//! # Features
//!
//! - **`zeroize`** (enabled by default) – when this feature is active the
//!   macro also implements `Drop` for the struct, calling
//!   `clear_sensitive_fields()` so that any `String`/`Option<String>` fields are
//!   zeroised when the value goes out of scope. A consumer wishing to opt out
//!   may disable the feature in its `Cargo.toml`.
//!
//! # `no_std` compatibility
//!
//! At present the generated code uses `std` (the `Drop` impl and the library
//! itself depend on heap‑allocated strings).  If you intend to use this crate in
//! a `no_std` / embedded environment you will either need to fork/patch it or
//! add a new feature to remove those dependencies.  The `zeroize` feature is
//! harmless in `no_std` as long as the consumer doesn't rely on `Drop` behaviour.
use proc_macro::TokenStream;
use quote::quote;
use syn::{parse_macro_input, Data, DeriveInput, Fields, Type};

#[proc_macro_derive(RasyptDecrypt)]
pub fn rasypt_decrypt_derive(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    let name = &input.ident;
    let (impl_generics, ty_generics, where_clause) = input.generics.split_for_impl();

    let fields = match &input.data {
        Data::Struct(data) => match &data.fields {
            Fields::Named(fields) => &fields.named,
            _ => panic!("RasyptDecrypt only supports named fields"),
        },
        _ => panic!("RasyptDecrypt can only be derived for structs"),
    };

    let field_decryptors = fields.iter().filter_map(|f| {
        let field_name = f.ident.as_ref()?;
        let ty = &f.ty;

        if is_string_type(ty) {
            Some(quote! {
                // Attempt to decrypt every string field;
                // Any error (including `NotEncValue`) will be returned to the caller
                self.#field_name = ::rasypt_lite_lib::decrypt_enc(&self.#field_name, password)?;
            })
        } else if is_option_string_type(ty) {
            Some(quote! {
                if let Some(ref val) = self.#field_name {
                    // Attempt decryption for Option<String>; propagate any error
                    self.#field_name = Some(::rasypt_lite_lib::decrypt_enc(val, password)?);
                }
            })
        } else {
            None
        }
    });

    let field_clearers = fields.iter().filter_map(|f| {
        let field_name = f.ident.as_ref()?;
        let ty = &f.ty;

        if is_string_type(ty) {
            Some(quote! {
                ::rasypt_lite_lib::clear_string(&mut self.#field_name);
            })
        } else if is_option_string_type(ty) {
            Some(quote! {
                ::rasypt_lite_lib::clear_option_string(&mut self.#field_name);
            })
        } else {
            None
        }
    });

    let expanded = quote! {
        impl #impl_generics #name #ty_generics #where_clause {
            /// Decrypt all `ENC(...)` wrapped `String` / `Option<String>` fields in-place.
            ///
            /// Returns `Ok(())` on success. If any field fails to decrypt (which should
            /// only happen if the wrapped ciphertext is invalid or the password is
            /// incorrect) the method will return the first error encountered and leave
            /// subsequent fields untouched.
            pub fn decrypt_enc_fields(&mut self, password: &str) -> Result<(), ::rasypt_lite_lib::Error> {
                #(#field_decryptors)*
                Ok(())
            }

            /// Zeroize and clear all `String` / `Option<String>` fields that may contain secrets.
            pub fn clear_sensitive_fields(&mut self) {
                #(#field_clearers)*
            }
        }

        // if the consumer crate enables the "zeroize" feature, automatically clear
        // sensitive fields when the struct is dropped. the feature is enabled by
        // default so callers who don't opt out get the safer behaviour. a panic in
        // `clear_sensitive_fields` is considered unlikely and not worth the
        // complexity of catching unwinds; in `panic = "abort"` profiles the
        // call will simply execute and then the process will abort on panic.
        #[cfg(feature = "zeroize")]
        impl #impl_generics Drop for #name #ty_generics #where_clause {
            fn drop(&mut self) {
                // we deliberately don't propagate errors or attempt to recover; this
                // is a best-effort sanitisation performed during destruction.
                let _ = self.clear_sensitive_fields();
            }
        }
    };

    TokenStream::from(expanded)
}

fn is_string_type(ty: &Type) -> bool {
    if let Type::Path(type_path) = ty {
        type_path
            .path
            .segments
            .last()
            .map_or(false, |seg| seg.ident == "String")
    } else {
        false
    }
}

fn is_option_string_type(ty: &Type) -> bool {
    if let Type::Path(type_path) = ty {
        if let Some(seg) = type_path.path.segments.last() {
            if seg.ident == "Option" {
                if let syn::PathArguments::AngleBracketed(args) = &seg.arguments {
                    if let Some(syn::GenericArgument::Type(inner)) = args.args.first() {
                        return is_string_type(inner);
                    }
                }
            }
        }
    }
    false
}
