//! Derive macro `RasyptDecrypt` for structs.
//!
//! Generates a `fn decrypt_enc_fields(&mut self, password: &str)` method that
//! decrypts only fields tagged with `#[rasypt(encrypted)]`.
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
use syn::{parse_macro_input, spanned::Spanned, Data, DeriveInput, Fields, Type};

#[proc_macro_derive(RasyptDecrypt, attributes(rasypt))]
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

    let mut encrypted_flags = Vec::with_capacity(fields.len());
    let mut invalid_tag_errors = Vec::new();
    for f in fields.iter() {
        match has_rasypt_encrypted_tag(f) {
            Ok(is_encrypted) => {
                encrypted_flags.push(is_encrypted);
                if is_encrypted && !is_string_type(&f.ty) && !is_option_string_type(&f.ty) {
                    invalid_tag_errors.push(syn::Error::new(
                        f.ty.span(),
                        "#[rasypt(encrypted)] can only be used on String or Option<String> fields",
                    ));
                }
            }
            Err(err) => {
                encrypted_flags.push(false);
                invalid_tag_errors.push(err);
            }
        }
    }

    if !invalid_tag_errors.is_empty() {
        let compile_errors = invalid_tag_errors.iter().map(syn::Error::to_compile_error);
        return TokenStream::from(quote! {
            #(#compile_errors)*
        });
    }

    let field_decryptors = fields
        .iter()
        .zip(encrypted_flags.iter())
        .filter_map(|(f, is_encrypted)| {
        if !*is_encrypted {
            return None;
        }

        let field_name = f.ident.as_ref()?;
        let ty = &f.ty;

        if is_string_type(ty) {
            Some(quote! {
                // Only decrypt values explicitly marked as ENC(...).
                if ::rasypt_lite_lib::is_enc_value(&self.#field_name) {
                    self.#field_name = ::rasypt_lite_lib::decrypt_enc(&self.#field_name, password)?;
                }
            })
        } else if is_option_string_type(ty) {
            Some(quote! {
                if let Some(ref val) = self.#field_name {
                    // Only decrypt Option<String> values explicitly marked as ENC(...).
                    if ::rasypt_lite_lib::is_enc_value(val) {
                        self.#field_name = Some(::rasypt_lite_lib::decrypt_enc(val, password)?);
                    }
                }
            })
        } else {
            None
        }
    });

    let field_clearers =
        fields
            .iter()
            .zip(encrypted_flags.iter())
            .filter_map(|(f, is_encrypted)| {
                if !*is_encrypted {
                    return None;
                }

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

    let drop_impl = if cfg!(feature = "zeroize") {
        quote! {
            impl #impl_generics Drop for #name #ty_generics #where_clause {
                fn drop(&mut self) {
                    // we deliberately don't propagate errors or attempt to recover; this
                    // is a best-effort sanitisation performed during destruction.
                    self.clear_sensitive_fields();
                }
            }
        }
    } else {
        quote! {}
    };

    let expanded = quote! {
        impl #impl_generics #name #ty_generics #where_clause {
            /// Decrypt all `#[rasypt(encrypted)]` fields wrapped with `ENC(...)` in-place.
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

        #drop_impl
    };

    TokenStream::from(expanded)
}

fn has_rasypt_encrypted_tag(field: &syn::Field) -> Result<bool, syn::Error> {
    let mut has_encrypted_tag = false;

    for attr in field
        .attrs
        .iter()
        .filter(|attr| attr.path().is_ident("rasypt"))
    {
        let mut has_encrypted_option = false;
        attr.parse_nested_meta(|meta| {
            if meta.path.is_ident("encrypted") {
                has_encrypted_option = true;
                Ok(())
            } else {
                Err(meta.error("unsupported rasypt option; expected `encrypted`"))
            }
        })?;

        if !has_encrypted_option {
            return Err(syn::Error::new(
                attr.span(),
                "#[rasypt(...)] requires `encrypted`, e.g. #[rasypt(encrypted)]",
            ));
        }

        has_encrypted_tag = true;
    }

    Ok(has_encrypted_tag)
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
