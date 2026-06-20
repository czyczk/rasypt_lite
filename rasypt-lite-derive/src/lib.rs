//! Derive macro `RasyptDecrypt` for structs.
//!
//! Generates a `fn decrypt_enc_fields(&mut self, password: &str)` method that
//! decrypts only fields tagged with `#[rasypt(encrypted)]`.
//!
//! Use `#[rasypt(encrypted, algorithm = "PBEWithHMACSM3AndSM4_GCM")]` to
//! specify a non-default algorithm. The value must be a valid
//! [`Algorithm`](rasypt_lite_lib::Algorithm) variant name.
//!
//! # Features
//!
//! - **`zeroize`** (enabled by default) – generates a `Drop` impl that calls
//!   `clear_sensitive_fields()` so tagged fields are zeroised on drop.

use proc_macro::TokenStream;
use proc_macro2::Span;
use quote::quote;
use syn::{parse_macro_input, spanned::Spanned, Data, DeriveInput, Fields, Ident, LitStr, Type};

#[derive(Clone)]
struct FieldMeta {
    encrypted: bool,
    algorithm: Option<String>,
}

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

    let mut metas: Vec<FieldMeta> = Vec::with_capacity(fields.len());
    let mut invalid_tag_errors = Vec::new();

    for f in fields.iter() {
        match parse_rasypt_attr(f) {
            Ok(meta) => {
                if meta.encrypted && !is_string_type(&f.ty) && !is_option_string_type(&f.ty) {
                    invalid_tag_errors.push(syn::Error::new(
                        f.ty.span(),
                        "#[rasypt(encrypted)] can only be used on String or Option<String> fields",
                    ));
                }
                metas.push(meta);
            }
            Err(err) => {
                invalid_tag_errors.push(err);
                metas.push(FieldMeta { encrypted: false, algorithm: None });
            }
        }
    }

    if !invalid_tag_errors.is_empty() {
        let compile_errors = invalid_tag_errors.iter().map(syn::Error::to_compile_error);
        return TokenStream::from(quote! {
            #(#compile_errors)*
        });
    }

    let field_decryptors = fields.iter().zip(metas.iter()).filter_map(|(f, meta)| {
        if !meta.encrypted {
            return None;
        }
        let field_name = f.ident.as_ref()?;
        let ty = &f.ty;

        let decrypt_call = match &meta.algorithm {
            Some(alg_name) => {
                let alg_ident = Ident::new(alg_name, Span::call_site());
                if is_string_type(ty) {
                    quote! {
                        if ::rasypt_lite_lib::is_enc_value(&self.#field_name) {
                            self.#field_name = ::rasypt_lite_lib::decrypt_enc_with(
                                ::rasypt_lite_lib::Algorithm::#alg_ident,
                                &self.#field_name,
                                password,
                            )?;
                        }
                    }
                } else {
                    quote! {
                        if let Some(ref val) = self.#field_name {
                            if ::rasypt_lite_lib::is_enc_value(val) {
                                self.#field_name = Some(::rasypt_lite_lib::decrypt_enc_with(
                                    ::rasypt_lite_lib::Algorithm::#alg_ident,
                                    val,
                                    password,
                                )?);
                            }
                        }
                    }
                }
            }
            None => {
                if is_string_type(ty) {
                    quote! {
                        if ::rasypt_lite_lib::is_enc_value(&self.#field_name) {
                            self.#field_name = ::rasypt_lite_lib::decrypt_enc(&self.#field_name, password)?;
                        }
                    }
                } else {
                    quote! {
                        if let Some(ref val) = self.#field_name {
                            if ::rasypt_lite_lib::is_enc_value(val) {
                                self.#field_name = Some(::rasypt_lite_lib::decrypt_enc(val, password)?);
                            }
                        }
                    }
                }
            }
        };
        Some(decrypt_call)
    });

    let field_clearers = fields.iter().zip(metas.iter()).filter_map(|(f, meta)| {
        if !meta.encrypted {
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

fn parse_rasypt_attr(field: &syn::Field) -> Result<FieldMeta, syn::Error> {
    let mut encrypted = false;
    let mut algorithm: Option<String> = None;

    for attr in field
        .attrs
        .iter()
        .filter(|attr| attr.path().is_ident("rasypt"))
    {
        attr.parse_nested_meta(|meta| {
            if meta.path.is_ident("encrypted") {
                encrypted = true;
                Ok(())
            } else if meta.path.is_ident("algorithm") {
                let val: LitStr = meta.value()?.parse()?;
                algorithm = Some(val.value());
                Ok(())
            } else {
                Err(meta.error("unsupported rasypt option; expected `encrypted` or `algorithm`"))
            }
        })?;
    }

    if !encrypted {
        // Only flag as error if there's a #[rasypt] attribute without `encrypted`
        for attr in field.attrs.iter().filter(|a| a.path().is_ident("rasypt")) {
            if !attr.meta.require_list().is_ok() {
                continue;
            }
            // If we got here with encrypted=false, the attr had something but not `encrypted`
            // But parse_nested_meta already returned errors for unknown options.
        }
    }

    Ok(FieldMeta { encrypted, algorithm })
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
