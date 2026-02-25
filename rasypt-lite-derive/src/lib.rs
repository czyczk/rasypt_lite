//! Derive macro `RasyptDecrypt` for structs.
//!
//! Generates a `fn decrypt_enc_fields(&mut self, password: &str)` method that
//! walks every `String` and `Option<String>` field and, if the value matches
//! `ENC(...)`, replaces it with the decrypted plaintext.
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
                if ::rasypt_lite_lib::is_enc_value(&self.#field_name) {
                    if let Ok(decrypted) = ::rasypt_lite_lib::decrypt_enc(&self.#field_name, password) {
                        self.#field_name = decrypted;
                    }
                }
            })
        } else if is_option_string_type(ty) {
            Some(quote! {
                if let Some(ref val) = self.#field_name {
                    if ::rasypt_lite_lib::is_enc_value(val) {
                        if let Ok(decrypted) = ::rasypt_lite_lib::decrypt_enc(val, password) {
                            self.#field_name = Some(decrypted);
                        }
                    }
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
            pub fn decrypt_enc_fields(&mut self, password: &str) {
                #(#field_decryptors)*
            }

            /// Zeroize and clear all `String` / `Option<String>` fields that may contain secrets.
            pub fn clear_sensitive_fields(&mut self) {
                #(#field_clearers)*
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
