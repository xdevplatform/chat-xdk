//! Proc macros for chat-xdk.
//!
//! Provides `#[derive(JsCamelCase)]` to generate camelCase wrapper types
//! for JavaScript/WASM while keeping core types as snake_case for Python.
//!
//! # Usage
//!
//! ```ignore
//! #[derive(JsCamelCase)]
//! pub struct Message {
//!     pub sequence_id: Option<String>,  // becomes "sequenceId" in JSON
//!     #[js_camel(wrap)]
//!     pub meta: EventMeta,              // type becomes JsEventMeta
//! }
//! ```
//!
//! This generates:
//! - `JsMessage` Rust struct with `#[serde(rename_all = "camelCase")]`
//! - `From<Message> for JsMessage` and vice versa

use proc_macro::TokenStream;
use quote::{format_ident, quote};
use syn::{parse_macro_input, Data, DeriveInput, Fields, Ident};

/// Derive macro that generates a camelCase wrapper type for JavaScript.
///
/// For a type `Foo`, generates:
/// - `JsFoo` with `#[serde(rename_all = "camelCase")]`
/// - `impl From<Foo> for JsFoo`
/// - `impl From<JsFoo> for Foo`
///
/// # Attributes
///
/// - `#[js_camel(wrap)]` on a field: The field's type also has a `Js*` wrapper.
///   The generated code will use the wrapped type and call `.into()` for conversion.
///
/// # Example
///
/// ```ignore
/// #[derive(JsCamelCase)]
/// pub struct Message {
///     #[js_camel(wrap)]
///     pub meta: EventMeta,  // Uses JsEventMeta in the Js wrapper
///     pub text: String,     // Copied directly
/// }
/// ```
#[proc_macro_derive(JsCamelCase, attributes(js_camel))]
pub fn derive_js_camel_case(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    let name = &input.ident;
    let js_name = format_ident!("Js{}", name);
    let vis = &input.vis;

    match &input.data {
        Data::Struct(data) => generate_struct(&input, name, &js_name, vis, data),
        Data::Enum(data) => generate_enum(&input, name, &js_name, vis, data),
        Data::Union(_) => syn::Error::new_spanned(&input, "JsCamelCase does not support unions")
            .to_compile_error()
            .into(),
    }
}

/// Information about a processed field
struct ProcessedField<'a> {
    name: Option<&'a Ident>,
    js_type: proc_macro2::TokenStream,
    serde_attrs: Vec<proc_macro2::TokenStream>,
    wrap: bool,
    /// The wrapper type chain (e.g., [Option, Vec] for Option<Vec<T>>)
    wrapper_chain: Vec<WrapperKind>,
}

/// Kind of wrapper type for conversion generation
#[derive(Clone, Copy, Debug)]
enum WrapperKind {
    Box,
    Vec,
    Option,
}

fn generate_struct(
    input: &DeriveInput,
    name: &Ident,
    js_name: &Ident,
    vis: &syn::Visibility,
    data: &syn::DataStruct,
) -> TokenStream {
    let fields = match &data.fields {
        Fields::Named(fields) => &fields.named,
        Fields::Unnamed(_) => {
            return syn::Error::new_spanned(input, "JsCamelCase does not support tuple structs")
                .to_compile_error()
                .into();
        }
        Fields::Unit => {
            return syn::Error::new_spanned(input, "JsCamelCase does not support unit structs")
                .to_compile_error()
                .into();
        }
    };

    // Process all fields
    let processed: Vec<ProcessedField> = fields.iter().map(process_field).collect();

    // Generate field definitions for the Js* struct
    let field_defs: Vec<_> = processed
        .iter()
        .map(|f| {
            let field_name = &f.name;
            let js_type = &f.js_type;
            let serde_attrs = &f.serde_attrs;
            quote! {
                #(#serde_attrs)*
                pub #field_name: #js_type
            }
        })
        .collect();

    // Generate conversions
    let to_js_conversions: Vec<_> = processed
        .iter()
        .map(|f| {
            let field_name = &f.name;
            generate_field_to_js(field_name, f.wrap, &f.wrapper_chain)
        })
        .collect();

    let from_js_conversions: Vec<_> = processed
        .iter()
        .map(|f| {
            let field_name = &f.name;
            generate_field_from_js(field_name, f.wrap, &f.wrapper_chain)
        })
        .collect();

    let expanded = quote! {
        #[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
        #[serde(rename_all = "camelCase")]
        #vis struct #js_name {
            #(#field_defs,)*
        }

        impl From<#name> for #js_name {
            fn from(value: #name) -> Self {
                Self {
                    #(#to_js_conversions,)*
                }
            }
        }

        impl From<#js_name> for #name {
            fn from(value: #js_name) -> Self {
                Self {
                    #(#from_js_conversions,)*
                }
            }
        }
    };

    expanded.into()
}

fn generate_enum(
    input: &DeriveInput,
    name: &Ident,
    js_name: &Ident,
    vis: &syn::Visibility,
    data: &syn::DataEnum,
) -> TokenStream {
    // Transform serde attributes: convert tag values to camelCase, skip rename_all
    let transformed_serde_attrs = transform_enum_serde_attrs(&input.attrs);

    let variants: Vec<_> = data
        .variants
        .iter()
        .map(|v| {
            let variant_name = &v.ident;
            let variant_attrs: Vec<_> = v
                .attrs
                .iter()
                .filter(|a| a.path().is_ident("serde"))
                .collect();

            // Check if the variant itself has js_camel(wrap) attribute
            let variant_wrap = has_wrap_attr(&v.attrs);

            match &v.fields {
                Fields::Named(fields) => {
                    // For named fields, each field can have its own wrap attribute
                    let processed: Vec<ProcessedField> =
                        fields.named.iter().map(process_field).collect();

                    let field_defs: Vec<_> = processed
                        .iter()
                        .map(|f| {
                            let field_name = &f.name;
                            let js_type = &f.js_type;
                            let serde_attrs = &f.serde_attrs;
                            quote! {
                                #(#serde_attrs)*
                                #field_name: #js_type
                            }
                        })
                        .collect();

                    let field_names: Vec<_> = processed.iter().map(|f| &f.name).collect();

                    let to_js: Vec<_> = processed
                        .iter()
                        .map(|f| {
                            let n = &f.name;
                            generate_variant_field_to_js(n, f.wrap, &f.wrapper_chain)
                        })
                        .collect();

                    let from_js: Vec<_> = processed
                        .iter()
                        .map(|f| {
                            let n = &f.name;
                            generate_variant_field_from_js(n, f.wrap, &f.wrapper_chain)
                        })
                        .collect();

                    (
                        quote! {
                            #(#variant_attrs)*
                            #variant_name {
                                #(#field_defs,)*
                            }
                        },
                        quote! {
                            #name::#variant_name { #(#field_names,)* } => {
                                #js_name::#variant_name { #(#to_js,)* }
                            }
                        },
                        quote! {
                            #js_name::#variant_name { #(#field_names,)* } => {
                                #name::#variant_name { #(#from_js,)* }
                            }
                        },
                    )
                }
                Fields::Unnamed(fields) => {
                    // For unnamed fields, use the variant-level wrap attribute
                    let processed: Vec<ProcessedField> = fields
                        .unnamed
                        .iter()
                        .map(|f| {
                            process_field_with_wrap(f, variant_wrap || has_wrap_attr(&f.attrs))
                        })
                        .collect();
                    let js_types: Vec<_> = processed.iter().map(|f| &f.js_type).collect();
                    let field_indices: Vec<_> = (0..fields.unnamed.len())
                        .map(|i| format_ident!("f{}", i))
                        .collect();

                    let to_js: Vec<_> = processed
                        .iter()
                        .zip(field_indices.iter())
                        .map(|(f, idx)| generate_unnamed_field_to_js(idx, f.wrap, &f.wrapper_chain))
                        .collect();

                    let from_js: Vec<_> = processed
                        .iter()
                        .zip(field_indices.iter())
                        .map(|(f, idx)| {
                            generate_unnamed_field_from_js(idx, f.wrap, &f.wrapper_chain)
                        })
                        .collect();

                    (
                        quote! {
                            #(#variant_attrs)*
                            #variant_name(#(#js_types,)*)
                        },
                        quote! {
                            #name::#variant_name(#(#field_indices,)*) => {
                                #js_name::#variant_name(#(#to_js,)*)
                            }
                        },
                        quote! {
                            #js_name::#variant_name(#(#field_indices,)*) => {
                                #name::#variant_name(#(#from_js,)*)
                            }
                        },
                    )
                }
                Fields::Unit => (
                    quote! {
                        #(#variant_attrs)*
                        #variant_name
                    },
                    quote! {
                        #name::#variant_name => #js_name::#variant_name
                    },
                    quote! {
                        #js_name::#variant_name => #name::#variant_name
                    },
                ),
            }
        })
        .collect();

    let variant_defs: Vec<_> = variants.iter().map(|(def, _, _)| def).collect();
    let to_js_arms: Vec<_> = variants.iter().map(|(_, to_js, _)| to_js).collect();
    let from_js_arms: Vec<_> = variants.iter().map(|(_, _, from_js)| from_js).collect();

    let expanded = quote! {
        #[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
        #(#transformed_serde_attrs)*
        #[serde(rename_all = "camelCase")]
        #vis enum #js_name {
            #(#variant_defs,)*
        }

        impl From<#name> for #js_name {
            fn from(value: #name) -> Self {
                match value {
                    #(#to_js_arms,)*
                }
            }
        }

        impl From<#js_name> for #name {
            fn from(value: #js_name) -> Self {
                match value {
                    #(#from_js_arms,)*
                }
            }
        }
    };

    expanded.into()
}

/// Process a field to extract its JS type and conversion info
fn process_field(field: &syn::Field) -> ProcessedField<'_> {
    process_field_with_wrap(field, has_wrap_attr(&field.attrs))
}

/// Process a field with explicit wrap setting (for variant-level attributes)
fn process_field_with_wrap(field: &syn::Field, wrap: bool) -> ProcessedField<'_> {
    let serde_attrs = transform_field_serde_attrs(&field.attrs);

    let (js_type, wrapper_chain) = if wrap {
        transform_type_to_js(&field.ty)
    } else {
        let ty = &field.ty;
        (quote! { #ty }, Vec::new())
    };

    ProcessedField {
        name: field.ident.as_ref(),
        js_type,
        serde_attrs,
        wrap,
        wrapper_chain,
    }
}

/// Check if a field has #[js_camel(wrap)] attribute
fn has_wrap_attr(attrs: &[syn::Attribute]) -> bool {
    attrs.iter().any(|attr| {
        if !attr.path().is_ident("js_camel") {
            return false;
        }
        // Parse the attribute to check for "wrap"
        if let syn::Meta::List(meta_list) = &attr.meta {
            let tokens = meta_list.tokens.to_string();
            return tokens.contains("wrap");
        }
        false
    })
}

/// Transform a type to its Js* equivalent, returning the JS type and wrapper chain
/// e.g., `EventMeta` -> `JsEventMeta`, `Option<Vec<Message>>` -> `Option<Vec<JsMessage>>`
fn transform_type_to_js(ty: &syn::Type) -> (proc_macro2::TokenStream, Vec<WrapperKind>) {
    transform_type_to_js_recursive(ty, Vec::new())
}

fn transform_type_to_js_recursive(
    ty: &syn::Type,
    mut chain: Vec<WrapperKind>,
) -> (proc_macro2::TokenStream, Vec<WrapperKind>) {
    match ty {
        syn::Type::Path(type_path) => {
            let segments = &type_path.path.segments;
            if segments.len() == 1 {
                let seg = &segments[0];
                let ident = &seg.ident;

                // Handle generic types like Box<T>, Vec<T>, Option<T>
                if let syn::PathArguments::AngleBracketed(args) = &seg.arguments {
                    let wrapper = ident.to_string();
                    let wrapper_kind = match wrapper.as_str() {
                        "Box" => Some(WrapperKind::Box),
                        "Vec" => Some(WrapperKind::Vec),
                        "Option" => Some(WrapperKind::Option),
                        _ => None,
                    };

                    if let Some(kind) = wrapper_kind {
                        // Add this wrapper to the chain and recurse
                        chain.push(kind);
                        if let Some(syn::GenericArgument::Type(inner_ty)) = args.args.first() {
                            let (inner_js, chain) = transform_type_to_js_recursive(inner_ty, chain);
                            return (quote! { #ident<#inner_js> }, chain);
                        }
                    }
                }

                // Simple type - prefix with Js
                let js_ident = format_ident!("Js{}", ident);
                (quote! { #js_ident }, chain)
            } else {
                // Multi-segment path, just use as-is
                (quote! { #ty }, chain)
            }
        }
        _ => (quote! { #ty }, chain),
    }
}

/// Build conversion expression for a wrapper chain (inside-out)
/// For Option<Vec<T>>: builds `x.map(|x| x.into_iter().map(|x| x.into()).collect())`
fn build_conversion_expr(chain: &[WrapperKind]) -> proc_macro2::TokenStream {
    // Start with the innermost conversion
    let mut expr = quote! { x.into() };

    // Build from inside out (reverse the chain)
    for wrapper in chain.iter().rev() {
        expr = match wrapper {
            WrapperKind::Box => quote! { Box::new((*x).into()) },
            WrapperKind::Vec => quote! { x.into_iter().map(|x| #expr).collect() },
            WrapperKind::Option => quote! { x.map(|x| #expr) },
        };
    }

    expr
}

/// Generate the conversion code for a field from original to Js type
fn generate_field_to_js(
    field_name: &Option<&Ident>,
    wrap: bool,
    wrapper_chain: &[WrapperKind],
) -> proc_macro2::TokenStream {
    if !wrap {
        return quote! { #field_name: value.#field_name };
    }

    if wrapper_chain.is_empty() {
        return quote! { #field_name: value.#field_name.into() };
    }

    // Build the conversion expression and substitute the field access
    let conversion = build_conversion_expr(wrapper_chain);
    quote! { #field_name: { let x = value.#field_name; #conversion } }
}

/// Generate the conversion code for a field from Js type to original
fn generate_field_from_js(
    field_name: &Option<&Ident>,
    wrap: bool,
    wrapper_chain: &[WrapperKind],
) -> proc_macro2::TokenStream {
    if !wrap {
        return quote! { #field_name: value.#field_name };
    }

    if wrapper_chain.is_empty() {
        return quote! { #field_name: value.#field_name.into() };
    }

    // Same conversion logic works both directions due to bidirectional From impls
    let conversion = build_conversion_expr(wrapper_chain);
    quote! { #field_name: { let x = value.#field_name; #conversion } }
}

/// Generate conversion for named enum variant fields (to JS)
fn generate_variant_field_to_js(
    field_name: &Option<&Ident>,
    wrap: bool,
    wrapper_chain: &[WrapperKind],
) -> proc_macro2::TokenStream {
    if !wrap {
        return quote! { #field_name };
    }

    if wrapper_chain.is_empty() {
        return quote! { #field_name: #field_name.into() };
    }

    let conversion = build_conversion_expr(wrapper_chain);
    quote! { #field_name: { let x = #field_name; #conversion } }
}

/// Generate conversion for named enum variant fields (from JS)
fn generate_variant_field_from_js(
    field_name: &Option<&Ident>,
    wrap: bool,
    wrapper_chain: &[WrapperKind],
) -> proc_macro2::TokenStream {
    if !wrap {
        return quote! { #field_name };
    }

    if wrapper_chain.is_empty() {
        return quote! { #field_name: #field_name.into() };
    }

    let conversion = build_conversion_expr(wrapper_chain);
    quote! { #field_name: { let x = #field_name; #conversion } }
}

/// Generate conversion for unnamed enum variant fields (to JS)
fn generate_unnamed_field_to_js(
    idx: &Ident,
    wrap: bool,
    wrapper_chain: &[WrapperKind],
) -> proc_macro2::TokenStream {
    if !wrap {
        return quote! { #idx };
    }

    if wrapper_chain.is_empty() {
        return quote! { #idx.into() };
    }

    let conversion = build_conversion_expr(wrapper_chain);
    quote! { { let x = #idx; #conversion } }
}

/// Generate conversion for unnamed enum variant fields (from JS)
fn generate_unnamed_field_from_js(
    idx: &Ident,
    wrap: bool,
    wrapper_chain: &[WrapperKind],
) -> proc_macro2::TokenStream {
    if !wrap {
        return quote! { #idx };
    }

    if wrapper_chain.is_empty() {
        return quote! { #idx.into() };
    }

    let conversion = build_conversion_expr(wrapper_chain);
    quote! { { let x = #idx; #conversion } }
}

/// Transform serde attributes for enums:
/// - Convert tag values from snake_case to camelCase
/// - Skip rename_all (we add our own camelCase)
fn transform_enum_serde_attrs(attrs: &[syn::Attribute]) -> Vec<proc_macro2::TokenStream> {
    attrs
        .iter()
        .filter(|a| a.path().is_ident("serde"))
        .filter_map(|attr| {
            if let syn::Meta::List(meta_list) = &attr.meta {
                let tokens_str = meta_list.tokens.to_string();

                // Skip rename_all - we add our own camelCase
                if tokens_str.contains("rename_all") {
                    return None;
                }

                // Transform tag = "snake_case" to tag = "camelCase"
                if tokens_str.contains("tag") {
                    let transformed = transform_tag_value(&tokens_str);
                    // Use the original tokens if parsing fails
                    match transformed.parse::<proc_macro2::TokenStream>() {
                        Ok(tokens) => return Some(quote! { #[serde(#tokens)] }),
                        Err(_) => {
                            // Fall back to original if transformation fails
                            let tokens = &meta_list.tokens;
                            return Some(quote! { #[serde(#tokens)] });
                        }
                    }
                }

                // Keep other serde attributes as-is
                let tokens = &meta_list.tokens;
                return Some(quote! { #[serde(#tokens)] });
            }
            None
        })
        .collect()
}

/// Transform field-level serde attributes for the generated `Js*` type.
///
/// Any `rename = "snake_case"` value is converted to camelCase so it stays
/// consistent with the struct-level `rename_all = "camelCase"`. A field-level
/// `rename` otherwise overrides `rename_all`, which would leak snake_case keys
/// into the JS/WASM output. All other serde options (`skip_serializing_if`,
/// `default`, etc.) are preserved unchanged.
fn transform_field_serde_attrs(attrs: &[syn::Attribute]) -> Vec<proc_macro2::TokenStream> {
    attrs
        .iter()
        .filter(|a| a.path().is_ident("serde"))
        .map(|attr| {
            if let syn::Meta::List(meta_list) = &attr.meta {
                let tokens_str = meta_list.tokens.to_string();
                // `rename_all` is a container option; never rewrite it here.
                if tokens_str.contains("rename") && !tokens_str.contains("rename_all") {
                    let transformed = transform_rename_value(&tokens_str);
                    if let Ok(tokens) = transformed.parse::<proc_macro2::TokenStream>() {
                        return quote! { #[serde(#tokens)] };
                    }
                }
                let tokens = &meta_list.tokens;
                quote! { #[serde(#tokens)] }
            } else {
                quote! { #attr }
            }
        })
        .collect()
}

/// Transform a serde `rename = "snake_case"` value to camelCase, leaving the
/// rest of the attribute token string untouched.
/// e.g., rename = "unified_card" -> rename = "unifiedCard"
fn transform_rename_value(s: &str) -> String {
    let mut result = s.to_string();

    if let Some(start) = result.find("rename") {
        if let Some(open_rel) = result[start..].find('"') {
            let open = start + open_rel;
            if let Some(close_rel) = result[open + 1..].find('"') {
                let close = open + 1 + close_rel;
                let rename_value = &result[open + 1..close];
                let camel_value = to_camel_case(rename_value);
                result = format!(
                    "{}\"{}\"{}",
                    &result[..open],
                    camel_value,
                    &result[close + 1..]
                );
            }
        }
    }

    result
}

/// Transform a serde tag value from snake_case to camelCase
/// e.g., tag = "content_type" -> tag = "contentType"
fn transform_tag_value(s: &str) -> String {
    let mut result = s.to_string();

    // Find tag = "..." pattern and transform the value inside quotes
    if let Some(start) = result.find("tag") {
        if let Some(quote_start) = result[start..].find('"') {
            let quote_start = start + quote_start + 1;
            if let Some(quote_end) = result[quote_start..].find('"') {
                let quote_end = quote_start + quote_end;
                let tag_value = &result[quote_start..quote_end];
                let camel_value = to_camel_case(tag_value);
                result = format!(
                    "{}\"{}\"{}",
                    &result[..quote_start],
                    camel_value,
                    &result[quote_end + 1..]
                );
            }
        }
    }

    result
}

/// Convert snake_case to camelCase
fn to_camel_case(s: &str) -> String {
    let mut result = String::new();
    let mut capitalize_next = false;

    for c in s.chars() {
        if c == '_' {
            capitalize_next = true;
        } else if capitalize_next {
            result.push(c.to_ascii_uppercase());
            capitalize_next = false;
        } else {
            result.push(c);
        }
    }

    result
}
