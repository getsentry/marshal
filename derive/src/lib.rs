extern crate syn;

#[macro_use] extern crate synstructure;
#[macro_use] extern crate quote;
extern crate proc_macro2;

use syn::{Meta, NestedMeta, MetaNameValue, Lit};
use quote::ToTokens;
use proc_macro2::TokenStream;

decl_derive!([ProcessAnnotatedValue, attributes(process_annotated_value)] => process_item_derive);

fn process_item_derive(s: synstructure::Structure) -> TokenStream {
    let mut body = TokenStream::new();
    for variant in s.variants() {
        let mut variant = variant.clone();
        for binding in variant.bindings_mut() {
            binding.style = synstructure::BindStyle::MoveMut;
        }
        let mut variant_body = TokenStream::new();
        for bi in variant.bindings() {
            let mut pii_kind = None;
            let mut cap = None;
            let mut process_annotated_value = false;
            for attr in &bi.ast().attrs {
                let meta = match attr.interpret_meta() {
                    Some(meta) => meta,
                    None => continue,
                };
                if meta.name() == "process_annotated_value" {
                    process_annotated_value = true;
                } else {
                    continue;
                }

                if let Meta::List(metalist) = meta {
                    process_annotated_value = true;
                    for nested_meta in metalist.nested {
                        match nested_meta {
                            NestedMeta::Literal(..) => panic!("unexpected literal attribute"),
                            NestedMeta::Meta(meta) => {
                                match meta {
                                    Meta::NameValue(MetaNameValue { ident, lit, .. }) => {
                                        if ident == "pii_kind" {
                                            match lit {
                                                Lit::Str(litstr) => {
                                                    pii_kind = Some(pii_kind_to_enum_variant(&litstr.value()));
                                                }
                                                _ => {
                                                    panic!("Got non string literal for pii_kind");
                                                }
                                            }
                                        } else if ident == "cap" {
                                            match lit {
                                                Lit::Str(litstr) => {
                                                    cap = Some(cap_to_enum_variant(&litstr.value()));
                                                }
                                                _ => {
                                                    panic!("Got non string literal for cap");
                                                }
                                            }
                                        }
                                    }
                                    other => {
                                        panic!("Unexpected or bad attribute {}", other.name());
                                    }
                                }
                            }
                        }
                    }
                }
            }

            if process_annotated_value {
                let pii_kind = pii_kind.map(|x| quote!(Some(__processor::#x))).unwrap_or_else(|| quote!(None));
                let cap = cap.map(|x| quote!(Some(__processor::#x))).unwrap_or_else(|| quote!(None));
                (quote! {
                    #bi = __processor::ProcessAnnotatedValue::process_annotated_value(
                        #bi, __processor, &__processor::ValueInfo
                    {
                        pii_kind: #pii_kind,
                        cap: #cap,
                    });
                }).to_tokens(&mut variant_body);
            } else {
                // just do nothing
                (quote! {
                    #bi = #bi;
                }).to_tokens(&mut variant_body);
            }
        }

        let pat = variant.pat();
        let mut variant = variant.clone();
        for binding in variant.bindings_mut() {
            binding.style = synstructure::BindStyle::Move;
        }
        let assemble_pat = variant.pat();

        (quote! {
            __meta::Annotated(Some(#pat), __meta) => {
                #variant_body
                __meta::Annotated(Some(#assemble_pat), __meta)
            }
            __annotated @ __meta::Annotated(..) => __annotated
        }).to_tokens(&mut body);
    }

    s.gen_impl(quote! {
        use processor as __processor;
        use meta as __meta;

        gen impl __processor::ProcessAnnotatedValue for @Self {
            fn process_annotated_value(
                __annotated: __meta::Annotated<Self>,
                __processor: &__processor::Processor,
                __info: &__processor::ValueInfo
            ) -> __meta::Annotated<Self> {
                match __annotated {
                    #body
                }
            }
        }
    })
}

fn pii_kind_to_enum_variant(name: &str) -> TokenStream {
    match name {
        "freeform" => quote!(PiiKind::Freeform),
        "ip" => quote!(PiiKind::Ip),
        "id" => quote!(PiiKind::Id),
        "username" => quote!(PiiKind::Username),
        "sensitive" => quote!(PiiKind::Sensitive),
        "name" => quote!(PiiKind::Name),
        "email" => quote!(PiiKind::Email),
        "databag" => quote!(PiiKind::Databag),
        _ => panic!("invalid pii_kind variant '{}'", name)
    }
}

fn cap_to_enum_variant(name: &str) -> TokenStream {
    match name {
        "summary" => quote!(Cap::Summary),
        "message" => quote!(Cap::Message),
        "path" => quote!(Cap::Path),
        "short_path" => quote!(Cap::ShortPath),
        "databag" => quote!(Cap::Databag),
        _ => panic!("invalid cap variant '{}'", name)
    }
}
