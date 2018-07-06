extern crate syn;

#[macro_use] extern crate synstructure;
#[macro_use] extern crate quote;
#[macro_use] extern crate proc_macro2;

use syn::{Meta, NestedMeta, MetaNameValue, Lit};
use quote::ToTokens;
use proc_macro2::TokenStream;

decl_derive!([ProcessValue, attributes(process_value)] => process_item_derive);

fn process_item_derive(s: synstructure::Structure) -> TokenStream {
    let mut body = TokenStream::new();
    for variant in s.variants() {
        let mut variant = variant.clone();
        for binding in variant.bindings_mut() {
            binding.style = synstructure::BindStyle::RefMut;
        }
        variant.each(|bi| {
            let mut pii_kind = None;
            let mut cap = None;
            let mut process_value = false;
            for attr in &bi.ast().attrs {
                if let Some(Meta::List(metalist)) = attr.interpret_meta() {
                    if metalist.ident == "process_value" {
                        process_value = true;
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
            }
            if process_value {
                let pii_kind = pii_kind.map(|x| quote!(Some(__processor::#x))).unwrap_or_else(|| quote!(None));
                let cap = cap.map(|x| quote!(Some(__processor::#x))).unwrap_or_else(|| quote!(None));
                quote! {
                    __processor::ProcessValue::process_value(#bi, __processor, &__processor::ValueInfo {
                        pii_kind: #pii_kind,
                        cap: #cap,
                    });
                }
            } else {
                quote! {
                    ::std::mem::drop(#bi);
                }
            }
        }).to_tokens(&mut body);
    }

    s.gen_impl(quote! {
        use processor as __processor;

        gen impl __processor::ProcessValue for @Self {
            fn process_value(__annotated: &mut Annotated<Self>,
                            __processor: &__processor::Processor,
                            __info: &__processor::ValueInfo)
            {
                match __annotated.value_mut() {
                    Some(__value) => {
                        match *__value {
                            #body
                        }
                    }
                    None => {}
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
        "databag" => quote!(PiiKind::DataBag),
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
