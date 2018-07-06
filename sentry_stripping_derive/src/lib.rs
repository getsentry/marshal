extern crate syn;

#[macro_use] extern crate synstructure;
#[macro_use] extern crate quote;
#[macro_use] extern crate proc_macro2;

use syn::{Meta, NestedMeta, MetaNameValue, Lit};
use quote::ToTokens;
use proc_macro2::TokenStream;

decl_derive!([ProcessItem, attributes(process_item)] => process_item_derive);

fn process_item_derive(s: synstructure::Structure) -> TokenStream {
    let mut body = TokenStream::new();
    for variant in s.variants() {
        let mut variant = variant.clone();
        for binding in variant.bindings_mut() {
            binding.style = synstructure::BindStyle::RefMut;
        }
        variant.each(|bi| {
            let mut pii_kind = None;
            for attr in &bi.ast().attrs {
                if let Some(Meta::List(metalist)) = attr.interpret_meta() {
                    if metalist.ident == "process_item" {
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
            let pii_kind = pii_kind.map(|x| quote!(Some(#x))).unwrap_or_else(|| quote!(None));
            quote! {
                __protocol::ProcessItem::process_item(#bi, __processor, &__protocol::ProcessInfo {
                    pii_kind: #pii_kind,
                });
            }
        }).to_tokens(&mut body);
    }

    s.gen_impl(quote! {
        use protocol as __protocol;

        gen impl __protocol::ProcessItem for @Self {
            fn process_item(annotated: &mut Annotated<Self>,
                            __processor: &__protocol::Processor,
                            __info: &__protocol::ProcessInfo)
            {
                match *annotated {
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
        "databag" => quote!(PiiKind::DataBag),
        _ => panic!("invalid pii_kind variant '{}'", name)
    }
}
