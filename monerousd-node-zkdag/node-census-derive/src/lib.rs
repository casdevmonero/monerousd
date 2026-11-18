// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)

//! ⭐⭐⭐ DB-402 R2 — THE `Node` FIELD CENSUS IS DERIVED FROM THE STRUCT, never written by hand.
//!
//! The restart census and the replicated-state census compare EVERY field of `pub struct Node`. Their field list used to
//! be written by an untracked script someone had to remember to re-run — and DB-402 measured the common cause of every
//! guard that missed DB-401: a subject list written by hand goes stale the day the code grows. This derive (the serde
//! shape: the compiler hands it the struct, so it cannot disagree with it) emits, on `#[cfg_attr(test, derive(..))]`:
//! - `Node::NODE_FIELD_NAMES` — every field, in declaration order;
//! - `Node::node_field_census(skip)` — each field's streaming canonical digest, through autoref specialization
//!   (`(&Probe(&self.f)).census_digest()`): `Some` when the field's type is `Debug`, `None` when it is not, so a new field
//!   never breaks the build, and a `None` with no stand-in and no declared reason is refused by the completeness pin.
//! It writes no file and adds nothing to any production binary (a dev-dependency, test builds only).
use proc_macro::TokenStream;
use quote::quote;

#[proc_macro_derive(NodeFieldCensus)]
pub fn node_field_census(input: TokenStream) -> TokenStream {
    let ast: syn::DeriveInput = match syn::parse(input) {
        Ok(a) => a,
        Err(e) => return e.to_compile_error().into(),
    };
    let name = &ast.ident;
    let fields = match &ast.data {
        syn::Data::Struct(syn::DataStruct { fields: syn::Fields::Named(n), .. }) => &n.named,
        _ => {
            return syn::Error::new_spanned(name, "NodeFieldCensus derives only on a struct with named fields")
                .to_compile_error()
                .into()
        }
    };
    let idents: Vec<&syn::Ident> = fields.iter().filter_map(|f| f.ident.as_ref()).collect();
    let names: Vec<String> = idents.iter().map(|i| i.to_string()).collect();
    quote! {
        impl #name {
            /// DB-402 R2: every field of this struct, in declaration order (derived; never a hand-written list).
            pub(crate) const NODE_FIELD_NAMES: &'static [&'static str] = &[#(#names),*];

            /// DB-402 R2: every field's canonical digest, `None` for a field named in `skip` or whose type is not `Debug`.
            pub(crate) fn node_field_census(&self, skip: &[&str]) -> Vec<(&'static str, Option<(u64, usize)>)> {
                #[allow(unused_imports)]
                use crate::node::restart_census_fields::{DigestUnprintable as _, DigestViaDebug as _, Probe};
                vec![#((#names, if skip.contains(&#names) { None } else { (&Probe(&self.#idents)).census_digest() })),*]
            }

            /// DB-402 R1 triage: stream one field's `{:?}` into `out` (the first-difference instrument); `false` when no field
            /// has that name or its type is not `Debug`.
            pub(crate) fn node_field_render(&self, name: &str, out: &mut dyn std::fmt::Write) -> bool {
                #[allow(unused_imports)]
                use crate::node::restart_census_fields::{Probe, RenderUnprintable as _, RenderViaDebug as _};
                match name {
                    #(#names => (&Probe(&self.#idents)).census_render(out),)*
                    _ => false,
                }
            }
        }
    }
    .into()
}
