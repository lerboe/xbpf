//! Procedural macros for [xbpf](https://docs.rs/xbpf). Use them through the
//! re-exports of `xbpf`.

use proc_macro::TokenStream;
use quote::{format_ident, quote};
use syn::{Error, Ident, ItemFn, Token, parse_macro_input, punctuated::Punctuated};

/// Turns a function into a test of a `BPF_PROG_TYPE_SYSCALL` program.
///
/// See `xbpf::test` for the details.
#[proc_macro_attribute]
pub fn test(attr: TokenStream, item: TokenStream) -> TokenStream {
    let args = parse_macro_input!(attr with Punctuated::<Ident, Token![,]>::parse_terminated);
    let func = parse_macro_input!(item as ItemFn);

    let args: Vec<Ident> = args.into_iter().collect();
    let [bpf, prog] = args.as_slice() else {
        return Error::new_spanned(
            quote!(#(#args),*),
            "expected `#[xbpf::test(<bpf_prog>, <syscall>)]`",
        )
        .into_compile_error()
        .into();
    };

    let ItemFn {
        attrs,
        vis,
        sig,
        block,
    } = func;
    if !sig.inputs.is_empty() || sig.asyncness.is_some() {
        return Error::new_spanned(
            sig,
            "xbpf::test functions take no arguments and are not async",
        )
        .into_compile_error()
        .into();
    }

    let builder = format_ident!("{}SkelBuilder", skel_name(&bpf.to_string()));

    quote! {
        #[test]
        #(#attrs)*
        #vis #sig {
            #[allow(unused_imports)]
            use #bpf::types;

            let mut __xbpf_obj = ::xbpf::OpenObject::new();
            let __xbpf_skel = {
                use ::xbpf::libbpf_rs::skel::{OpenSkel, SkelBuilder};
                #bpf::#builder::default()
                    .open(&mut __xbpf_obj)
                    .and_then(|skel| skel.load())
                    .expect(concat!("failed to load ", stringify!(#bpf)))
            };
            let #prog = |ctx| ::xbpf::test::run(&__xbpf_skel.progs.#prog, ctx);

            #block
        }
    }
    .into()
}

/// Mirrors how libbpf-cargo names a skeleton after its object.
fn skel_name(obj: &str) -> String {
    let mut name = String::new();
    for part in obj.split('_') {
        let mut chars = part.chars();
        let Some(first) = chars.next() else { continue };
        name.extend(first.to_uppercase());
        name.push_str(chars.as_str());
    }
    name
}
