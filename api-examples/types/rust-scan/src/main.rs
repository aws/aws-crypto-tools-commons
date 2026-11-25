//! Prints the types in one crate's public signatures, as JSON lines.
//!
//! Usage: rust-types-scan <crate-name> <crate-dir>
//!
//! It reads every .rs file except tests, benches, examples and build scripts.
//! An item counts as public when it is marked `pub`, even inside a private module.
//! It prints these lines, sorted:
//!   {"pos":"param","type":"&[u8]","count":3}     a parameter of a pub fn
//!   {"pos":"return","type":"Vec<u8>","count":2}   a return type, with one Result layer removed
//!   {"pos":"field","type":"Blob","count":1}       a pub struct field or an enum variant field
//!   {"defines":"Bytes","path":"bytes::Bytes"}     a pub type, at the module path of its file
//!   {"defines":"Bytes","path":"uuid::Bytes","alias":"[u8; 16]"}  a pub type alias and its target
//!   {"impl":"AsRef<[u8]>","for":"Bytes"}          a trait impl that says what a type holds
//!   {"ctor":"Client","fn":"new","param":"&SdkConfig"}  a pub fn in `impl Client` that takes one value and returns Self
//!   {"parse_errors":0}
//! A generic parameter shows as `_`, and a generic fn parameter `x: T` shows as `impl` plus T's bounds.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

use proc_macro2::{TokenStream, TokenTree};
use syn::punctuated::Punctuated;
use syn::{
    Expr, FnArg, GenericArgument, GenericParam, Generics, ImplItem, Item, Lit, PathArguments, ReturnType,
    Signature, TraitBoundModifier, TraitItem, Type, TypeParamBound, Visibility, WherePredicate,
};

// Traits whose impls say what a type holds: bytes, text, a path or a reader.
const HOLDS_TRAITS: &[&str] = &["AsRef", "Deref", "Borrow", "From", "Read", "BufRead", "AsyncRead", "Stream", "Body"];
// Auto traits are left out of bounds, so `dyn Read + Send` and `dyn Read` count as one type.
const AUTO_TRAITS: &[&str] = &["Send", "Sync", "Unpin"];

// Generic names in scope, each with its rendered trait bounds.
type Generic = BTreeMap<String, Vec<String>>;

#[derive(Default)]
struct Scan {
    types: BTreeMap<(String, String), u64>,
    defines: BTreeSet<(String, String)>,
    aliases: BTreeSet<(String, String, String)>,
    impls: BTreeSet<(String, String)>,
    ctors: BTreeSet<(String, String, String)>,
    parse_errors: u64,
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 3 {
        eprintln!("usage: rust-types-scan <crate-name> <crate-dir>");
        std::process::exit(2);
    }
    let crate_name = args[1].replace('-', "_");
    let root = PathBuf::from(&args[2]);
    let mut scan = Scan::default();
    let mut files = Vec::new();
    rust_files(&root, &root, &mut files);
    files.sort();
    for file in files {
        let Ok(text) = fs::read_to_string(&file) else { continue };
        let Ok(parsed) = syn::parse_file(&text) else {
            scan.parse_errors += 1;
            continue;
        };
        let mut module = vec![crate_name.clone()];
        module.extend(module_path(&root, &file));
        scan.items(&parsed.items, &module, &Generic::new());
    }
    for ((pos, ty), count) in &scan.types {
        println!("{}", serde_json::json!({"pos": pos, "type": ty, "count": count}));
    }
    for (name, path) in &scan.defines {
        println!("{}", serde_json::json!({"defines": name, "path": path}));
    }
    for (name, path, target) in &scan.aliases {
        println!("{}", serde_json::json!({"defines": name, "path": path, "alias": target}));
    }
    for (tr, ty) in &scan.impls {
        println!("{}", serde_json::json!({"impl": tr, "for": ty}));
    }
    for (ty, name, param) in &scan.ctors {
        println!("{}", serde_json::json!({"ctor": ty, "fn": name, "param": param}));
    }
    println!("{}", serde_json::json!({"parse_errors": scan.parse_errors}));
}

// Every .rs file under `dir`, skipping tests, benches, examples, build scripts and build output.
fn rust_files(root: &Path, dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = fs::read_dir(dir) else { return };
    for entry in entries.flatten() {
        let path = entry.path();
        let name = entry.file_name().to_string_lossy().to_string();
        if path.is_dir() {
            if !["tests", "benches", "examples", "target", ".git"].contains(&name.as_str()) {
                rust_files(root, &path, out);
            }
        } else if name.ends_with(".rs") && !(name == "build.rs" && path.parent() == Some(root)) {
            out.push(path);
        }
    }
}

// The module path of a file: src/a/b.rs and src/a/b/mod.rs are a::b, and src/lib.rs is the crate root.
fn module_path(root: &Path, file: &Path) -> Vec<String> {
    let rel = file.strip_prefix(root).unwrap_or(file);
    let rel = rel.strip_prefix("src").unwrap_or(rel);
    let mut parts: Vec<String> = rel.iter().map(|p| p.to_string_lossy().to_string()).collect();
    if let Some(last) = parts.pop() {
        let stem = last.trim_end_matches(".rs").to_string();
        if !["lib", "main", "mod"].contains(&stem.as_str()) {
            parts.push(stem);
        }
    }
    parts
}

fn is_pub(vis: &Visibility) -> bool {
    matches!(vis, Visibility::Public(_))
}

// Names that follow `pub struct` or `pub enum` in a macro's tokens.
fn pub_types_in(tokens: TokenStream) -> Vec<syn::Ident> {
    let trees: Vec<TokenTree> = tokens.into_iter().collect();
    let mut out = Vec::new();
    for (i, tree) in trees.iter().enumerate() {
        match tree {
            TokenTree::Group(g) => out.extend(pub_types_in(g.stream())),
            TokenTree::Ident(word) if word == "pub" => {
                if let (Some(TokenTree::Ident(kind)), Some(TokenTree::Ident(name))) = (trees.get(i + 1), trees.get(i + 2)) {
                    if kind == "struct" || kind == "enum" {
                        out.push(name.clone());
                    }
                }
            }
            _ => {}
        }
    }
    out
}

impl Scan {
    fn items(&mut self, items: &[Item], module: &[String], outer: &Generic) {
        for item in items {
            match item {
                Item::Fn(f) if is_pub(&f.vis) => self.signature(&f.sig, outer, None),
                Item::Impl(imp) => self.impl_block(imp, outer),
                Item::Trait(t) if is_pub(&t.vis) => {
                    self.define(&t.ident, module);
                    let g = with_generics(outer, &t.generics);
                    for ti in &t.items {
                        if let TraitItem::Fn(m) = ti {
                            self.signature(&m.sig, &g, None);
                        }
                    }
                }
                Item::Struct(s) if is_pub(&s.vis) => {
                    self.define(&s.ident, module);
                    let g = with_generics(outer, &s.generics);
                    for field in s.fields.iter().filter(|f| is_pub(&f.vis)) {
                        self.add("field", render(&field.ty, &g));
                    }
                }
                Item::Enum(e) if is_pub(&e.vis) => {
                    self.define(&e.ident, module);
                    let g = with_generics(outer, &e.generics);
                    for variant in &e.variants {
                        for field in variant.fields.iter() {
                            self.add("field", render(&field.ty, &g));
                        }
                    }
                }
                Item::Type(t) if is_pub(&t.vis) => {
                    let mut path = module.to_vec();
                    path.push(t.ident.to_string());
                    let target = render(&t.ty, &with_generics(outer, &t.generics)).unwrap_or_else(|| "_".to_string());
                    self.aliases.insert((t.ident.to_string(), path.join("::"), target));
                }
                Item::Union(u) if is_pub(&u.vis) => self.define(&u.ident, module),
                Item::Mod(m) => {
                    if let Some((_, inner)) = &m.content {
                        let mut path = module.to_vec();
                        path.push(m.ident.to_string());
                        self.items(inner, &path, outer);
                    }
                }
                // Macros like pin_project! wrap type definitions, so look for `pub struct Name` in their tokens.
                Item::Macro(m) => {
                    for name in pub_types_in(m.mac.tokens.clone()) {
                        self.define(&name, module);
                    }
                }
                _ => {}
            }
        }
    }

    fn impl_block(&mut self, imp: &syn::ItemImpl, outer: &Generic) {
        let g = with_generics(outer, &imp.generics);
        let Some(self_ty) = render(&imp.self_ty, &g) else { return };
        if let Some((_, trait_path, _)) = &imp.trait_ {
            let name = trait_path.segments.last().map(|s| s.ident.to_string()).unwrap_or_default();
            if !HOLDS_TRAITS.contains(&name.as_str()) {
                return;
            }
            let Some(mut tr) = render_path(trait_path, &g) else { return };
            if name == "Deref" {
                for ii in &imp.items {
                    if let ImplItem::Type(t) = ii {
                        if t.ident == "Target" {
                            if let Some(target) = render(&t.ty, &g) {
                                tr = format!("Deref<Target = {target}>");
                            }
                        }
                    }
                }
            }
            self.impls.insert((tr, self_ty));
            return;
        }
        let base = self_ty.split('<').next().unwrap_or(&self_ty).to_string();
        for ii in &imp.items {
            if let ImplItem::Fn(m) = ii {
                if is_pub(&m.vis) {
                    self.signature(&m.sig, &g, Some(&base));
                }
            }
        }
    }

    // `owner` is the type of an inherent impl, so a pub fn there that returns Self is a constructor.
    fn signature(&mut self, sig: &Signature, outer: &Generic, owner: Option<&str>) {
        let g = with_generics(outer, &sig.generics);
        let returns_self = match &sig.output {
            ReturnType::Type(_, ty) => owner.is_some_and(|o| names_type(unwrap_result(ty), o)),
            ReturnType::Default => false,
        };
        // A constructor that takes one value turns that value into the type, like Client::new(&SdkConfig).
        let one_value = sig.inputs.len() == 1 && matches!(sig.inputs.first(), Some(FnArg::Typed(_)));
        for input in &sig.inputs {
            if let FnArg::Typed(pt) = input {
                let ty = render_param(&pt.ty, &g);
                if returns_self && one_value {
                    if let (Some(o), Some(t)) = (owner, &ty) {
                        self.ctors.insert((o.to_string(), sig.ident.to_string(), t.clone()));
                    }
                }
                self.add("param", ty);
            }
        }
        if let ReturnType::Type(_, ty) = &sig.output {
            self.add("return", render(unwrap_result(ty), &g));
        }
    }

    fn add(&mut self, pos: &str, ty: Option<String>) {
        if let Some(ty) = ty {
            *self.types.entry((pos.to_string(), ty)).or_default() += 1;
        }
    }

    fn define(&mut self, ident: &syn::Ident, module: &[String]) {
        let mut path = module.to_vec();
        path.push(ident.to_string());
        self.defines.insert((ident.to_string(), path.join("::")));
    }
}

// True when `ty` is `Self` or the named type, with any generic arguments.
fn names_type(ty: &Type, owner: &str) -> bool {
    match ty {
        Type::Path(p) => p.path.segments.last().is_some_and(|s| s.ident == "Self" || s.ident == owner),
        _ => false,
    }
}

fn with_generics(outer: &Generic, generics: &Generics) -> Generic {
    let mut g = outer.clone();
    for param in &generics.params {
        match param {
            GenericParam::Type(tp) => {
                g.insert(tp.ident.to_string(), Vec::new());
            }
            GenericParam::Const(c) => {
                g.insert(c.ident.to_string(), Vec::new());
            }
            GenericParam::Lifetime(_) => {}
        }
    }
    let mut bounds: Vec<(String, Vec<String>)> = Vec::new();
    for param in &generics.params {
        if let GenericParam::Type(tp) = param {
            bounds.push((tp.ident.to_string(), render_bounds(&tp.bounds, &g)));
        }
    }
    if let Some(wc) = &generics.where_clause {
        for pred in &wc.predicates {
            if let WherePredicate::Type(pt) = pred {
                if let Type::Path(p) = &pt.bounded_ty {
                    if let Some(ident) = p.path.get_ident() {
                        bounds.push((ident.to_string(), render_bounds(&pt.bounds, &g)));
                    }
                }
            }
        }
    }
    for (name, found) in bounds {
        if let Some(list) = g.get_mut(&name) {
            list.extend(found);
        }
    }
    g
}

fn unwrap_result(ty: &Type) -> &Type {
    if let Type::Path(p) = ty {
        if let Some(last) = p.path.segments.last() {
            if last.ident == "Result" {
                if let PathArguments::AngleBracketed(a) = &last.arguments {
                    if let Some(GenericArgument::Type(t)) = a.args.first() {
                        return t;
                    }
                }
            }
        }
    }
    ty
}

// A parameter `x: T` with `T: AsRef<[u8]>` shows as `impl AsRef<[u8]>`.
fn render_param(ty: &Type, g: &Generic) -> Option<String> {
    if let Type::Path(p) = ty {
        if let Some(ident) = p.path.get_ident() {
            if let Some(bounds) = g.get(&ident.to_string()) {
                return if bounds.is_empty() { None } else { Some(format!("impl {}", bounds.join(" + "))) };
            }
        }
    }
    render(ty, g)
}

fn render(ty: &Type, g: &Generic) -> Option<String> {
    match ty {
        Type::Reference(r) => {
            let inner = render(&r.elem, g)?;
            Some(if r.mutability.is_some() { format!("&mut {inner}") } else { format!("&{inner}") })
        }
        Type::Slice(s) => Some(format!("[{}]", render(&s.elem, g)?)),
        Type::Array(a) => Some(format!("[{}; {}]", render(&a.elem, g)?, array_len(&a.len))),
        Type::Tuple(t) => {
            let parts: Option<Vec<String>> = t.elems.iter().map(|e| render(e, g)).collect();
            Some(format!("({})", parts?.join(", ")))
        }
        Type::Paren(p) => render(&p.elem, g),
        Type::Group(gr) => render(&gr.elem, g),
        Type::Path(p) if p.qself.is_none() => render_path(&p.path, g),
        Type::TraitObject(t) => join_bounds(render_bounds(&t.bounds, g)).map(|b| format!("dyn {b}")),
        Type::ImplTrait(t) => join_bounds(render_bounds(&t.bounds, g)).map(|b| format!("impl {b}")),
        _ => None,
    }
}

fn render_path(path: &syn::Path, g: &Generic) -> Option<String> {
    let first = path.segments.first()?.ident.to_string();
    let last = path.segments.last()?;
    let name = last.ident.to_string();
    if first == "Self" {
        return None;
    }
    if g.contains_key(&first) {
        // A bare generic is `_`. A path through a generic, like T::Output, is skipped.
        return if path.segments.len() == 1 { Some("_".to_string()) } else { None };
    }
    match &last.arguments {
        PathArguments::None => Some(name),
        PathArguments::AngleBracketed(a) => {
            let mut parts = Vec::new();
            for arg in &a.args {
                match arg {
                    GenericArgument::Lifetime(_) => {}
                    GenericArgument::Type(t) => parts.push(render(t, g)?),
                    GenericArgument::Const(e) => parts.push(const_text(e)),
                    GenericArgument::AssocType(b) => parts.push(format!("{} = {}", b.ident, render(&b.ty, g)?)),
                    _ => return None,
                }
            }
            Some(if parts.is_empty() { name } else { format!("{name}<{}>", parts.join(", ")) })
        }
        PathArguments::Parenthesized(p) => {
            let inputs: Option<Vec<String>> = p.inputs.iter().map(|t| render(t, g)).collect();
            let output = match &p.output {
                ReturnType::Default => String::new(),
                ReturnType::Type(_, t) => format!(" -> {}", render(t, g)?),
            };
            Some(format!("{name}({}){output}", inputs?.join(", ")))
        }
    }
}

fn render_bounds(bounds: &Punctuated<TypeParamBound, syn::Token![+]>, g: &Generic) -> Vec<String> {
    let mut out = Vec::new();
    for bound in bounds {
        if let TypeParamBound::Trait(t) = bound {
            if matches!(t.modifier, TraitBoundModifier::Maybe(_)) {
                continue;
            }
            if let Some(s) = render_path(&t.path, g) {
                if !AUTO_TRAITS.contains(&s.as_str()) {
                    out.push(s);
                }
            }
        }
    }
    out
}

fn join_bounds(bounds: Vec<String>) -> Option<String> {
    if bounds.is_empty() {
        None
    } else {
        Some(bounds.join(" + "))
    }
}

// An array length shows as its number, or N when it is a name.
fn array_len(expr: &Expr) -> String {
    match expr {
        Expr::Lit(l) => match &l.lit {
            Lit::Int(i) => i.base10_digits().to_string(),
            _ => "N".to_string(),
        },
        _ => "N".to_string(),
    }
}

fn const_text(expr: &Expr) -> String {
    array_len(expr)
}
