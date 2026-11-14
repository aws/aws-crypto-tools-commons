// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Writes every mutant of some Rust source files into the files themselves.
//!
//! Each mutated spot becomes `if ::test_server_control::mutant::is_on(<id>) { <mutant> } else { <original> }`,
//! so one build holds every mutant and a running server switches between them.
//! The files are rewritten in place: run this only on a throwaway copy.
//!
//! Usage: rust-mutant-schemata --root <dir> --out <mutants.json> [--first-id N]
//!        [--skip <id,id,...>] [--lines <lines.json>] <file.rs>...
//!
//! File paths are relative to --root, and so are the paths in mutants.json.
//! --lines names a JSON object {"<file>": [<line>, ...]}: only mutants on those
//! lines are written (a pull request's changed lines).
//! --skip names mutants that did not compile; their ids stay taken, so the
//! other ids do not move between attempts.

use proc_macro2::Span;
use quote::ToTokens;
use serde_json::{json, Value};
use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use syn::spanned::Spanned;
use syn::visit_mut::{self, VisitMut};
use syn::{parse_quote, BinOp, Block, Expr, ReturnType, Stmt, Type};

struct Options {
    root: PathBuf,
    out: PathBuf,
    first_id: u32,
    skip: HashSet<u32>,
    lines: Option<HashMap<String, HashSet<usize>>>,
    files: Vec<String>,
}

fn parse_args() -> Options {
    let mut args = std::env::args().skip(1);
    let mut options = Options {
        root: PathBuf::from("."),
        out: PathBuf::from("mutants.json"),
        first_id: 1,
        skip: HashSet::new(),
        lines: None,
        files: Vec::new(),
    };
    while let Some(arg) = args.next() {
        let mut value = || args.next().unwrap_or_else(|| panic!("{arg} needs a value"));
        match arg.as_str() {
            "--root" => options.root = PathBuf::from(value()),
            "--out" => options.out = PathBuf::from(value()),
            "--first-id" => options.first_id = value().parse().expect("--first-id"),
            "--skip" => {
                options.skip = value()
                    .split(',')
                    .filter(|s| !s.is_empty())
                    .map(|s| s.parse().expect("--skip"))
                    .collect()
            }
            "--lines" => {
                let text = std::fs::read_to_string(value()).expect("--lines file");
                let parsed: HashMap<String, Vec<usize>> =
                    serde_json::from_str(&text).expect("--lines JSON");
                options.lines = Some(
                    parsed
                        .into_iter()
                        .map(|(k, v)| (k, v.into_iter().collect()))
                        .collect(),
                );
            }
            _ => options.files.push(arg),
        }
    }
    options
}

struct Mutator<'a> {
    options: &'a Options,
    file: String,
    function: String,
    next_id: u32,
    mutants: Vec<Value>,
    // Spots left alone on purpose, by rule, for the report.
    skipped: HashMap<&'static str, usize>,
}

impl Mutator<'_> {
    fn skip(&mut self, rule: &'static str) {
        *self.skipped.entry(rule).or_default() += 1;
    }

    /// Takes the next id for a mutant at `span`. None when the mutant is skipped
    /// or is not on a chosen line; the id is taken either way.
    fn take(&mut self, span: Span, kind: &str, description: String) -> Option<u32> {
        let id = self.next_id;
        self.next_id += 1;
        let line = span.start().line;
        if let Some(lines) = &self.options.lines {
            if !lines
                .get(&self.file)
                .is_some_and(|wanted| wanted.contains(&line))
            {
                return None;
            }
        }
        if self.options.skip.contains(&id) {
            return None;
        }
        self.mutants.push(json!({
            "id": id,
            "file": self.file,
            "line": line,
            "column": span.start().column + 1,
            "kind": kind,
            "description": description,
            "function": self.function,
        }));
        Some(id)
    }

    /// `(if is_on(a) { m_a } else if is_on(b) { m_b } else { original })`
    fn switch(choices: Vec<(u32, Expr)>, original: Expr) -> Expr {
        let mut expr = original;
        for (id, mutant) in choices.into_iter().rev() {
            // Parentheses keep a block-like expression such as `match` from ending the statement early.
            expr = parse_quote!(if ::test_server_control::mutant::is_on(#id) { (#mutant) } else { (#expr) });
        }
        parse_quote!((#expr))
    }

    /// The `if is_on(id) { return <value>; }` statements that replace a function body.
    fn fn_value_guards(&mut self, output: &ReturnType, block: &Block) -> Vec<Stmt> {
        let values: Vec<Expr> = match output {
            ReturnType::Default => vec![parse_quote!(())],
            ReturnType::Type(_, ty) => return_values(ty),
        };
        let body = block.to_token_stream().to_string();
        let mut guards: Vec<Stmt> = Vec::new();
        for value in values {
            let text = value.to_token_stream().to_string();
            // A body that already returns this value would give a mutant no test can kill.
            if body == format!("{{ {text} }}") {
                self.skip("the function already returns that value");
                continue;
            }
            let Some(id) = self.take(
                block.span(),
                "fn_value",
                format!("replace the body of {} with {text}", self.function),
            ) else {
                continue;
            };
            guards.push(
                parse_quote!(if ::test_server_control::mutant::is_on(#id) { return #value; }),
            );
        }
        guards
    }

    fn mutate_fn(&mut self, attrs: &[syn::Attribute], sig: &syn::Signature, block: &mut Block) {
        // const fns cannot call is_on, and test code is not library code.
        if sig.constness.is_some() {
            self.skip("const fn");
            return;
        }
        if is_test(attrs) {
            self.skip("test function");
            return;
        }
        let outer = std::mem::replace(&mut self.function, sig.ident.to_string());
        let guards = self.fn_value_guards(&sig.output, block);
        self.visit_block_mut(block);
        // Added after the visit, so the guards' own conditions are not mutated.
        block.stmts.splice(0..0, guards);
        self.function = outer;
    }
}

/// The values a function body is replaced with, by return type. Empty for types with no obvious value.
fn return_values(ty: &Type) -> Vec<Expr> {
    let Type::Path(path) = ty else {
        return if matches!(ty, Type::Tuple(t) if t.elems.is_empty()) {
            vec![parse_quote!(())]
        } else {
            vec![]
        };
    };
    let Some(last) = path.path.segments.last() else {
        return vec![];
    };
    match last.ident.to_string().as_str() {
        "bool" => vec![parse_quote!(true), parse_quote!(false)],
        "u8" | "u16" | "u32" | "u64" | "u128" | "usize" | "i8" | "i16" | "i32" | "i64" | "i128"
        | "isize" => {
            vec![parse_quote!(0), parse_quote!(1)]
        }
        "String" => vec![parse_quote!(String::new())],
        "Vec" => vec![parse_quote!(Vec::new())],
        "Option" => vec![parse_quote!(None)],
        "Result" => vec![parse_quote!(Ok(Default::default()))],
        _ => vec![],
    }
}

fn is_test(attrs: &[syn::Attribute]) -> bool {
    attrs.iter().any(|attr| {
        let text = attr.to_token_stream().to_string();
        attr.path().is_ident("test") || text.contains("cfg (test)") || text.ends_with(":: test]")
    })
}

fn binary_replacements(op: &BinOp) -> Vec<(BinOp, &'static str)> {
    use syn::token;
    let span = op.span();
    match op {
        BinOp::Eq(_) => vec![(BinOp::Ne(token::Ne(span)), "!=")],
        BinOp::Ne(_) => vec![(BinOp::Eq(token::EqEq(span)), "==")],
        BinOp::Lt(_) => vec![(BinOp::Le(token::Le(span)), "<=")],
        BinOp::Le(_) => vec![(BinOp::Lt(token::Lt(span)), "<")],
        BinOp::Gt(_) => vec![(BinOp::Ge(token::Ge(span)), ">=")],
        BinOp::Ge(_) => vec![(BinOp::Gt(token::Gt(span)), ">")],
        BinOp::And(_) => vec![(BinOp::Or(token::OrOr(span)), "||")],
        BinOp::Or(_) => vec![(BinOp::And(token::AndAnd(span)), "&&")],
        BinOp::Add(_) => vec![(BinOp::Sub(token::Minus(span)), "-")],
        BinOp::Sub(_) => vec![(BinOp::Add(token::Plus(span)), "+")],
        BinOp::Mul(_) => vec![(BinOp::Div(token::Slash(span)), "/")],
        BinOp::Div(_) => vec![(BinOp::Mul(token::Star(span)), "*")],
        BinOp::AddAssign(_) => vec![(BinOp::SubAssign(token::MinusEq(span)), "-=")],
        BinOp::SubAssign(_) => vec![(BinOp::AddAssign(token::PlusEq(span)), "+=")],
        _ => vec![],
    }
}

fn contains_let(expr: &Expr) -> bool {
    match expr {
        Expr::Let(_) => true,
        Expr::Binary(binary) => contains_let(&binary.left) || contains_let(&binary.right),
        Expr::Paren(paren) => contains_let(&paren.expr),
        _ => false,
    }
}

fn is_literal(expr: &Expr) -> bool {
    matches!(expr, Expr::Lit(_))
}

impl VisitMut for Mutator<'_> {
    fn visit_item_fn_mut(&mut self, item: &mut syn::ItemFn) {
        let (attrs, sig) = (item.attrs.clone(), item.sig.clone());
        self.mutate_fn(&attrs, &sig, &mut item.block);
    }

    fn visit_impl_item_fn_mut(&mut self, item: &mut syn::ImplItemFn) {
        let (attrs, sig) = (item.attrs.clone(), item.sig.clone());
        self.mutate_fn(&attrs, &sig, &mut item.block);
    }

    fn visit_trait_item_fn_mut(&mut self, item: &mut syn::TraitItemFn) {
        if let Some(block) = &mut item.default {
            let (attrs, sig) = (item.attrs.clone(), item.sig.clone());
            self.mutate_fn(&attrs, &sig, block);
        }
    }

    fn visit_item_mod_mut(&mut self, item: &mut syn::ItemMod) {
        if is_test(&item.attrs) {
            self.skip("test module");
        } else {
            visit_mut::visit_item_mod_mut(self, item);
        }
    }

    fn visit_item_impl_mut(&mut self, item: &mut syn::ItemImpl) {
        // Debug and Display output is not behavior the SDKs promise.
        let formatting = item
            .trait_
            .as_ref()
            .and_then(|(_, path, _)| path.segments.last())
            .is_some_and(|segment| segment.ident == "Debug" || segment.ident == "Display");
        if formatting {
            self.skip("Debug or Display impl");
        } else if is_test(&item.attrs) {
            self.skip("test impl");
        } else {
            visit_mut::visit_item_impl_mut(self, item);
        }
    }

    // Constant contexts cannot call is_on.
    fn visit_item_const_mut(&mut self, _: &mut syn::ItemConst) {}
    fn visit_item_static_mut(&mut self, _: &mut syn::ItemStatic) {}
    fn visit_item_enum_mut(&mut self, _: &mut syn::ItemEnum) {}
    fn visit_impl_item_const_mut(&mut self, _: &mut syn::ImplItemConst) {}
    fn visit_type_mut(&mut self, _: &mut Type) {}

    fn visit_block_mut(&mut self, block: &mut Block) {
        for stmt in &mut block.stmts {
            // Visiting can swap parts for generated code with no source position, so spans come from the original.
            let original_span = stmt.span();
            self.visit_stmt_mut(stmt);
            // Skip a statement that only calls something: a missing check or a missing side effect.
            let Stmt::Expr(expr, Some(_)) = &*stmt else {
                continue;
            };
            let call = match expr {
                Expr::Try(attempt) => &*attempt.expr,
                other => other,
            };
            // `make_salt(&mut s).map_err(..)?` is named make_salt: skipping it skips the whole chain.
            let mut root = call;
            while let Expr::MethodCall(method) = root {
                match &*method.receiver {
                    inner @ (Expr::Call(_) | Expr::MethodCall(_)) => root = inner,
                    _ => break,
                }
            }
            let named = match root {
                Expr::Call(call) => call.func.to_token_stream().to_string().replace(' ', ""),
                Expr::MethodCall(call) => call.method.to_string(),
                _ => continue,
            };
            if named == "drop" {
                self.skip("drop call");
                continue;
            }
            let Some(id) = self.take(
                original_span,
                "skip_call",
                format!("skip the call to {named}"),
            ) else {
                continue;
            };
            let original = expr.clone();
            *stmt = parse_quote!(if !::test_server_control::mutant::is_on(#id) { #original; });
        }
    }

    fn visit_expr_mut(&mut self, expr: &mut Expr) {
        let original = expr.clone();
        visit_mut::visit_expr_mut(self, expr);
        match &original {
            Expr::Binary(binary) => {
                // Both sides fixed: the result never changes. A `let` chain cannot sit inside an `if` branch.
                if is_literal(&binary.left) && is_literal(&binary.right) {
                    self.skip("both sides are literals");
                    return;
                }
                if contains_let(&original) {
                    return;
                }
                let mut choices = Vec::new();
                for (op, text) in binary_replacements(&binary.op) {
                    let from = binary.op.to_token_stream().to_string();
                    if let Some(id) = self.take(
                        binary.op.span(),
                        "binary",
                        format!("replace {from} with {text}"),
                    ) {
                        let mut mutant = binary.clone();
                        mutant.op = op;
                        choices.push((id, Expr::Binary(mutant)));
                    }
                }
                if !choices.is_empty() {
                    *expr = Mutator::switch(choices, expr.clone());
                }
            }
            Expr::Unary(unary) if matches!(unary.op, syn::UnOp::Not(_) | syn::UnOp::Neg(_)) => {
                let from = unary.op.to_token_stream().to_string();
                if let Some(id) = self.take(unary.op.span(), "unary", format!("delete {from}")) {
                    *expr = Mutator::switch(vec![(id, (*unary.expr).clone())], expr.clone());
                }
            }
            _ => {}
        }
        // The condition of an `if` (not `if let`) is replaced with true and with false.
        if let (Expr::If(branch), Expr::If(before)) = (&mut *expr, &original) {
            if !contains_let(&branch.cond) {
                let span = before.cond.span();
                let mut choices = Vec::new();
                for value in [true, false] {
                    if let Some(id) = self.take(
                        span,
                        "condition",
                        format!("replace the condition with {value}"),
                    ) {
                        choices.push((id, parse_quote!(#value)));
                    }
                }
                if !choices.is_empty() {
                    let cond = (*branch.cond).clone();
                    *branch.cond = Mutator::switch(choices, cond);
                }
            }
        }
        // Each match arm, when a later `_` arm catches what it no longer matches.
        if let Expr::Match(matched) = expr {
            // A #[cfg] arm may not be compiled in, so it neither counts as the `_` arm nor gets deleted.
            let has_wildcard = matched.arms.iter().any(|arm| {
                matches!(arm.pat, syn::Pat::Wild(_)) && arm.guard.is_none() && arm.attrs.is_empty()
            });
            if has_wildcard {
                for arm in &mut matched.arms {
                    if matches!(arm.pat, syn::Pat::Wild(_)) || !arm.attrs.is_empty() {
                        continue;
                    }
                    let pattern = arm.pat.to_token_stream().to_string();
                    let Some(id) = self.take(
                        arm.pat.span(),
                        "match_arm",
                        format!("delete the match arm {pattern}"),
                    ) else {
                        continue;
                    };
                    let guard: Expr = match arm.guard.take() {
                        Some((_, guard)) => {
                            parse_quote!(!::test_server_control::mutant::is_on(#id) && (#guard))
                        }
                        None => parse_quote!(!::test_server_control::mutant::is_on(#id)),
                    };
                    arm.guard = Some((Default::default(), Box::new(guard)));
                }
            }
        }
    }
}

fn main() {
    let options = parse_args();
    let mut next_id = options.first_id;
    let mut mutants = Vec::new();
    let mut skipped: HashMap<&str, usize> = HashMap::new();
    for file in &options.files {
        let path = options.root.join(file);
        let source =
            std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
        let mut syntax =
            syn::parse_file(&source).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
        let mut mutator = Mutator {
            options: &options,
            file: file.clone(),
            function: String::new(),
            next_id,
            mutants: Vec::new(),
            skipped: HashMap::new(),
        };
        mutator.visit_file_mut(&mut syntax);
        next_id = mutator.next_id;
        if !mutator.mutants.is_empty() {
            std::fs::write(&path, prettyplease::unparse(&syntax))
                .unwrap_or_else(|e| panic!("{}: {e}", path.display()));
        }
        mutants.extend(mutator.mutants);
        for (rule, count) in mutator.skipped {
            *skipped.entry(rule).or_insert(0usize) += count;
        }
    }
    let summary = json!({ "next_id": next_id, "mutants": mutants, "skipped": skipped });
    std::fs::write(
        &options.out,
        serde_json::to_string_pretty(&summary).unwrap(),
    )
    .expect("write --out");
}
