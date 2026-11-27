// Prints the call signatures of some exports of an installed npm package as
// JSON, read from its .d.ts files with the TypeScript compiler.
//
//   node read_dts.js <dir with node_modules> <package> <name>...
//
// A name is an exported class (its constructor), an exported function, or
// fn().method for a method of what fn returns (buildClient().encrypt). A
// parameter whose type is an interface or object literal also lists its
// properties, so { generatorKeyId?: string } shows up as an option.
"use strict";
const path = require("node:path");
const { createRequire } = require("node:module");

const [dir, pkg, ...names] = process.argv.slice(2);
const req = createRequire(path.join(path.resolve(dir), "package.json"));
const ts = req("typescript");

const entry = req.resolve(`${pkg}/package.json`).replace(/package\.json$/, "") + require(req.resolve(`${pkg}/package.json`)).types;
const program = ts.createProgram([entry], { strict: true, skipLibCheck: true });
const checker = program.getTypeChecker();
const exportsOf = checker.getExportsOfModule(checker.getSymbolAtLocation(program.getSourceFile(entry)));
const exported = name => {
  const s = exportsOf.find(x => x.name === name);
  if (!s) throw new Error(`${pkg} has no export ${name}`);
  return s.flags & ts.SymbolFlags.Alias ? checker.getAliasedSymbol(s) : s;
};

// Uint8Array<ArrayBufferLike> is how TypeScript 5.7+ prints a plain Uint8Array.
const text = t => checker.typeToString(t, undefined, ts.TypeFormatFlags.NoTruncation).replace(/<ArrayBufferLike>/g, "");
// An options object of the package's own: not a class, a function, or a type
// from TypeScript's lib or @types/node such as Uint8Array.
const fromLib = t => (t.symbol?.declarations || []).some(d => /[\\/](typescript[\\/]lib|@types[\\/]node)[\\/]/.test(d.getSourceFile().fileName));
// A mapped type such as Partial<KmsKeyringInput> is declared in lib but its properties are the package's.
const isMapped = t => !!(t.objectFlags & ts.ObjectFlags.Mapped);
const isObject = t => (t.flags & ts.TypeFlags.Object) && !(t.symbol?.flags & ts.SymbolFlags.Class)
  && !t.getCallSignatures().length && (isMapped(t) || !fromLib(t)) && t.getProperties().length > 0;

// The members of a union, with enum members folded back into their enum,
// and true and false into boolean when both are there. A union of only
// string literals, such as BufferEncoding, stays one type.
function parts(t) {
  if (!t.isUnion()) return [t];
  const members = t.types.filter(x => !(x.flags & ts.TypeFlags.Undefined));
  if (members.every(x => x.flags & ts.TypeFlags.StringLiteral)) return [checker.getNonNullableType(t)];
  const booleans = members.filter(x => x.flags & ts.TypeFlags.BooleanLiteral);
  const out = [];
  for (const x of members) {
    const fold = x.flags & ts.TypeFlags.EnumLiteral || (x.flags & ts.TypeFlags.BooleanLiteral && booleans.length === 2);
    const y = fold ? checker.getBaseTypeOfLiteralType(x) : x;
    if (!out.includes(y)) out.push(y);
  }
  return out;
}

function param(name, t, optional, depth) {
  const out = { name, type: text(checker.getNonNullableType(t)), optional, union: parts(t).map(text) };
  const objects = depth === 0 ? parts(t).filter(isObject) : [];
  if (objects.length) {
    out.props = objects.map(o => ({ type: text(o), props: checker.getPropertiesOfType(o).map(p =>
      param(p.name, checker.getTypeOfSymbol(p), !!(p.flags & ts.SymbolFlags.Optional), depth + 1)) }));
  }
  return out;
}

// One signature's parameters. A rest parameter typed as a tuple, as the
// functions that buildClient returns have, gives one parameter per element.
function params(sig) {
  return sig.getParameters().flatMap(p => {
    const decl = p.valueDeclaration;
    const t = checker.getTypeOfSymbol(p);
    if (decl?.dotDotDotToken && checker.isTupleType(t)) {
      const target = t.target;
      return checker.getTypeArguments(t).map((e, i) => param(target.labeledElementDeclarations?.[i]?.name.getText() || `arg${i}`,
        e, !!(target.elementFlags[i] & ts.ElementFlags.Optional), 0));
    }
    return [param(p.name, t, !!(decl?.questionToken || decl?.initializer), 0)];
  });
}

const signatures = type => type.getCallSignatures().concat(type.getConstructSignatures())
  .map(sig => ({ params: params(sig), returns: text(sig.getReturnType()) }));

const out = {};
for (const name of names) {
  const [fn, method] = name.split("().");
  const sym = exported(fn);
  const at = sym.valueDeclaration || sym.declarations[0];
  let type = checker.getTypeOfSymbolAtLocation(sym, at);
  if (method) {
    const returned = type.getCallSignatures()[0].getReturnType();
    type = checker.getTypeOfSymbolAtLocation(returned.getProperty(method), at);
  }
  out[name] = signatures(type);
}
console.log(JSON.stringify(out));
