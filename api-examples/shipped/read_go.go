// Prints the exported structs and functions of the Go packages under a
// module directory as JSON: each struct's fields, and each function's or
// method's parameters. read_shipped.py runs it on a released module's source.
//
//	go run read_go.go <module dir>
package main

import (
	"bytes"
	"encoding/json"
	"go/ast"
	"go/parser"
	"go/printer"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

type field struct {
	Name string `json:"name"`
	Type string `json:"type"`
}

type function struct {
	Name     string  `json:"name"`
	Package  string  `json:"package"`
	Receiver string  `json:"receiver"`
	Params   []field `json:"params"`
}

func main() {
	fset := token.NewFileSet()
	text := func(n ast.Node) string {
		var b bytes.Buffer
		printer.Fprint(&b, fset, n)
		return b.String()
	}
	fields := func(list *ast.FieldList, exportedOnly bool) []field {
		out := []field{}
		for _, f := range list.List {
			for _, n := range f.Names {
				if n.IsExported() || !exportedOnly {
					out = append(out, field{n.Name, text(f.Type)})
				}
			}
		}
		return out
	}
	structs := map[string][]field{}
	functions := []function{}
	root := os.Args[1]
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return err
		}
		file, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil {
			return err
		}
		for _, decl := range file.Decls {
			switch decl := decl.(type) {
			case *ast.GenDecl:
				for _, spec := range decl.Specs {
					t, ok := spec.(*ast.TypeSpec)
					if !ok || !t.Name.IsExported() {
						continue
					}
					if s, ok := t.Type.(*ast.StructType); ok {
						structs[file.Name.Name+"."+t.Name.Name] = fields(s.Fields, true)
					}
				}
			case *ast.FuncDecl:
				if !decl.Name.IsExported() {
					continue
				}
				receiver := ""
				if decl.Recv != nil {
					receiver = file.Name.Name + "." + strings.TrimPrefix(text(decl.Recv.List[0].Type), "*")
				}
				functions = append(functions, function{decl.Name.Name, file.Name.Name, receiver, fields(decl.Type.Params, false)})
			}
		}
		return nil
	})
	if err != nil {
		panic(err)
	}
	json.NewEncoder(os.Stdout).Encode(map[string]any{"structs": structs, "functions": functions})
}
