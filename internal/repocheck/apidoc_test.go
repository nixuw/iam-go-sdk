package repocheck

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"strings"
	"testing"
)

// TestExportedAPIIsDocumented is API-06: every exported identifier of the
// public packages has a doc comment.
func TestExportedAPIIsDocumented(t *testing.T) {
	for _, pkg := range []string{".", "iamhttp", "iamfiber", "iamgrpc", "iamtest"} {
		dir := filepath.Join(root(t), pkg)
		fset := token.NewFileSet()
		pkgs, err := parser.ParseDir(fset, dir, func(info fs.FileInfo) bool { return !strings.HasSuffix(info.Name(), "_test.go") }, parser.ParseComments)
		if err != nil {
			t.Fatal(err)
		}
		for _, p := range pkgs {
			hasPackageDoc := false
			for name, file := range p.Files {
				if file.Doc != nil {
					hasPackageDoc = true
				}
				for _, decl := range file.Decls {
					for _, missing := range undocumented(fset, decl) {
						t.Errorf("%s: exported %s has no doc comment", filepath.Join(pkg, filepath.Base(name)), missing)
					}
				}
			}
			if !hasPackageDoc {
				t.Errorf("package %s has no package comment", p.Name)
			}
		}
	}
}

// undocumented lists the exported identifiers of a declaration that lack a
// doc comment. Methods of unexported types are skipped, as are the members
// of a documented const or var group.
func undocumented(fset *token.FileSet, decl ast.Decl) []string {
	var out []string
	switch d := decl.(type) {
	case *ast.FuncDecl:
		if !d.Name.IsExported() || d.Doc != nil {
			return nil
		}
		if d.Recv != nil && len(d.Recv.List) == 1 {
			recv := d.Recv.List[0].Type
			if star, ok := recv.(*ast.StarExpr); ok {
				recv = star.X
			}
			if id, ok := recv.(*ast.Ident); ok && !id.IsExported() {
				return nil
			}
		}
		out = append(out, "func "+d.Name.Name)
	case *ast.GenDecl:
		for _, spec := range d.Specs {
			switch s := spec.(type) {
			case *ast.TypeSpec:
				if s.Name.IsExported() && d.Doc == nil && s.Doc == nil {
					out = append(out, "type "+s.Name.Name)
				}
				if st, ok := s.Type.(*ast.StructType); ok && s.Name.IsExported() {
					for _, f := range st.Fields.List {
						for _, n := range f.Names {
							if n.IsExported() && f.Doc == nil && f.Comment == nil && !documentedByGroup(fset, st, f) {
								out = append(out, "field "+s.Name.Name+"."+n.Name)
							}
						}
					}
				}
			case *ast.ValueSpec:
				for _, n := range s.Names {
					if n.IsExported() && d.Doc == nil && s.Doc == nil && s.Comment == nil {
						out = append(out, "value "+n.Name)
					}
				}
			}
		}
	}
	return out
}

// documentedByGroup reports whether a struct field belongs to a run of
// fields on consecutive lines that starts with a documented field: one
// comment then covers the run (e.g. "IssuedAt and ExpiresAt delimit …").
func documentedByGroup(fset *token.FileSet, st *ast.StructType, field *ast.Field) bool {
	line := fset.Position(field.Pos()).Line
	for i := len(st.Fields.List) - 1; i >= 0; i-- {
		f := st.Fields.List[i]
		if f.Pos() >= field.Pos() {
			continue
		}
		if fset.Position(f.End()).Line != line-1 {
			return false // a blank line or a comment ends the run
		}
		if f.Doc != nil {
			return true
		}
		line = fset.Position(f.Pos()).Line
	}
	return false
}
