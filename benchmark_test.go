package wastedassign_test

import (
	"testing"

	wastedassign "github.com/sanposhiho/wastedassign/v2"
	"golang.org/x/tools/go/analysis"
	"golang.org/x/tools/go/analysis/passes/inspect"
	"golang.org/x/tools/go/packages"
)

// BenchmarkAnalyzerHTTP runs the analyzer against net/http, which is large
// enough to make algorithmic costs visible.
func BenchmarkAnalyzerHTTP(b *testing.B) {
	pkgs, err := packages.Load(&packages.Config{
		Mode: packages.NeedName |
			packages.NeedImports |
			packages.NeedDeps |
			packages.NeedTypes |
			packages.NeedTypesSizes |
			packages.NeedSyntax |
			packages.NeedTypesInfo,
	}, "net/http")
	if err != nil {
		b.Fatal(err)
	}
	if packages.PrintErrors(pkgs) > 0 {
		b.Fatal("errors loading net/http")
	}
	pkg := pkgs[0]

	// Run the inspect sub-analyzer once; its result is safe to reuse across
	// iterations because it is read-only.
	inspPass := &analysis.Pass{
		Analyzer:  inspect.Analyzer,
		Fset:      pkg.Fset,
		Files:     pkg.Syntax,
		Pkg:       pkg.Types,
		TypesInfo: pkg.TypesInfo,
		ResultOf:  map[*analysis.Analyzer]any{},
		Report:    func(analysis.Diagnostic) {},
	}
	inspResult, err := inspect.Analyzer.Run(inspPass)
	if err != nil {
		b.Fatal(err)
	}

	for b.Loop() {
		pass := &analysis.Pass{
			Analyzer:   wastedassign.Analyzer,
			Fset:       pkg.Fset,
			Files:      pkg.Syntax,
			Pkg:        pkg.Types,
			TypesInfo:  pkg.TypesInfo,
			TypesSizes: pkg.TypesSizes,
			ResultOf: map[*analysis.Analyzer]any{
				inspect.Analyzer: inspResult,
			},
			Report: func(analysis.Diagnostic) {},
		}
		if _, err := wastedassign.Analyzer.Run(pass); err != nil {
			b.Fatal(err)
		}
	}
}
