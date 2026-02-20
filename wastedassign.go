package wastedassign

import (
	"fmt"
	"go/ast"
	"go/token"
	"go/types"

	"golang.org/x/tools/go/analysis"
	"golang.org/x/tools/go/analysis/passes/inspect"
	"golang.org/x/tools/go/ast/inspector"
	"golang.org/x/tools/go/ssa"
)

const doc = "wastedassign finds wasted assignment statements."

// Analyzer is the wastedassign analyzer.
var Analyzer = &analysis.Analyzer{
	Name: "wastedassign",
	Doc:  doc,
	Run:  run,
	Requires: []*analysis.Analyzer{
		inspect.Analyzer,
	},
}

type wastedAssignStruct struct {
	pos    token.Pos
	reason string
}

func run(pass *analysis.Pass) (interface{}, error) {
	prog := ssa.NewProgram(pass.Fset, ssa.NaiveForm)

	// Create SSA packages for direct imports.
	for _, p := range pass.Pkg.Imports() {
		prog.CreatePackage(p, nil, nil, true)
	}

	// Create and build the primary package.
	ssapkg := prog.CreatePackage(pass.Pkg, pass.Files, pass.TypesInfo, false)
	ssapkg.Build()

	// Collect source functions in source order, including anonymous functions.
	var srcFuncs []*ssa.Function
	for _, f := range pass.Files {
		for _, decl := range f.Decls {
			fdecl, ok := decl.(*ast.FuncDecl)
			if !ok {
				continue
			}
			// SSA does not build a Function for a FuncDecl named blank.
			if fdecl.Name.Name == "_" {
				continue
			}
			fn, ok := pass.TypesInfo.Defs[fdecl.Name].(*types.Func)
			if !ok || fn == nil {
				continue
			}
			f := ssapkg.Prog.FuncValue(fn)
			if f == nil {
				continue
			}
			var addAnons func(*ssa.Function)
			addAnons = func(f *ssa.Function) {
				srcFuncs = append(srcFuncs, f)
				for _, anon := range f.AnonFuncs {
					addAnons(anon)
				}
			}
			addAnons(f)
		}
	}

	typeSwitchPos := map[int]bool{}
	inspect := pass.ResultOf[inspect.Analyzer].(*inspector.Inspector)
	inspect.Preorder([]ast.Node{new(ast.TypeSwitchStmt)}, func(n ast.Node) {
		if _, ok := n.(*ast.TypeSwitchStmt); ok {
			typeSwitchPos[pass.Fset.Position(n.Pos()).Line] = true
		}
	})

	var wastedAssignMap []wastedAssignStruct

	for _, sf := range srcFuncs {
		// Build a set of locals for O(1) lookup instead of scanning the slice
		// for every store operand.
		localSet := make(map[*ssa.Alloc]bool, len(sf.Locals))
		for _, l := range sf.Locals {
			localSet[l] = true
		}

		for _, bl := range sf.Blocks {
			for i, ist := range bl.Instrs {
				if _, ok := ist.(*ssa.Store); !ok {
					continue
				}

				var buf [10]*ssa.Value
				for _, op := range ist.Operands(buf[:0]) {
					alloc, ok := (*op).(*ssa.Alloc)
					if !ok || !localSet[alloc] {
						continue
					}

					// Pass only the instructions after this store so that
					// isNextOperationToOpIsStore doesn't re-examine it.
					// Use a slice expression (O(1)) rather than rebuilding
					// the instruction list (O(n)) for every instruction.
					blCopy := *bl
					blCopy.Instrs = bl.Instrs[i+1:]
					reason := isNextOperationToOpIsStore([]*ssa.BasicBlock{&blCopy}, op, nil)
					if reason == notWasted {
						continue
					}

					if ist.Pos() == 0 || typeSwitchPos[pass.Fset.Position(ist.Pos()).Line] {
						continue
					}

					wastedAssignMap = append(wastedAssignMap, wastedAssignStruct{
						pos:    ist.Pos(),
						reason: reason.String(alloc),
					})
				}
			}
		}
	}

	for _, was := range wastedAssignMap {
		pass.Reportf(was.pos, "%s", was.reason)
	}

	return nil, nil
}

type wastedReason string

const (
	noUseUntilReturn wastedReason = "assigned, but never used afterwards"
	reassignedSoon   wastedReason = "wasted assignment"
	notWasted        wastedReason = ""
)

func (wr wastedReason) String(a *ssa.Alloc) string {
	switch wr {
	case noUseUntilReturn:
		return fmt.Sprintf("assigned to %s, but never used afterwards", a.Comment)
	case reassignedSoon:
		return fmt.Sprintf("assigned to %s, but reassigned without using the value", a.Comment)
	case notWasted:
		return ""
	default:
		return ""
	}
}

func isNextOperationToOpIsStore(bls []*ssa.BasicBlock, currentOp *ssa.Value, haveCheckedMap map[int]int) wastedReason {
	var wastedReasons []wastedReason
	var wastedReasonsCurrentBls []wastedReason

	if haveCheckedMap == nil {
		haveCheckedMap = map[int]int{}
	}

	for _, bl := range bls {
		if haveCheckedMap[bl.Index] == 2 {
			continue
		}

		haveCheckedMap[bl.Index]++
		breakFlag := false
		for _, ist := range bl.Instrs {
			if breakFlag {
				break
			}

			switch w := ist.(type) {
			case *ssa.Store:
				var buf [10]*ssa.Value
				for _, op := range ist.Operands(buf[:0]) {
					if *op == *currentOp {
						if w.Addr.Name() == (*currentOp).Name() {
							wastedReasonsCurrentBls = append(wastedReasonsCurrentBls, reassignedSoon)
							breakFlag = true
							break
						} else {
							return notWasted
						}
					}
				}
			default:
				var buf [10]*ssa.Value
				for _, op := range ist.Operands(buf[:0]) {
					if *op == *currentOp {
						// It wasn't a continuous store.
						return notWasted
					}
				}
			}
		}

		if len(bl.Succs) != 0 && !breakFlag {
			wastedReason := isNextOperationToOpIsStore(rmSameBlock(bl.Succs, bl), currentOp, haveCheckedMap)
			if wastedReason == notWasted {
				return notWasted
			}
			wastedReasons = append(wastedReasons, wastedReason)
		}
	}

	wastedReasons = append(wastedReasons, wastedReasonsCurrentBls...)

	if len(wastedReasons) != 0 && containReassignedSoon(wastedReasons) {
		return reassignedSoon
	}

	return noUseUntilReturn
}

func rmSameBlock(bls []*ssa.BasicBlock, currentBl *ssa.BasicBlock) []*ssa.BasicBlock {
	var rto []*ssa.BasicBlock
	for _, bl := range bls {
		if bl != currentBl {
			rto = append(rto, bl)
		}
	}
	return rto
}

func containReassignedSoon(ws []wastedReason) bool {
	for _, w := range ws {
		if w == reassignedSoon {
			return true
		}
	}
	return false
}


