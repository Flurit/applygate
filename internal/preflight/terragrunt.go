package preflight

import (
	"path/filepath"
	"strings"

	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclsyntax"
)

// Terragrunt is what a unit's terragrunt.hcl says about where it runs: the
// remote_state values and the terraform.source (4H12).
type Terragrunt struct {
	// Backend are the remote_state config values. A value built with
	// Terragrunt functions keeps its literal parts
	// ("${path_relative_to_include()}/prod.tfstate" gives "/prod.tfstate"),
	// which can only add name hints.
	Backend map[string]string
	// Source is terraform.source, the literal parts likewise.
	Source string
}

var (
	tgSchema       = &hcl.BodySchema{Blocks: []hcl.BlockHeaderSchema{{Type: "remote_state"}, {Type: "terraform"}}}
	tgConfigSchema = &hcl.BodySchema{Blocks: []hcl.BlockHeaderSchema{{Type: "config"}}}
)

// ReadTerragrunt reads dir's terragrunt.hcl (or terragrunt.hcl.json).
// Included files are not followed.
func ReadTerragrunt(dir string) *Terragrunt {
	var file *hcl.File
	for _, n := range []string{"terragrunt.hcl", "terragrunt.hcl.json"} {
		if file = parseFile(filepath.Join(dir, n)); file != nil {
			break
		}
	}
	if file == nil {
		return nil
	}
	tg := &Terragrunt{Backend: map[string]string{}}
	top, _, _ := file.Body.PartialContent(tgSchema)
	for _, b := range top.Blocks {
		inner, rest, _ := b.Body.PartialContent(tgConfigSchema)
		attrs, _ := attributesOf(rest)
		switch b.Type {
		case "terraform":
			if a, ok := attrs["source"]; ok {
				tg.Source = literalParts(a.Expr)
			}
		case "remote_state":
			if a, ok := attrs["config"]; ok {
				if obj, ok := a.Expr.(*hclsyntax.ObjectConsExpr); ok {
					for _, it := range obj.Items {
						k := hcl.ExprAsKeyword(it.KeyExpr)
						if k == "" {
							k, _ = literal(it.KeyExpr)
						}
						if k != "" {
							tg.Backend[k] = literalParts(it.ValueExpr)
						}
					}
				} else if v, d := a.Expr.Value(emptyCtx); !d.HasErrors() && v.IsWhollyKnown() && v.CanIterateElements() {
					for k, x := range v.AsValueMap() {
						if t, ok := scalarText(x); ok {
							tg.Backend[k] = t
						}
					}
				}
			}
			for _, cb := range inner.Blocks {
				ca, _ := attributesOf(cb.Body)
				for k, a := range ca {
					tg.Backend[k] = literalParts(a.Expr)
				}
			}
		}
	}
	return tg
}

// literalParts is e's value when it is a literal, else the literal text in
// it, joined.
func literalParts(e hcl.Expression) string {
	if v, ok := scalar(e); ok {
		return v
	}
	var b strings.Builder
	hclsyntax.VisitAll(asSyntax(e), func(n hclsyntax.Node) hcl.Diagnostics {
		if l, ok := n.(*hclsyntax.LiteralValueExpr); ok {
			if t, ok := scalarText(l.Val); ok {
				b.WriteString(t)
			}
		}
		return nil
	})
	return b.String()
}

func asSyntax(e hcl.Expression) hclsyntax.Node {
	if n, ok := e.(hclsyntax.Expression); ok {
		return n
	}
	return &hclsyntax.LiteralValueExpr{}
}
