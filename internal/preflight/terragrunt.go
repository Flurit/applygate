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
	// Unknown says why the backend cannot be told: a remote_state value
	// built with locals or functions, or a generate "backend" block.
	Unknown string
	// Generated are the configuration files generate blocks write, parsed:
	// a provider block there is a target like one in a .tf file.
	Generated []*hcl.File
}

var (
	tgSchema       = &hcl.BodySchema{Blocks: []hcl.BlockHeaderSchema{{Type: "remote_state"}, {Type: "terraform"}, {Type: "generate", LabelNames: []string{"name"}}}}
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
		case "generate":
			if len(b.Labels) > 0 && strings.Contains(strings.ToLower(b.Labels[0]), "backend") {
				tg.Unknown = "generate \"" + b.Labels[0] + "\" writes the backend configuration, which is not read"
			} else if a, ok := attrs["path"]; ok && strings.Contains(strings.ToLower(literalParts(a.Expr)), "backend") {
				tg.Unknown = "a generate block writes a backend file, which is not read"
			}
			// Whatever the block is called, what it writes is configuration
			// Terraform reads: its provider blocks are targets and a backend
			// block in it is the backend. Contents built with Terragrunt
			// functions cannot be read.
			label := ""
			if len(b.Labels) > 0 {
				label = b.Labels[0]
			}
			if a, ok := attrs["contents"]; ok {
				if text, lit := scalar(a.Expr); lit {
					f, d := hclsyntax.ParseConfig([]byte(text), "generate "+label, hcl.Pos{Line: 1, Column: 1})
					switch {
					case d.HasErrors() || f == nil:
						if pa, ok := attrs["path"]; !ok || strings.Contains(strings.ToLower(literalParts(pa.Expr)), ".tf") {
							if tg.Unknown == "" {
								tg.Unknown = "generate \"" + label + "\" writes configuration that does not parse"
							}
						}
					default:
						tg.Generated = append(tg.Generated, f)
						if why := runsTerraformBackend(f); why && tg.Unknown == "" {
							tg.Unknown = "generate \"" + label + "\" writes a backend block, which is not read"
						}
					}
				} else if t := strings.ToLower(literalParts(a.Expr)); strings.Contains(t, "provider") || strings.Contains(t, "backend") || strings.Contains(t, "terraform") {
					if tg.Unknown == "" {
						tg.Unknown = "generate \"" + label + "\" writes configuration built with Terragrunt functions, which is not read"
					}
				}
			}
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
							if _, ok := scalar(it.ValueExpr); !ok && tg.Unknown == "" {
								tg.Unknown = "remote_state " + k + " is built from locals or functions, so the state it names is not known"
							}
						}
					}
				} else if v, d := a.Expr.Value(emptyCtx); !d.HasErrors() && v.IsWhollyKnown() && v.CanIterateElements() {
					for k, x := range v.AsValueMap() {
						if t, ok := scalarText(x); ok {
							tg.Backend[k] = t
						}
					}
				} else if tg.Unknown == "" {
					tg.Unknown = "remote_state config is built from locals or functions, so the state it names is not known"
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

// runsTerraformBackend reports whether f declares a backend.
func runsTerraformBackend(f *hcl.File) bool {
	top, _, _ := f.Body.PartialContent(&hcl.BodySchema{Blocks: []hcl.BlockHeaderSchema{{Type: "terraform"}}})
	for _, b := range top.Blocks {
		inner, _, _ := b.Body.PartialContent(&hcl.BodySchema{Blocks: []hcl.BlockHeaderSchema{{Type: "backend", LabelNames: []string{"type"}}}})
		if len(inner.Blocks) > 0 {
			return true
		}
	}
	return false
}
