package preflight

import (
	"path/filepath"
	"slices"
	"strings"

	"github.com/hashicorp/hcl/v2"
	"github.com/zclconf/go-cty/cty"
)

// kubeForms reads the kubernetes and helm providers' other ways to name a
// cluster: the helm provider's nested kubernetes block or attribute object,
// config_path and config_paths (a kubeconfig whose current context applies),
// and host (an API server the config's environments do not name).
func (t *Targets) kubeForms(sets [][]*hcl.File) {
	sources := []string{"hashicorp/kubernetes", "hashicorp/helm", "gavinbunney/kubectl", "alekc/kubectl"}
	for si, set := range sets {
		names := map[string]bool{}
		for _, src := range sources {
			names[filepath.Base(src)] = true
		}
		for _, f := range set {
			for _, src := range sources {
				for n := range localNames(f.Body, src) {
					names[n] = true
				}
			}
		}
		for _, f := range set {
			top, _, _ := f.Body.PartialContent(providerSchema)
			for _, pb := range top.Blocks {
				if !names[pb.Labels[0]] {
					continue
				}
				for _, attrs := range kubeBodies(pb.Body) {
					for k, e := range attrs {
						switch k {
						case "config_context":
							if v, lit := literal(e); lit {
								if !slices.Contains(t.KubeContexts, v) {
									t.KubeContexts = append(t.KubeContexts, v)
								}
							} else if t.Unknown == "" {
								t.Unknown = "the kubernetes provider's config_context is computed"
							}
						case "config_path", "config_paths":
							if v, lit := literal(e); lit && v != "" {
								t.KubeConfigs = append(t.KubeConfigs, v)
							} else if lst, ok := literalList(e); ok {
								t.KubeConfigs = append(t.KubeConfigs, lst...)
							} else if t.Unknown == "" {
								t.Unknown = "the kubernetes provider's " + k + " is computed, so the cluster it selects is not known"
								if si > 0 {
									t.Unknown += " (in a module)"
								}
							}
						case "host":
							if v, lit := literal(e); !lit {
								if t.Unknown == "" {
									t.Unknown = "the kubernetes provider's host is computed, so the cluster it names is not known"
								}
							} else if v != "" && !strings.Contains(v, "localhost") && !strings.Contains(v, "127.0.0.1") && t.Unknown == "" {
								t.Unknown = "the kubernetes provider's host names an API server (" + v + "), which no environment in the config can be matched to"
							}
						}
					}
				}
			}
		}
	}
}

// kubeBodies are the attribute sets of a kubernetes-style provider block:
// its own, those of a nested kubernetes block, and the object a kubernetes
// attribute holds (the helm provider takes both forms).
func kubeBodies(body hcl.Body) []map[string]hcl.Expression {
	var out []map[string]hcl.Expression
	inner, rest, _ := body.PartialContent(&hcl.BodySchema{Blocks: []hcl.BlockHeaderSchema{{Type: "kubernetes"}}})
	own, _ := attributesOf(rest)
	m := map[string]hcl.Expression{}
	for k, a := range own {
		m[k] = a.Expr
		if k == "kubernetes" {
			if v, d := a.Expr.Value(emptyCtx); !d.HasErrors() && v.IsWhollyKnown() && !v.IsNull() && (v.Type().IsObjectType() || v.Type().IsMapType()) {
				obj := map[string]hcl.Expression{}
				for it := v.ElementIterator(); it.Next(); {
					k2, v2 := it.Element()
					obj[k2.AsString()] = hcl.StaticExpr(v2, hcl.Range{})
				}
				out = append(out, obj)
			}
		}
	}
	out = append(out, m)
	for _, nb := range inner.Blocks {
		nattrs, _ := attributesOf(nb.Body)
		nm := map[string]hcl.Expression{}
		for k, a := range nattrs {
			nm[k] = a.Expr
		}
		out = append(out, nm)
	}
	return out
}

// literalList is the strings of a list expression whose elements are literal.
func literalList(e hcl.Expression) ([]string, bool) {
	v, d := e.Value(emptyCtx)
	if d.HasErrors() || !v.IsWhollyKnown() || v.IsNull() || !(v.Type().IsListType() || v.Type().IsTupleType() || v.Type().IsSetType()) {
		return nil, false
	}
	var out []string
	for it := v.ElementIterator(); it.Next(); {
		_, ev := it.Element()
		if ev.Type() != cty.String || ev.IsNull() {
			return nil, false
		}
		out = append(out, ev.AsString())
	}
	return out, true
}
