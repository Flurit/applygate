package suggest

import "github.com/Flurit/applygate/internal/config"

// Tests load fixture configs nobody trusted; internal/config covers the check.
func init() { config.TrustAll = true }
