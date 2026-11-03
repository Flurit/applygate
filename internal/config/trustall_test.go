package config

// Tests load fixture configs nobody trusted; trust_test.go covers the check.
func init() { TrustAll = true }
