//go:build race

package harness

// raceBuild is true when the tests run with the race detector, which slows
// every decision several times over.
const raceBuild = true
