// Command optictrace is the OpticTrace agent and toolbox.
//
// The implementation lives in the cli package so that a binary which adds
// licensed features can run exactly this code rather than a copy of it.
package main

import (
	"os"

	"github.com/dwarka-prasad/optictrace/cli"
)

// version is stamped at release time via -ldflags -X main.version=...
var version = "0.9.0-dev"

func main() { cli.Run(os.Args[1:], version) }
