// Command aws-netpath models a network and answers reachability questions offline.
package main

import (
	"os"

	"github.com/jajera/aws-netpath/internal/cli"
)

func main() {
	os.Exit(cli.Run(os.Args[1:], os.Stdout, os.Stderr))
}
