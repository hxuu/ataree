package main

import (
	"fmt"
	"os"

	"github.com/hxuu/ataree/internal/cli"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		os.Exit(1)
	}
}

func run() error {
	return cli.Run()
}
