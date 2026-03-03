package main

import (
	"fmt"
	"os"

	"github.com/hxuu/ataree/internal/cli"
<<<<<<< HEAD
	"github.com/cilium/ebpf/link" // <--- Add this
    "github.com/hxuu/ataree/internal/ebpf"

=======
>>>>>>> ed35978 (read from ring buffer)
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
