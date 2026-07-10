package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/raphbaph/CompliantAI/internal/version"
)

func main() {
	showVersion := flag.Bool("version", false, "print build metadata as JSON")
	flag.Parse()

	if *showVersion {
		if err := json.NewEncoder(os.Stdout).Encode(version.Current()); err != nil {
			fmt.Fprintln(os.Stderr, "failed to encode build metadata")
			os.Exit(1)
		}
		return
	}

	fmt.Fprintln(os.Stderr, "gateway server is not implemented yet")
	os.Exit(2)
}
