package main

import (
	"os"

	"github.com/spf13/cobra"
)

const version = "0.2.0"

func newRootCmd() *cobra.Command {
	root := &cobra.Command{
		Use:     "gshark",
		Short:   "3GPP subscriber tracker built on tshark",
		Version: version,
	}
	root.AddCommand(newUsertrackCmd())
	return root
}

func main() {
	if err := newRootCmd().Execute(); err != nil {
		os.Exit(1)
	}
}
