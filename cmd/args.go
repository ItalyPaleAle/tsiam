package main

import (
	"errors"
	"flag"
	"fmt"
	"io"

	"github.com/italypaleale/tsiam/pkg/buildinfo"
)

// Parses command-line flags (--help and --version) before loading configuration
func handleArgs(args []string, stdout io.Writer, stderr io.Writer) (exit bool, code int) {
	fs := flag.NewFlagSet(buildinfo.AppName, flag.ContinueOnError)
	fs.SetOutput(stderr)
	version := fs.Bool("version", false, "Print the version and exit")
	fs.Usage = func() {
		_, _ = fmt.Fprintf(stderr, "Usage: %s [--version]\n\n", buildinfo.AppName)
		_, _ = fmt.Fprintln(stderr, "tsiam reads its configuration from the file in the TSIAM_CONFIG environment variable, or from config.yaml in the current directory, ~/.tsiam, or /etc/tsiam.")
		_, _ = fmt.Fprintln(stderr, "\nFlags:")
		fs.PrintDefaults()
	}

	err := fs.Parse(args)
	switch {
	case errors.Is(err, flag.ErrHelp):
		return true, 0
	case err != nil:
		return true, 2
	case fs.NArg() > 0:
		_, _ = fmt.Fprintf(stderr, "Unexpected argument: %s\n", fs.Arg(0))
		fs.Usage()
		return true, 2
	case *version:
		_, _ = fmt.Fprintf(stdout, "%s %s\nBuild: %s\n", buildinfo.AppName, buildinfo.AppVersion, buildinfo.BuildDescription)
		return true, 0
	default:
		return false, 0
	}
}
