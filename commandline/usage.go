package commandline

import (
	"flag"
	"fmt"
	"os"
)

// PrintHelp prints a formatted help message to the console.
func PrintHelp() {

	// Print a help message.
	// Can prettify later.
	fmt.Fprintf(os.Stderr, "Usage: %s [options]\n\n", os.Args[0])
	fmt.Fprintf(os.Stderr, "Options:\n")

	// Prints all the flags and their defaults.
	flag.PrintDefaults()
}
