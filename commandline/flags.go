package commandline

import (
	"flag"
)

// Config holds all the configuration parsed from the command line.
// This is much cleaner than returning three separate strings.
type Config struct {
	Server string
	Port   string
	Output string
	Help   bool
}

// Parse parses the command-line flags and returns a Config struct.
func Parse() *Config {
	// Define the flags
	server := flag.String("s", "0.0.0.0", "Specify ip address to listen on")
	port := flag.String("p", "445", "Specify port to listen on")
	output := flag.String("o", "output.txt", "Specify output file to write hashes to")

	help := flag.Bool("h", false, "Show help")

	// Parse the flags from os.Args
	flag.Parse()

	// Return a new Config struct populated with the parsed values
	// We use *server to get the actual string value from the flag pointer
	return &Config{
		Server: *server,
		Port:   *port,
		Output: *output,
		Help:   *help,
	}

}
