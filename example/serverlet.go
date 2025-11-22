package main

import (
	"flag"

	"github.com/dleto614/simba"
	"github.com/dleto614/simba/logs"
)

func main() {
	// fmt.Printf("Hello, world.")

	// Listen 445 Port
	var server *string
	var port *string

	var output *string

	server = flag.String("s", "0.0.0.0", "Specify ip address to listen on")
	port = flag.String("p", "445", "Specify port to listen on")

	output = flag.String("o", "log.txt", "Specify output file to write hashes to")

	flag.Parse()

	s := &simba.Server{}
	err := s.ListenAndServe(*server+":"+*port, *output)

	if (logs.ChkServerInit(err)) == false {
		return
	}

}
