package main

import (
	// Make sure to import your new commandline package
	"github.com/dleto614/simba"
	"github.com/dleto614/simba/commandline"
	"github.com/dleto614/simba/logs"
)

func main() {
	// 1. Call the Parse function from your commandline package
	//    to get the configuration.
	config := commandline.Parse()

	// 2. Use the fields from the config struct to build the address.
	address := config.Server + ":" + config.Port

	// 3. Pass the address and output file to your server.
	s := &simba.Server{}
	err := s.ListenAndServe(address, config.Output)

	// 4. Check for errors as before.
	if logs.ChkServerInit(err) == false {
		return
	}
}
