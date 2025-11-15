package main

import (
	"github.com/dleto614/simba"
	"github.com/dleto614/simba/logs"
)

func main() {
	// fmt.Printf("Hello, world.")

	// Listen 445 Port

	s := &simba.Server{}
	err := s.ListenAndServe("0.0.0.0:445")

	if (logs.ChkServerInit(err)) == false {
		return
	}

}
