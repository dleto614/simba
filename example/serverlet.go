package main

import (
	"github.com/dleto614/simba"
)

func main() {
	// fmt.Printf("Hello, world.")

	// Listen 445 Port

	s := &simba.Server{}
	s.ListenAndServe("0.0.0.0445")

}
