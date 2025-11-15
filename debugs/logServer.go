package debug

import "fmt"

func LogReadRequest(r []byte) bool {
	fmt.Println("readRequest: %v\n", r)

	return true
}
