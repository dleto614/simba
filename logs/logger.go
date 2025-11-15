package logs

import (
	"fmt"
	"log"
	"os"
)

func ChkFlags([]string) bool {
	if len(os.Args) < 2 {
		fmt.Println("Usage: go run ntlm_parser.go <log_file>")
		return false
	}

	return true // Successfully inputted correct

}

func ChkReadFile(err error) bool {
	if err != nil {
		log.Println("Error reading file: ", err)
		return false
	}

	return true // Successfully read file.
}

func ChkServerInit(err error) bool {
	if err != nil {
		log.Println("Error starting server: ", err)
		return false
	}

	return true
}

func ChkReadRequest(err error) bool {
	if err != nil {
		// fmt.Printf("readRequest error: %v\n", err)
		log.Println("Read request error: ", err)
		return false
	}

	return true
}
