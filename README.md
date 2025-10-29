# Simba:

## Introduction

Originally forked from the original library here: https://github.com/PichuChen/simba

go.mod is a little bitch when it comes to handling forked Go libraries so decided to just create a seperate repo.

Was the only library that I could find that was simple, but can use some work so will be adding my own features.

For now, goal is to try to use this library for my smb-honeypot that is on my todo for Ussuri honeypot project, but probably will end up making this more of a Go variant of Impacket SMB Server.

## Example code: 

(This is based on the original guy's example code and I will update this later)

```go
package main

import (
	"fmt"
	"log"

	"github.com/PichuChen/simba"
)

func main() {
	fmt.Println("Starting simple SMB2 server...")

	// Create a new SMB server
	server := &simba.Server{
		Addr: "0.0.0.0:445",
	}

	// Start the server on default port
	fmt.Println("Server starting on:", server.Addr)

	err := server.ListenAndServe(server.Addr)
	if err != nil {
		log.Fatalf("Server error: %v", err)
	}
}
```

## Future Plans:

- The library only implants smb2 and for now that is what I will be using mostly till I get this in a way that I want it to be and later I plan on adding smb3.
- Might expand and add a way to serve files via a filesystem.
- I want to clean up the output just a bit since currently all I could see is that you specify the addr and port via the `Server` structure and probably will add addr and port as seperate options in the structure.
- Clean up `ListenAndServe()`, can add both addr and port in the struct so it makes sense to use the struct instead of only specifying address and having to specify the port in the function.
- Currently the default behavior is too verbose and most of the output is not very friendly for saving and parsing in a log or handling the data seperatly. So probably will add a seperate logging or improve upon the logging provided.
- World domination???  
