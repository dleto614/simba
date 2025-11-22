package logs

import (
	"encoding/hex"
	"log"
	"net"
)

// Might use this function at some port, but for now this is fine
// func ChkFlags([]string) bool {

// 	return true // Successfully inputted correct

// }

func ChkReadFile(err error) bool {
	if err != nil {
		log.Println("Error reading file:", err)
		return false
	}

	return true // Successfully read file.
}

func ChkServerInit(err error) bool {
	if err != nil {
		log.Println("Error starting server:", err)
		return false
	}

	return true
}

func ChkReadRequest(err error) bool {
	if err != nil {
		// fmt.Printf("readRequest error: %v\n", err)
		log.Println("Read request error:", err)
		return false
	}

	return true
}

func LogNewConnection(rw net.Conn) bool {
	log.Println("Accepted a new connection:", rw.RemoteAddr().String())

	return true
}

func LogRemoteAddr(rwc net.Conn) bool {
	log.Println("Remote addr:", rwc.RemoteAddr())

	return true
}

func LogMechToken(mechToken []byte) bool {
	if len(mechToken) == 0 {
		log.Println("mechToken is empty")
		return false
	} else {

		// This is what we want for the ntlm hash thing.
		log.Println("Token:", hex.EncodeToString(mechToken))
		log.Println("Token not encoded:", mechToken)

		return true
	}
}

func LogNTLMUnknown(ntlmsspPayloadMsgType uint32) bool {
	log.Println("NTLMSSP unknown message type: ", ntlmsspPayloadMsgType)

	return true
}
