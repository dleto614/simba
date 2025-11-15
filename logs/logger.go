package logs

import (
	"encoding/hex"
	"fmt"
	"log"
	"net"
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
	log.Println("mechToken: ", hex.EncodeToString(mechToken))
	log.Println("mechToken not encoded: ", mechToken)

	return true
}

func LogNTLMNegotiate(ntlmsspPayload []byte) bool {
	log.Println("NTLM_NEGOTIATE: ", len(ntlmsspPayload))

	return true
}

func LogNTLMAuth(ntlmsspPayload []byte) bool {
	log.Println("NTLMSSP_AUTH: ", len(ntlmsspPayload))

	return true
}

func LogNTLMUnknown(ntlmsspPayloadMsgType uint32) bool {
	log.Println("NTLMSSP unknown message type: ", ntlmsspPayloadMsgType)

	return true
}
