package debug

import (
	"encoding/hex"
	"log"
)

func LogSMBMessageLength(msg []byte) bool {

	log.Println("[DEBUG] msg len: ", len(msg))
	log.Println("[DEBUG] msg: ", msg)

	return true

}

func LogReadRequest(buf []byte, n int) bool {
	log.Println("[DEBUG] Read request: ", hex.EncodeToString(buf[:n]), n)
	return true
}
