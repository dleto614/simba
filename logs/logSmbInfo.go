package logs

import (
	"encoding/hex"
	"log"
)

func LogSMB2Negotiate() bool {
	log.Println("[LOGGER] SMB2_NEGOTIATE")
	return true
}

func LogSMB2SessionSetup() bool {
	log.Println("[LOGGER] SMB2_SESSION_SETUP")
	return true
}

func LogUnknownCommand(r uint16) bool {
	log.Println("[LOGGER] Unknown command: ", r)
	return true
}

func LogReadRequest(buf []byte, n int) bool {
	log.Println("[LOGGER] Read request: ", hex.EncodeToString(buf[:n]), n)
	return true
}

func LogSMBMessageLength(msg []byte) bool {

	log.Println("[LOGGER] msg: len: ", len(msg), msg)

	return true

}

func LogChkMsgInvalid(msg []byte) {

}
