package logs

import (
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

func LogChkMsgInvalid(msg []byte) {

}
