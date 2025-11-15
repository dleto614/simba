package logs

import (
	"encoding/hex"
	"log"

	"github.com/dleto614/simba"
)

func LogSMB2Negotiate() bool {
	log.Println("SMB2_NEGOTIATE")
	return true
}

func LogSMB2SessionSetup() bool {
	log.Println("SMB2_SESSION_SETUP")
	return true
}

func LogUnknownCommand() bool {
	log.Println("Unknown command: ", r.Command())
	return true
}

func LogReadRequest(buf []byte, n int) bool {
	log.Println("Read request: ", hex.EncodeToString(buf[:n]), n)
	return true
}

func LogSMBMessageLength(msg PacketCodec) bool {

	log.Println("msg: len: ", len(msg), msg)

	return true

}

func LogChkMsgInvalid(msg []byte) {

}
