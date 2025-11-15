package debug

import (
	"log"
)

func LogSMBMessageLength(msg []byte) bool {

	log.Println("[DEBUG] msg len: ", len(msg))
	log.Println("[DEBUG] msg: ", msg)

	return true

}
