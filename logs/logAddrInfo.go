package logs

import (
	"log"
	"net"
)

func LogNewConnection(rw net.Conn) bool {
	log.Println("[LOGGER] Accept a new connection:", rw.RemoteAddr().String())
	return true
}

func LogRemoteAddr(rwc net.Conn) bool {
	log.Println("[LOGGER] Remote addr:", rwc.RemoteAddr())
	return true
}
