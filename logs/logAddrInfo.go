package logs

import (
	"log"
	"net"
)

func LogNewConnection(rw net.Conn) bool {
	log.Println("Accept a new connection: ", rw.RemoteAddr().String())
	return true
}

func LogRemoteAddr(rwc net.Conn) bool {
	log.Println("Remote addr: ", rwc.RemoteAddr())
	return true
}
