package simba

import (
	"encoding/binary"
	"net"
)

type Server struct {
	Addr string
}

var (
	le = binary.LittleEndian
)

func (srv *Server) ListenAndServe(server string, output string) error {
	// addr := srv.Addr
	ln, err := net.Listen("tcp", server)
	if err != nil {
		return err
	}
	return srv.Serve(ln, output)
}
