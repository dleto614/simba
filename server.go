package simba

import (
	"encoding/hex"
	"fmt"
	"log"
	"net"
	"time"

	"github.com/dleto614/simba/auth"
	"github.com/dleto614/simba/logs"
)

var serverGUID = []byte{0x6d, 0x62, 0x76, 0x6d, 0x32, 0x32, 0x31, 0x32, 0x30, 0x38, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}

// TODO: change to a session manager
var sessionID = uint64(2023)

// Session represents an authenticated SMB session
type Session struct {
	ID            uint64
	User          string
	Authenticated bool
	CreatedAt     time.Time
}

type conn struct {
	server *Server

	// rwc is the underlying network connection.
	rwc net.Conn

	remoteAddr    string
	authenticated bool
	session       *Session
}

type response struct {
	conn *conn
}

func (srv *Server) Serve(l net.Listener) error {
	for {
		rw, err := l.Accept()
		if err != nil {
			return err
		}
		logs.LogNewConnection(rw)

		c := srv.newConn(rw)
		go c.serve()
	}
}

func (srv *Server) newConn(rw net.Conn) *conn {
	c := &conn{
		server: srv,
		rwc:    rw,
	}

	return c
}

func (c *conn) serve() {
	logs.LogRemoteAddr(c.rwc)
	c.remoteAddr = c.rwc.RemoteAddr().String()

	defer func() {
		if err := c.rwc.Close(); err != nil {
			log.Printf("Error closing connection: %v", err)
		} else {
			log.Printf("Connection closed gracefully from %s", c.remoteAddr)
		}
	}()

	for {
		r, err := c.readRequest()

		if (logs.ChkReadRequest(err)) == false {
			return
		}

		switch r.Command() {
		case SMB2_NEGOTIATE:
			log.Println("Received SMB2 Negotiate request. Trying to handle the negotiate request.")
			msg := NegotiateRequest(r[64:])
			c.handleNegotiate(r, msg)

		case SMB2_SESSION_SETUP:
			log.Println("Received SMB2 Session Setup request. Trying to handle the session setup request.")
			msg := SessionSetupRequest(r[64:])
			c.handleSessionSetup(r, msg)

		// Add handling for other commands after authentication
		case SMB2_TREE_CONNECT:
			if !c.authenticated {
				log.Println("Tree connect request before authentication")
				c.sendError(r, STATUS_ACCESS_DENIED)
				continue
			}
			log.Println("Received SMB2 Tree Connect request.")
			// Handle tree connect

		case SMB2_CREATE:
			if !c.authenticated {
				log.Println("Create request before authentication")
				c.sendError(r, STATUS_ACCESS_DENIED)
				continue
			}
			log.Println("Received SMB2 Create request.")
			// Handle create

		case SMB2_LOGOFF:
			if !c.authenticated {
				log.Println("Logoff request before authentication")
				c.sendError(r, STATUS_ACCESS_DENIED)
				continue
			}
			log.Println("Received SMB2 Logoff request.")
			c.handleLogoff(r)
			return

		default:
			log.Println("Unknown command received: ", r.Command())
			c.sendError(r, STATUS_INVALID_PARAMETER)
		}
	}
}

func (c *conn) readRequest() (w PacketCodec, err error) {
	var buf [1024]byte
	n, err := c.rwc.Read(buf[:])
	if err != nil {
		return nil, err
	}

	stringProtocolLength := (uint32(buf[1]) << 16) + (uint32(buf[2]) << 8) + uint32(buf[3])

	// TODO: using loop to read all data
	if n < int(stringProtocolLength) {
		n2, err := c.rwc.Read(buf[n:])
		if err != nil {
			return nil, err
		}
		n += n2
	}

	smb2Message := buf[4 : 4+stringProtocolLength]

	msg := PacketCodec(smb2Message)

	return msg, nil
}

func (c *conn) sendError(request PacketCodec, status uint32) {
	response := PacketCodec(make([]byte, 64))
	response.SetProtocolId()
	response.SetStructureSize()
	response.SetCreditCharge(1)
	response.SetCommand(request.Command())
	response.SetStatus(status)
	response.SetCreditRequestResponse(1)
	response.SetFlags(SMB2_FLAGS_SERVER_TO_REDIR)
	response.SetNextCommand(0)
	response.SetMessageId(request.MessageId())
	response.SetTreeId(request.TreeId())
	response.SetSessionId(request.SessionId())
	response.SetSignature([]byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})

	l := len(response)
	netBIOSHeader := []byte{0x00, 0x00, 0x00, 0x00}
	netBIOSHeader[3] = byte(l)
	netBIOSHeader[2] = byte(l >> 8)

	pkt := append(netBIOSHeader, response...)
	c.rwc.Write(pkt)
}

func (c *conn) handleLogoff(request PacketCodec) {
	response := PacketCodec(make([]byte, 4))
	response[0] = 0x04 // StructureSize
	response[1] = 0x00
	response[2] = 0x00
	response[3] = 0x00 // Reserved

	smb2Header := PacketCodec(make([]byte, 64))
	smb2Header.SetProtocolId()
	smb2Header.SetStructureSize()
	smb2Header.SetCreditCharge(1)
	smb2Header.SetCommand(SMB2_LOGOFF)
	smb2Header.SetStatus(STATUS_SUCCESS)
	smb2Header.SetCreditRequestResponse(1)
	smb2Header.SetFlags(SMB2_FLAGS_SERVER_TO_REDIR)
	smb2Header.SetNextCommand(0)
	smb2Header.SetMessageId(request.MessageId())
	smb2Header.SetTreeId(request.TreeId())
	smb2Header.SetSessionId(request.SessionId())
	smb2Header.SetSignature([]byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})

	l := len(smb2Header) + len(response)
	netBIOSHeader := []byte{0x00, 0x00, 0x00, 0x00}
	netBIOSHeader[3] = byte(l)
	netBIOSHeader[2] = byte(l >> 8)

	pkt := append(netBIOSHeader, smb2Header...)
	pkt = append(pkt, response...)

	c.rwc.Write(pkt)

	// Mark as unauthenticated
	c.authenticated = false
	c.session = nil
}

func (c *conn) handleNegotiate(p PacketCodec, msg NegotiateRequest) error {
	securityBufferPayload := auth.DefaultNegoPayload

	negotiateContextPreauth := NegotiateContext(make([]byte, 8+38))
	negotiateContextPreauth.SetContextType(SMB2_PREAUTH_INTEGRITY_CAPABILITIES)
	negotiateContextPreauth.SetDataLength(38)
	negotiateContextPreauth.SetReserved(0)
	negotiateContextPreauth.SetData([]byte{
		0x01, 0x00, // hash algorithm count
		0x20, 0x00, // salt length
		0x01, 0x00, // hash algorithm: SHA-512
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
		0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20})

	negotiateContextEncryption := NegotiateContext(make([]byte, 8+4))
	negotiateContextEncryption.SetContextType(SMB2_ENCRYPTION_CAPABILITIES)
	negotiateContextEncryption.SetDataLength(4)
	negotiateContextEncryption.SetReserved(0)
	negotiateContextEncryption.SetData([]byte{0x01, 0x00, 0x02, 0x00})

	pkt := []byte{}
	responseHdr := NegotiateResponse(make([]byte, 65+len(securityBufferPayload)+len(negotiateContextPreauth)+19))
	responseHdr.SetStructureSize(65)
	responseHdr.SetSecurityMode(SMB2_NEGOTIATE_SIGNING_ENABLED)
	responseHdr.SetDialectRevision(0x311)
	responseHdr.SetNegotiateContextCount(2)
	responseHdr.SetServerGuid(serverGUID)
	responseHdr.SetCapabilities(SMB2_GLOBAL_CAP_DFS | SMB2_GLOBAL_CAP_LEASING | SMB2_GLOBAL_CAP_LARGE_MTU)
	responseHdr.SetMaxTransactSize(8388608) // 8MB
	responseHdr.SetMaxReadSize(8388608)
	responseHdr.SetMaxWriteSize(8388608)
	responseHdr.SetSystemTime(time.Now())
	responseHdr.SetServerStartTime(time.Time{})
	responseHdr.SetSecurityBufferOffset(0x80)
	responseHdr.SetSecurityBufferLength(uint16(len(securityBufferPayload)))
	responseHdr.SetBuffer(securityBufferPayload)

	responseHdr.SetNegotiateContextOffset(0xD0)
	responseHdr.SetNegotiateContexts([]NegotiateContext{negotiateContextPreauth, negotiateContextEncryption})

	smb2Header := PacketCodec(make([]byte, 64, 64))
	smb2Header.SetProtocolId()
	smb2Header.SetStructureSize()
	smb2Header.SetCreditCharge(1)
	smb2Header.SetCommand(SMB2_NEGOTIATE)
	smb2Header.SetStatus(0)
	smb2Header.SetCreditRequestResponse(1)
	smb2Header.SetFlags(SMB2_FLAGS_SERVER_TO_REDIR)
	smb2Header.SetNextCommand(0)
	smb2Header.SetMessageId(p.MessageId())
	smb2Header.SetTreeId(0)
	smb2Header.SetSessionId(p.SessionId())
	smb2Header.SetSignature([]byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})

	l := len(smb2Header) + len(responseHdr)
	netBIOSHeader := []byte{0x00, 0x00, 0x00, 0x00}
	netBIOSHeader[3] = byte(l)
	netBIOSHeader[2] = byte(l >> 8)

	pkt = append(pkt, netBIOSHeader...)
	pkt = append(pkt, smb2Header...)
	pkt = append(pkt, responseHdr...)

	c.rwc.Write(pkt)

	return nil
}

func (c *conn) handleSessionSetup(p PacketCodec, msg SessionSetupRequest) error {
	// get NTLMSSP message
	gssBuffer := msg.Buffer()
	var mechToken []byte
	if gssBuffer[0] == 0x60 {
		gssPayload, err := auth.NewInitPayload(gssBuffer)
		if err != nil {
			return fmt.Errorf("handleSessionSetup NewInitPayload: %v", err)
		}
		mechToken = gssPayload.Token.NegTokenInit.MechToken

	} else if gssBuffer[0] == 0xa1 {
		gssPayload, err := auth.NewTargPayload(gssBuffer)
		if err != nil {
			return fmt.Errorf("handleSessionSetup NewTargPayload: %v", err)
		}
		mechToken = gssPayload.ResponseToken
	}

	if logs.LogMechToken(mechToken) == false {
		// Will fix this later.
		return fmt.Errorf("handleSessionSetup mechToken is empty")
	}

	ntlmsspPayload := auth.NTLMMessage(mechToken)

	if ntlmsspPayload.IsInvalid() {
		return fmt.Errorf("handleSessionSetup NTLMMessage is invalid")
	}

	switch ntlmsspPayload.MessageType() {
	case auth.NTLMSSP_NEGOTIATE:
		return c.handleSessionSetupNtmlsspNetotiate(p, msg, auth.NTLMNegotiateMessage(mechToken))

	case auth.NTLMSSP_AUTH:
		return c.handleSessionSetupNtmlsspAuth(p, msg, auth.NTLMNegotiateMessage(mechToken))

	default:
		logs.LogNTLMUnknown(ntlmsspPayload.MessageType())
	}
	return fmt.Errorf("unknown ntlm message type: %0x\n", ntlmsspPayload.MessageType())
}

func (c *conn) handleSessionSetupNtmlsspNetotiate(p PacketCodec, msg SessionSetupRequest, ntlpPayload auth.NTLMNegotiateMessage) error {
	pkt := []byte{}
	securityBuffer, _ := hex.DecodeString("a181c43081c1a0030a0101a10c060a2b06010401823702020aa281ab0481a84e544c4d5353500002000000140014003800000015828ae2ade8f7c5b20b941000000000000000005c005c004c000000060100000000000f4d00420056004d00320032003100320030003800020014004d00420056004d00320032003100320030003800010014004d00420056004d0032003200310032003000380004000000030014006d00620076006d0032003200310032003000380007000800a421b4497870d90100000000")

	responseHdr := SessionSetupResponse(make([]byte, 8+len(securityBuffer)))
	responseHdr.SetStructureSize()
	responseHdr.SetSecurityBufferOffset(0x48)
	responseHdr.SetSecurityBufferLength(uint16(len(securityBuffer)))
	responseHdr.SetBuffer(securityBuffer)

	smb2Header := PacketCodec(make([]byte, 64, 64))
	smb2Header.SetProtocolId()
	smb2Header.SetStructureSize()
	smb2Header.SetCreditCharge(1)
	smb2Header.SetCommand(SMB2_SESSION_SETUP)
	smb2Header.SetStatus(STATUS_MORE_PROCESSING_REQUIRED)
	smb2Header.SetCreditRequestResponse(1)
	smb2Header.SetFlags(SMB2_FLAGS_SERVER_TO_REDIR)
	smb2Header.SetNextCommand(0)
	smb2Header.SetMessageId(p.MessageId())
	smb2Header.SetTreeId(0)
	smb2Header.SetSessionId(sessionID)
	smb2Header.SetSignature([]byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})

	l := len(smb2Header) + len(responseHdr)
	netBIOSHeader := []byte{0x00, 0x00, 0x00, 0x00}
	netBIOSHeader[3] = byte(l)
	netBIOSHeader[2] = byte(l >> 8)

	pkt = append(pkt, netBIOSHeader...)
	pkt = append(pkt, smb2Header...)
	pkt = append(pkt, responseHdr...)

	c.rwc.Write(pkt)

	return nil
}

func (c *conn) handleSessionSetupNtmlsspAuth(p PacketCodec, msg SessionSetupRequest, ntlmPayload auth.NTLMNegotiateMessage) error {
	// Create a new session
	session := &Session{
		ID:            p.SessionId(), // Use the session ID from the request
		User:          "guest",       // In a real implementation, extract from auth
		Authenticated: true,
		CreatedAt:     time.Now(),
	}

	c.session = session
	c.authenticated = true

	pkt := []byte{}
	responseHdr := SessionSetupResponse(make([]byte, 8))
	responseHdr.SetStructureSize()
	responseHdr.SetSessionFlags(SMB2_SESSION_FLAG_IS_GUEST | SMB2_SESSION_FLAG_IS_NULL)
	responseHdr.SetSecurityBufferOffset(0)
	responseHdr.SetSecurityBufferLength(0)

	smb2Header := PacketCodec(make([]byte, 64))
	smb2Header.SetProtocolId()
	smb2Header.SetStructureSize()
	smb2Header.SetCreditCharge(1)
	smb2Header.SetCommand(SMB2_SESSION_SETUP)
	smb2Header.SetStatus(STATUS_SUCCESS) // Changed from STATUS_LOGON_FAILURE
	smb2Header.SetCreditRequestResponse(1)
	smb2Header.SetFlags(SMB2_FLAGS_SERVER_TO_REDIR)
	smb2Header.SetNextCommand(0)
	smb2Header.SetMessageId(p.MessageId())
	smb2Header.SetTreeId(0)
	smb2Header.SetSessionId(session.ID)
	smb2Header.SetSignature([]byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})

	l := len(smb2Header) + len(responseHdr)
	netBIOSHeader := []byte{0x00, 0x00, 0x00, 0x00}
	netBIOSHeader[3] = byte(l)
	netBIOSHeader[2] = byte(l >> 8)

	pkt = append(pkt, netBIOSHeader...)
	pkt = append(pkt, smb2Header...)
	pkt = append(pkt, responseHdr...)

	c.rwc.Write(pkt)

	return nil
}
