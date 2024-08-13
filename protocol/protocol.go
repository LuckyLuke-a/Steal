package protocol

import (
	"fmt"
	"net"
	"steal/protocol/freedom"
	"steal/protocol/http"
	"steal/protocol/reality"
	"steal/protocol/socks5"
	"steal/structure"
)

var (
	supportedProtocols = []string{"reality", "socks5", "http", "freedom"}
)

type ProtocolHandler interface {
	// Retrive destAddr and destNetwork
	ReadDestAddr() error  

	// Send addr (addr+network)
	SendDestAddr(addr, network string, clientHello []byte) error

	// Send success message (connection established)
	ConnectionEstablished() error

	// Estalish connection to server
	Handshake() error

	// Read buffer
	Read() ([]byte, error)

	// Write buffer
	Write(buffer []byte) (int, error)

	// Get destAddr
	GetDestAddr() string

	// Get destNetwork	
	GetDestNetwork() string     
	
	// Add upload usage to stats	
	AddUploadUsage(uploadCount uintptr)

	// Add download usage to stats	
	AddDwonloadUsage(downloadCount uintptr)

	// Set deadline to prevent hang on read	
	SetReadDeadline(deadline int64)

	// Set deadline to prevent hang on write	
	SetWriteDeadline(deadline int64)

	// Close connection
	Close() error

}

func GetProtocolHandler(conn *net.Conn, config *structure.BaseBound) (handler ProtocolHandler, err error) {	
	switch config.Protocol {
	case supportedProtocols[0]:
		handler = &reality.RealityHandler{Conn: conn, Config: config}

	case supportedProtocols[1]:
		handler = &socks5.Socks5Handler{Conn: conn}

	case supportedProtocols[2]:
		handler = &http.HttpHandler{Conn: conn}

	case supportedProtocols[3]:
		handler = &freedom.FreedomHandler{Conn: conn}

	default:
		err = fmt.Errorf("incorrect proxy type : %s", config.Protocol)
	}
	return
}

func IsSupportedProtocol(protocol string) bool {
	for _, supportProtocol := range supportedProtocols {
		if protocol == supportProtocol {
			return true
		}
	}
	return false
}
