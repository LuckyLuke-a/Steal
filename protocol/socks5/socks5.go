package socks5

// ********************************************************
// Refrence: https://datatracker.ietf.org/doc/html/rfc1928
// ********************************************************

import (
	"errors"
	"fmt"
	"io"
	"net"
	"time"
)


var (
	defaultIPAddr       net.IP = net.IP{127, 0, 0, 1}
	socksVersion5       byte   = 5
	cmdConnect          byte   = 1
	cmdBind             byte   = 2
	cmdUDPAssociate     byte   = 3
	atypIPv4            byte   = 1
	atypDomainName      byte   = 3
	atypIPv6            byte   = 4
	replySucceeded      byte   = 0
	replyGeneralFailure byte   = 1
)



type Socks5Handler struct{
	Conn *net.Conn
	udpConn *net.UDPConn
	destAddr string
	destNetwork string	
	port uint16
    natPort uint16
	header []byte
	cacheBuffer []byte
}



func (s *Socks5Handler) ReadConnection() error {
	// Read ver, nmethods, methods
	buf := make([]byte, 3)
	if _, err := io.ReadFull(*s.Conn, buf); err != nil {
		return err
	}

	if buf[0] != socksVersion5 {
		return errors.New("incorrect socks version")
	}

	// Success response
	if _, err := (*s.Conn).Write([]byte{5, 0}); err != nil{
		return err
	}

	// Read version, command, rsv, addressType(atyp)
	buf = make([]byte, 4)
	if _, err := io.ReadFull(*s.Conn, buf); err != nil {
		return err
	}
	
	addressType := buf[3]
	destAddr, destPort, _, _, err := readAdderAndPort(*s.Conn, addressType)
	if err != nil{
		return err
	}

	s.destAddr = fmt.Sprintf("%s:%d", destAddr, destPort)

	command := buf[1]
	switch command {
	case cmdConnect:
		// Connect
		return s.handleConnect()

	case cmdUDPAssociate:
		// UDP Associate
		return s.handleUDPAssociate()

	case cmdBind:
		// Bind
		return errors.New("bind method not implemented")

	default:
		return errors.New("incorrect command")
	}
}

func (s *Socks5Handler) ConnectionEstablished() error {
	err := s.sendReply(replySucceeded, atypIPv4, defaultIPAddr)
	if s.destNetwork == "udp"{
		buffer, err := s.Read()
		if err != nil{
			return err
		}
		s.cacheBuffer = buffer
	}
	return err

}

func (s *Socks5Handler) Read() ([]byte, error){
	buffer := make([]byte, 4096)
	switch s.destNetwork{
	case "tcp":
		n, err := (*s.Conn).Read(buffer)
		if err != nil{
			return nil, err
		}
		return buffer[:n], nil

	case "udp":
		if s.cacheBuffer != nil{
			buffer = s.cacheBuffer
			s.cacheBuffer = nil
			return buffer, nil
		}
		n, addr, err := s.udpConn.ReadFromUDP(buffer)
		if err != nil {
			return nil, err
		}
		data, err := s.handleUDPRequest(addr, buffer[:n])
		if err != nil{
			return nil, err
		}
		return data, nil
	default:
		return nil, errors.New("unknown error")
	}
}

func (s *Socks5Handler) Write(buf []byte) (int, error){
	switch s.destNetwork{
	case "tcp":
		return (*s.Conn).Write(buf)
	case "udp":
		return s.handleUDPResponse(buf)
	default:
		return 0, errors.New("unknown error")
	}
}


func (s *Socks5Handler) Close() error{
	if s.udpConn != nil{
		s.udpConn.Close()
	}
	return (*s.Conn).Close()
}


func (s *Socks5Handler) GetDestAddr() string {
	return s.destAddr
}

func (s *Socks5Handler) GetDestNetwork() string {
	return s.destNetwork
}


func (s *Socks5Handler) Handshake() error{
	return nil
}


func (s *Socks5Handler) PrepareDestAddr(addr, network string, clientHello []byte) error{
	return nil
}


func (s *Socks5Handler) AddUploadUsage(uploadCount uintptr) {
}

func (s *Socks5Handler) AddDwonloadUsage(downloadCount uintptr) {
}



func (s *Socks5Handler) SetReadDeadline(deadline int64) {
	if deadline == 0{
		deadline = 15
	}
	(*s.Conn).SetReadDeadline(time.Now().Add(time.Duration(deadline) * time.Second))
}

func (s *Socks5Handler) SetWriteDeadline(deadline int64) {
	if deadline == 0{
		deadline = 15
	}
	(*s.Conn).SetWriteDeadline(time.Now().Add(time.Duration(deadline) * time.Second))
}

