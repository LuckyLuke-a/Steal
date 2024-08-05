
package socks5


import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
)




func (s *Socks5Handler) handleConnect() error {
	s.destNetwork = "tcp"
	return nil
}



func (s *Socks5Handler) handleUDPAssociate() error {
	s.destNetwork = "udp"
	udpAddr, err := net.ResolveUDPAddr(s.destNetwork, s.destAddr)
	if err != nil {
		s.sendReply(replyGeneralFailure, atypIPv4, nil)
		return err
	}

	udpConn, err := net.ListenUDP(s.destNetwork, udpAddr)
	if err != nil {
		s.sendReply(replyGeneralFailure, atypIPv4, nil)
		return err
	}

	localAddr := udpConn.LocalAddr().(*net.UDPAddr)
	s.port = uint16(localAddr.Port)
	s.udpConn = udpConn
	return nil
}



func (s *Socks5Handler) handleUDPRequest(clientAddr *net.UDPAddr, data []byte) ([]byte, error){
	if len(data) < 10 {
		return nil, errors.New("incorrect data")
	}

	reader := bytes.NewReader(data)

	// Read 2 RSV bytes and 1 FRAG byte
    headerData := make([]byte, 3) 
    if _, err := io.ReadFull(reader, headerData); err != nil {
        return nil, err
    }

	var atyp byte
	if err := binary.Read(reader, binary.BigEndian, &atyp); err != nil {
		return nil, err
	}

	destAddr, destPort, rawAdder, rawPort, err := readAdderAndPort(reader, atyp)
	if err != nil{
		return nil, err
	}

    s.header = append(headerData, atyp)
    s.header = append(s.header, rawAdder...)
    s.header = append(s.header, rawPort...)
    s.natPort = uint16(clientAddr.Port)


	s.destAddr = fmt.Sprintf("%s:%d", destAddr, destPort)

	dataToSend, err := io.ReadAll(reader)
	if err != nil {
		return nil, err
	}
	return dataToSend, nil
}




func (s *Socks5Handler) handleUDPResponse(data []byte) (int, error){
	if s.natPort == 0{
		return 0, errors.New("failed to get natPort")
	}
	resolveAddr, err := net.ResolveUDPAddr("udp", fmt.Sprintf("%s:%d", defaultIPAddr.String(), s.natPort))
	if err != nil{
		return 0, err
	}
	prepareBuf := append(s.header, data...)

	return s.udpConn.WriteToUDP(prepareBuf, resolveAddr)
}




func (s *Socks5Handler) sendReply(rep byte, atyp byte, bndAddr net.IP) error {
	var addrBytes []byte
	switch atyp {
	case atypIPv4:
		if bndAddr == nil {
			addrBytes = make([]byte, 4)
		} else {
			addrBytes = bndAddr.To4()
		}
	case atypIPv6:
		if bndAddr == nil {
			addrBytes = make([]byte, 16)
		} else {
			addrBytes = bndAddr.To16()
		}
	default:
		addrBytes = []byte{0}
	}

	portBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(portBytes, s.port)

	reply := bytes.NewBuffer([]byte{socksVersion5, rep, 0, atyp})
	reply.Write(addrBytes)
	reply.Write(portBytes)

	_, err := (*s.Conn).Write(reply.Bytes())
	return err
}




func readAdderAndPort(conn io.Reader, addressType byte) (destAddr string, destPort uint16, rawAdder []byte, rawPort []byte, err error){
	switch addressType {
	case atypIPv4:
		// IPV4
		rawAdder = make([]byte, 4)
		if _, err = io.ReadFull(conn, rawAdder); err != nil {
			return
		}
		destAddr = net.IP(rawAdder).String()

	case atypDomainName:
		// DomainName
		domainLength := make([]byte, 1)
		if _, err = io.ReadFull(conn, domainLength); err != nil {
			return 
		}

		rawAdder = make([]byte, domainLength[0])
		if _, err = io.ReadFull(conn, rawAdder); err != nil {
			return
		}
		destAddr = string(rawAdder)
		rawAdder = append(domainLength, rawAdder...)

	case atypIPv6:
		// IPV6
		rawAdder = make([]byte, 16)
		if _, err = io.ReadFull(conn, rawAdder); err != nil {
			return 
		}
		destAddr = net.IP(rawAdder).String()

	default:
		err = errors.New("incorrect addressType")
		return 
	}

	rawPort = make([]byte, 2)
	if _, err = io.ReadFull(conn, rawPort); err != nil {
		return
	}
	destPort = binary.BigEndian.Uint16(rawPort)
	return
}


