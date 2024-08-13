package connection

import (
	"log"
	"net"
	"steal/assistant"
	"steal/structure"
	"steal/protocol"
	"sync"
	"time"
)

type Connection struct {
	Inbound   *structure.BaseBound
	Outbound  *structure.BaseBound
	Listener  *net.Listener
	IsInbound bool
}

func (c *Connection) Run() {
	listener, err := net.Listen("tcp", c.Inbound.Addr)
	if err != nil {
		log.Fatal("Failed to start tcp listener: ", err)
	}
	defer listener.Close()
	c.Listener = &listener

	if c.IsInbound {
		log.Printf("[Inbound-%s] started at: %s",
			c.Inbound.Protocol,
			c.Inbound.Addr)
	} else {
		log.Printf("[Outbound-%s] started at: %s",
			c.Inbound.Protocol,
			c.Inbound.Addr)
	}

	for {
		clientConn, err := listener.Accept()
		if err != nil {
			continue
		}
		go c.handleConnection(&clientConn)
	}
}

func (c *Connection) handleConnection(clientConn *net.Conn) {
	defer (*clientConn).Close()

	// Get inbound proxy type
	inboundHandler, err := protocol.GetProtocolHandler(clientConn, c.Inbound)
	if err != nil {
		log.Println("[Connection]: GetProtocolHandler: ", err)
		return
	}
	defer inboundHandler.Close()

	// Read destAddr, destNetwork from inbound connection
	if err := inboundHandler.ReadDestAddr(); err != nil {
		log.Println("[Connection]: ReadConnection: ", err)
		return
	}

	// Send success message from inbound to client
	if err := inboundHandler.ConnectionEstablished(); err != nil {
		log.Println("[Connection]: ConnectionEstablished: ", err)
		return
	}

	// Received destAddr, destNetwork
	destNetwork := inboundHandler.GetDestNetwork()
	destAddr := inboundHandler.GetDestAddr()

	isFreedom := c.Outbound.Protocol == "freedom" || !c.IsInbound

	var serverConn net.Conn
	if isFreedom {
		// Server side
		serverConn, err = net.Dial(destNetwork, destAddr)
	} else {
		// Client side
		serverConn, err = net.Dial("tcp", c.Outbound.Addr)
	}
	if err != nil {
		log.Println("[Connection]: ServerConn: ", err)
		return
	}
	defer serverConn.Close()

	// Get oubound proxy type
	outboundHandler, err := protocol.GetProtocolHandler(&serverConn, c.Outbound)
	if err != nil {
		log.Println("[Connection]: ServerHandler: ", err)
		return
	}
	defer outboundHandler.Close()

	// Establish connection to outbound
	if err := outboundHandler.Handshake(); err != nil {
		log.Println("[Connection]: EstablishConnection: ", err)
		return
	}

	log.Printf("[Connection]: Accepted to: %s:%s", destNetwork, destAddr)

	// Client side
	if !isFreedom {
		// Get clientHello (if exist)
		(*clientConn).SetReadDeadline(time.Now().Add(time.Millisecond * 100))
		buffer, err := inboundHandler.Read()
		if err != nil{
			buffer = []byte{}
		}

		// Prepare destAddr, destNetwork
		if err := outboundHandler.SendDestAddr(destAddr, destNetwork, buffer); err != nil {
			return
		}
	}

	var wg sync.WaitGroup
	wg.Add(2)

	// Copy data from inboundHandler to outboundHandler
	isClientAnyDataSent := false
	go func() {
		defer wg.Done()
		defer assistant.CloseConnection(inboundHandler, outboundHandler)
		for {
			inboundHandler.SetReadDeadline(c.Inbound.ProtocolSettings.ReadDeadLineSecond)
			buffer, err := inboundHandler.Read()
			if err != nil {
				if err, ok := err.(net.Error); ok && err.Timeout() && isClientAnyDataSent {
					continue
				}
				return
			}

			inboundHandler.AddDwonloadUsage(uintptr(len(buffer)))
			isClientAnyDataSent = true

			outboundHandler.SetWriteDeadline(c.Outbound.ProtocolSettings.WriteDeadLineSecond)
			if _, err = outboundHandler.Write(buffer); err != nil {
				return
			}

			outboundHandler.AddUploadUsage(uintptr(len(buffer)))
		}
	}()

	// Copy data from outboundHandler to inboundHandler
	isServerAnyDataSent := false
	go func() {
		defer wg.Done()
		defer assistant.CloseConnection(outboundHandler, inboundHandler)
		for {
			outboundHandler.SetReadDeadline(c.Outbound.ProtocolSettings.ReadDeadLineSecond)
			buffer, err := outboundHandler.Read()
			if err != nil {
				if err, ok := err.(net.Error); ok && err.Timeout() && isServerAnyDataSent {
					continue
				}
				return
			}

			outboundHandler.AddDwonloadUsage(uintptr(len(buffer)))
			isServerAnyDataSent = true

			inboundHandler.SetWriteDeadline(c.Inbound.ProtocolSettings.WriteDeadLineSecond)
			_, err = inboundHandler.Write(buffer)
			if err != nil {
				return
			}
			inboundHandler.AddUploadUsage(uintptr(len(buffer)))
		}
	}()

	wg.Wait()

}
