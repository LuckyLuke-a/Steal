package reality

import (
	"bytes"
	"fmt"
	"net"
	"steal/protocol/reality/encryption"
	"steal/protocol/reality/tlserver"
	"steal/structure"
	"strings"
	"time"
	"math/rand"

)

var (
	minRandPacket = 600
	maxRandPacket = 1300
)

type RealityHandler struct {
	Conn                 *net.Conn
	Config               *structure.BaseBound
	tlsConn              net.Conn
	userID               string
	destAddr             string
	destNetwork          string
	authKey              []byte
	cacheBuffer          []byte
	handshakeSuccess     bool
	firstPacketProcessed bool
}

func (r *RealityHandler) ReadDestAddr() error {
	onlyHostSni := strings.Split(r.Config.ProtocolSettings.SNI, ":")[0]

	config := tlserver.Config{
		InsecureSkipVerify:     true,
		SessionTicketsDisabled: true,
		ServerName:             onlyHostSni,
	}

	tlsConn, err := tlserver.Server(
		r.Conn,
		&config,
		&r.Config.ProtocolSettings,
	)
	if err != nil {
		return fmt.Errorf("error handshake: %s", err)
	}
	r.tlsConn = tlsConn
	r.handshakeSuccess = true
	r.authKey = tlsConn.AuthKey

	// Wait to receive h2 initial message
	r.SetReadDeadline(r.Config.ProtocolSettings.ReadDeadLineSecond)
	buffer, err := r.Read()
	if err != nil {
		return err
	}
	if !bytes.Equal(buffer, getH2InitMessage()) {
		return fmt.Errorf("incorrect h2 initial message")
	}

	// Wait to receive first fragmented packet
	r.SetReadDeadline(r.Config.ProtocolSettings.ReadDeadLineSecond)
	buffer, err = r.Read()
	if err != nil {
		return err
	}

	// Wait, look like we process the user message
	time.Sleep(time.Microsecond * time.Duration(rand.Intn(150-50)+50))

	// Generate random packet
	randLength := rand.Intn(200-100+1) + 100
	randomPacket := encryption.GenerateRandomPacket(r.authKey, 60, randLength)

	countFakePacket := rand.Intn(4) + 1
	randomPacket[0] = byte(countFakePacket)
	r.SetWriteDeadline(r.Config.ProtocolSettings.WriteDeadLineSecond)
	if _, err := r.Write(randomPacket); err != nil {
		return err
	}

	// Wait to recv h2 settings
	r.SetReadDeadline(r.Config.ProtocolSettings.ReadDeadLineSecond)
	_, err = r.Read()
	if err != nil {
		return err
	}

	for range countFakePacket {
		time.Sleep(time.Microsecond * time.Duration(rand.Intn(150-50)+50)) // likely we proccess the message
		randLength = rand.Intn(maxRandPacket-minRandPacket+1) + minRandPacket
		randomPacket = encryption.GenerateRandomPacket(r.authKey, 100, randLength)
		r.SetWriteDeadline(r.Config.ProtocolSettings.WriteDeadLineSecond)
		if _, err := r.Write(randomPacket); err != nil {
			return err
		}
	}

	var reassemblePacket [][]byte

	packetData := buffer[:2]                                // Get currentIndex, allIndex
	reassemblePacket = append(reassemblePacket, buffer[2:]) // Skip currentIndex, allIndex
	allPacketLength := packetData[1]                        // Get allIndex

	for _ = range allPacketLength - 1 {
		buffer, err = r.Read()
		if err != nil {
			return err
		}
		reassemblePacket = append(reassemblePacket, buffer[2:])
	}

	// Reassemble user clientHello message
	buffer = encryption.RemovePadding(reassemblePacket, r.Config.ProtocolSettings.Padding, r.Config.ProtocolSettings.SubChunk)

	// decrypt message
	clientID, destAddr, destNetwork, clientHello, err := decryptH2HeadersMessage(buffer)
	if err != nil || !r.isValidUser(clientID) {
		return err
	}

	// Set the vars
	r.userID = clientID
	r.destAddr = destAddr
	r.destNetwork = destNetwork
	r.cacheBuffer = clientHello
	r.firstPacketProcessed = true
	return nil

}

func (r *RealityHandler) Handshake() (err error) {
	// Setup tls
	err = r.makeHandshake()
	return
}

func (r *RealityHandler) Read() (buffer []byte, err error) {
	if len(r.cacheBuffer) != 0 {
		buffer = r.cacheBuffer
		r.cacheBuffer = []byte{}
		return
	}
	buf := make([]byte, 8192)
	n, err := r.tlsConn.Read(buf)
	if err != nil {
		return
	}
	buffer = buf[:n]
	if r.firstPacketProcessed && len(buffer) > 6 && isHandshakePacket(buffer[6:]){
		var reassmeblePacket [][]byte
		lenPackets := buffer[1]
		reassmeblePacket = append(reassmeblePacket, buffer[2:])
		for range lenPackets-1{
			buf := make([]byte, 8192)
			n, err = r.tlsConn.Read(buf)
			if err != nil {
				return
			}
			buffer = buf[:n]
			reassmeblePacket = append(reassmeblePacket, buffer[2:])
		}
		buffer = encryption.RemovePadding(reassmeblePacket, r.Config.ProtocolSettings.Padding, r.Config.ProtocolSettings.SubChunk)
	}

	return
}

func (r *RealityHandler) Write(buf []byte) (n int, err error) {
	if r.firstPacketProcessed && isHandshakePacket(buf){
		minSplitSize := 1000
		maxSplitSize := 2000
		slicesChunk := encryption.AddPadding(buf, minSplitSize, maxSplitSize, r.Config.ProtocolSettings.Padding, r.Config.ProtocolSettings.SubChunk)
		for i, chunk := range slicesChunk{
			chunk = append([]byte{byte(i + 1), byte(len(slicesChunk))}, chunk...)
			r.SetWriteDeadline(r.Config.ProtocolSettings.WriteDeadLineSecond)
			if _, err := r.Write(chunk); err != nil {
				return 0, err
			}
			time.Sleep(time.Microsecond * time.Duration(rand.Intn(150-50)+50))
		}
		return
	}
	return r.tlsConn.Write(buf)
}

func (r *RealityHandler) Close() error {
	if r.handshakeSuccess {
		return r.tlsConn.Close()
	}
	return (*r.Conn).Close()
}

func (r *RealityHandler) GetDestAddr() string {
	return r.destAddr
}

func (r *RealityHandler) GetDestNetwork() string {
	return r.destNetwork
}

func (r *RealityHandler) ConnectionEstablished() error {
	return nil
}

func (r *RealityHandler) SendDestAddr(addr, network string, clientHello []byte) error {
	// Write Magic, SETTINGS[0], WINDOW_UPDATE[0]
	r.SetWriteDeadline(r.Config.ProtocolSettings.WriteDeadLineSecond)
	if _, err := r.Write(getH2InitMessage()); err != nil {
		return err
	}

	// Select first userID from inbound
	clientID := r.Config.Users[0].ID
	r.userID = clientID

	// Prepare first packet
	firstInitialPacket := getH2HeadersMessage(clientID, addr, network, clientHello)
	slicesChunk := encryption.AddPadding(
		firstInitialPacket, 
		r.Config.ProtocolSettings.MinSplitPacket, 
		r.Config.ProtocolSettings.MaxSplitPacket,
		r.Config.ProtocolSettings.Padding, 
		r.Config.ProtocolSettings.SubChunk,
	)

	for i, chunk := range slicesChunk {
		chunk = append([]byte{byte(i + 1), byte(len(slicesChunk))}, chunk...)
		r.SetWriteDeadline(r.Config.ProtocolSettings.WriteDeadLineSecond)
		if _, err := r.Write(chunk); err != nil {
			return err
		}
		if i == 0 {
			// Receive random packet from server
			r.SetReadDeadline(r.Config.ProtocolSettings.ReadDeadLineSecond)
			buffer, err := r.Read()
			if err != nil {
				return err
			}

			randomPacket := encryption.GenerateRandomPacket(r.authKey, 60, 100)
			if !bytes.HasPrefix(buffer[1:], randomPacket[1:]){
				return fmt.Errorf("incorrect random-byte")
			}
			countFakePacket := buffer[0]
			// Send SETTINGS[0]
			r.SetWriteDeadline(r.Config.ProtocolSettings.WriteDeadLineSecond)
			if _, err := r.Write(getH2Settings()); err != nil {
				return err
			}
			for range countFakePacket {
				// Recv random packet from server
				r.SetReadDeadline(r.Config.ProtocolSettings.ReadDeadLineSecond)
				buffer, err = r.Read()
				if err != nil {
					return err
				}
				randomPacket = encryption.GenerateRandomPacket(r.authKey, 100, minRandPacket)
				if !bytes.HasPrefix(buffer, randomPacket){
					return fmt.Errorf("random byte modified")
				}
			}
		}
	}

	r.AddUploadUsage(uintptr(len(clientHello)))
	r.firstPacketProcessed = true

	return nil
}

func (r *RealityHandler) AddUploadUsage(uploadCount uintptr) {
	for _, user := range r.Config.Users {
		if user.ID == r.userID {
			user.UploadStats.Add(uploadCount)
		}
	}
}

func (r *RealityHandler) AddDwonloadUsage(downloadCount uintptr) {
	for _, user := range r.Config.Users {
		if user.ID == r.userID {
			user.DownloadStats.Add(downloadCount)
		}
	}
}

func (r *RealityHandler) SetReadDeadline(deadline int64) {
	if deadline == 0 {
		deadline = 15
	}
	r.tlsConn.SetReadDeadline(time.Now().Add(time.Duration(deadline) * time.Second))
}

func (r *RealityHandler) SetWriteDeadline(deadline int64) {
	if deadline == 0 {
		deadline = 15
	}
	r.tlsConn.SetWriteDeadline(time.Now().Add(time.Duration(deadline) * time.Second))
}
