package reality

import (
	"bytes"
	"fmt"
	"net"
	"steal/assistant"
	"steal/protocol/reality/encryption"
	"steal/protocol/reality/tlserver"

	utls "github.com/refraction-networking/utls"

	cryptoRand "crypto/rand"
	mathRand "math/rand"
	"steal/structure"
	"strings"
	"time"
)

type RealityHandler struct {
	Conn             *net.Conn
	Config           *structure.BaseBound
	uConn            *utls.UConn
	userID           string
	destAddr         string
	destNetwork      string
	authKey          []byte
	nonce            []byte
	cacheBuffer      []byte
	cacheAlert       assistant.Alert
	handshakeSuccess bool
}

func (r *RealityHandler) ReadConnection() error {
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
	r.handshakeSuccess = true
	r.nonce = tlsConn.Random[:12]
	r.authKey = tlsConn.AuthKey

	
	r.SetReadDeadline(r.Config.ProtocolSettings.ReadDeadLineSecond)
	buffer, err := r.Read()
	if err != nil {
		return err
	}
	if bytes.Equal(buffer, getH2InitMessage()) {
		r.SetReadDeadline(r.Config.ProtocolSettings.ReadDeadLineSecond)
		buffer, err = r.Read()
		if err != nil {
			return err
		}
	}

	clientID, destAddr, destNetwork, clientHello, err := decryptH2HeadersMessage(buffer)
	if err != nil {
		return err
	}
	if !r.isValidUser(clientID) {
		return fmt.Errorf("invalid user id: %s", clientID)
	}
	r.userID = clientID

	randPacketCount := mathRand.Intn(800-400+1) + 400
	randPacket := make([]byte, randPacketCount)
	if _, err := cryptoRand.Read(randPacket); err != nil {
		return err
	}

	// Send random packet to client
	r.SetWriteDeadline(r.Config.ProtocolSettings.WriteDeadLineSecond)
	if _, err := r.Write(randPacket); err != nil {
		return err
	}

	// Wait to receive SETTINGS[0]
	r.SetReadDeadline(r.Config.ProtocolSettings.ReadDeadLineSecond)
	if _, err := r.Read(); err != nil {
		return err
	}

	r.destAddr = destAddr
	r.destNetwork = destNetwork
	r.cacheBuffer = clientHello

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
	buffer, alertErr, err := assistant.ReadFullMessage(r.Conn)
	switch alertErr {
	case assistant.AlertSuccess:
		buffer, err = r.decrypt(buffer)
		if err != nil {
			r.cacheAlert = assistant.AlertBadRecordMAC
			return
		}
		if assistant.IsAlertBuffer(buffer){
			err = fmt.Errorf("alert error")
			return
		}

	case assistant.AlertFailedToReadFull:
		r.cacheAlert = assistant.AlertCloseNotify
	default:
		err = fmt.Errorf("failed to read message")
		r.cacheAlert = alertErr
	}

	return
}

func (r *RealityHandler) Write(buf []byte) (n int, err error) {
	encryptBuffer, err := r.encrypt(buf)
	if err != nil {
		return
	}
	n, err = (*r.Conn).Write(encryptBuffer)
	if err != nil {
		return
	}
	return
}

func (r *RealityHandler) Close() error {
	// If handshake success, send alert
	if r.handshakeSuccess && r.cacheAlert != assistant.AlertCloseNotify{
		r.sendAlert(r.cacheAlert)
	}

	// Close connection
	if err := (*r.Conn).Close(); err != nil {
		return err
	}
	return nil
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

func (r *RealityHandler) PrepareDestAddr(addr, network string, clientHello []byte) error {
	// Write Magic, SETTINGS[0], WINDOW_UPDATE[0]
	r.SetWriteDeadline(r.Config.ProtocolSettings.WriteDeadLineSecond)
	if _, err := r.Write(getH2InitMessage()); err != nil {
		return err
	}

	// Select first userID from inbound
	clientID := r.Config.Users[0].ID
	r.userID = clientID

	// Sent encrypted(destAddr, destNetwork) to server
	r.SetWriteDeadline(r.Config.ProtocolSettings.WriteDeadLineSecond)
	if _, err := r.Write(getH2HeadersMessage(clientID, addr, network, clientHello)); err != nil {
		return err
	}

	r.AddUploadUsage(uintptr(len(clientHello)))

	// Receive random packet
	r.SetReadDeadline(r.Config.ProtocolSettings.ReadDeadLineSecond)
	if _, err := r.Read(); err != nil {
		return err
	}

	// Send SETTINGS[0]
	r.SetWriteDeadline(r.Config.ProtocolSettings.WriteDeadLineSecond)
	if _, err := r.Write(getH2Settings()); err != nil {
		return err
	}

	return nil
}

func (r *RealityHandler) encrypt(buffer []byte) ([]byte, error) {
	encryptData, err := encryption.Encrypt(buffer, r.authKey, r.nonce)
	if err != nil {
		return nil, err
	}
	addHeader := tlserver.AddHeaderApplicationData(encryptData)
	return addHeader, nil
}

func (r *RealityHandler) decrypt(buffer []byte) ([]byte, error) {
	// ignore recordHeader
	buffer = buffer[5:]
	decryptData, err := encryption.Decrypt(buffer, r.authKey, r.nonce)
	if err != nil {
		return nil, err
	}
	return decryptData, nil
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
	if deadline == 0{
		deadline = 15
	}
	(*r.Conn).SetReadDeadline(time.Now().Add(time.Duration(deadline) * time.Second))
}

func (r *RealityHandler) SetWriteDeadline(deadline int64) {
	if deadline == 0{
		deadline = 15
	}
	(*r.Conn).SetWriteDeadline(time.Now().Add(time.Duration(deadline) * time.Second))
}

