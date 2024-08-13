package reality

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha512"
	"crypto/x509"
	"fmt"
	"log"
	"reflect"
	"steal/protocol/reality/encryption"
	"strings"
	"unsafe"
	utls "github.com/refraction-networking/utls"

)

var (
	tlsClientHello = []byte{22, 3}
	tlsServerHello = []byte{22, 3, 3}
)



// Make tls handshake with steal server
func (r *RealityHandler) makeHandshake() error {
	getHost := strings.Split(r.Config.ProtocolSettings.SNI, ":")[0]

	utlsConfig := &utls.Config{
		ServerName:             getHost,
		InsecureSkipVerify:     true,
		SessionTicketsDisabled: true,
		VerifyPeerCertificate:  r.verifyCert,
	}

	utlsConn := utls.UClient(*r.Conn, utlsConfig, utls.HelloChrome_Auto)
	if err := utlsConn.BuildHandshakeState(); err != nil {
		return err
	}
	r.tlsConn = utlsConn

	utlsClientHello := utlsConn.HandshakeState.Hello
	publicKey, _, err := encryption.GenerateAuthKey(
		utlsClientHello.Random,
		r.Config.ProtocolSettings.IntervalSecond,
		r.Config.ProtocolSettings.SecretKey,
		0,
	)
	if err != nil {
		return err
	}

	preparePublicKey, err := ecdh.X25519().NewPublicKey(publicKey)
	if err != nil {
		return err
	}

	r.authKey, err = utlsConn.HandshakeState.State13.EcdheKey.ECDH(preparePublicKey)
	if err != nil {
		return err
	}
	newSessionId := encryption.GenerateSessionId(utlsClientHello.Random, r.authKey)
	if newSessionId == nil {
		return fmt.Errorf("failed to generate session id")
	}

	utlsClientHello.SessionId = newSessionId
	copy(utlsClientHello.Raw[39:], utlsClientHello.SessionId)

	if err := utlsConn.Handshake(); err != nil {
		log.Println("[Reality] handshake failed: ", err)
		return err
	}

	if !r.handshakeSuccess {
		return fmt.Errorf("[Reality] failed to authenticate server")
	}

	return nil
}


// Check the received certficate from server, has server signature or not
func (r *RealityHandler) verifyCert(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
	utlsConn := r.tlsConn.(*utls.UConn)
	getHost := strings.Split(r.Config.ProtocolSettings.SNI, ":")[0]
	
	p, _ := reflect.TypeOf(utlsConn.Conn).Elem().FieldByName("peerCertificates")
	certs := *(*([]*x509.Certificate))(unsafe.Pointer(uintptr(unsafe.Pointer(utlsConn.Conn)) + p.Offset))
	if pub, ok := certs[0].PublicKey.(ed25519.PublicKey); ok {
		h := hmac.New(sha512.New, r.authKey)
		h.Write(pub)
		if bytes.Equal(h.Sum(nil), certs[0].Signature) {
			r.handshakeSuccess = true
			return nil
		}
	}
	opts := x509.VerifyOptions{
		DNSName:       getHost,
		Intermediates: x509.NewCertPool(),
	}
	for _, cert := range certs[1:] {
		opts.Intermediates.AddCert(cert)
	}
	if _, err := certs[0].Verify(opts); err != nil {
		return err
	}
	return nil
}

// Check the received userID exist or not
func (r *RealityHandler) isValidUser(clientID string) bool {
	for _, user := range r.Config.Users {
		if strings.EqualFold(clientID, user.ID) {
			return true
		}
	}
	return false
}

// Check the received packet is handshake packet or not
func isHandshakePacket(buffer []byte) bool{
	if bytes.HasPrefix(buffer, tlsClientHello) || bytes.HasPrefix(buffer, tlsServerHello){
		return true
	}
	return false
}



