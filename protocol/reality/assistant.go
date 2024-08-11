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
	r.utlsConn = utlsConn
	r.tlsConn = utlsConn

	utlsClientHello := r.utlsConn.HandshakeState.Hello
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

	r.authKey, err = r.utlsConn.HandshakeState.State13.EcdheKey.ECDH(preparePublicKey)
	if err != nil {
		return err
	}
	r.nonce = utlsClientHello.Random[:12]
	newSessionId := encryption.GenerateSessionId(utlsClientHello.Random, r.authKey)
	if newSessionId == nil {
		return fmt.Errorf("failed to generate session id")
	}

	// Replace session id
	utlsClientHello.SessionId = newSessionId
	copy(utlsClientHello.Raw[39:], utlsClientHello.SessionId)

	// Handshake to stealServer
	if err := r.utlsConn.Handshake(); err != nil {
		log.Println("[Reality] handshake failed: ", err)
		return err
	}

	if !r.handshakeSuccess {
		return fmt.Errorf("[Reality] failed to authenticate server")
	}

	return nil
}

func (r *RealityHandler) verifyCert(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
	getHost := strings.Split(r.Config.ProtocolSettings.SNI, ":")[0]
	p, _ := reflect.TypeOf(r.utlsConn.Conn).Elem().FieldByName("peerCertificates")
	certs := *(*([]*x509.Certificate))(unsafe.Pointer(uintptr(unsafe.Pointer(r.utlsConn.Conn)) + p.Offset))
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

func (r *RealityHandler) isValidUser(clientID string) bool {
	for _, user := range r.Config.Users {
		if strings.EqualFold(clientID, user.ID) {
			return true
		}
	}
	return false
}
