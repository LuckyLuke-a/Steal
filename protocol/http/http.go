package http

// ********************************************************
// Refrence: https://datatracker.ietf.org/doc/html/rfc7231#section-4.3.6
// ********************************************************

import (
	"bufio"
	"bytes"
	"net"
	"net/http"
	"strings"
	"time"
)

type HttpHandler struct {
	Conn        *net.Conn
	httpMethod  string
	destAddr    string
	destNetwork string
	cacheBuffer []byte
}

func (h *HttpHandler) ReadDestAddr() error {
	buffer, err := h.Read()
	if err != nil{
		return err
	}
    readRequest, err := http.ReadRequest(bufio.NewReader(bytes.NewReader(buffer)))
    if err != nil {
        return err
    }

	h.httpMethod = readRequest.Method
	h.destAddr = readRequest.URL.Host
	h.destNetwork = "tcp"


	// Some apps do not set port in the http requests
	if !strings.Contains(h.destAddr, ":"){
		if strings.EqualFold(readRequest.URL.Scheme, "http"){
			h.destAddr += ":80"
		}else{
			h.destAddr += ":443"
		}
	}

	if !h.isConnectMethod(){
		h.cacheBuffer = buffer
	}
	return nil
}

func (h *HttpHandler) ConnectionEstablished() error {
	if h.isConnectMethod() {
		if _, err := (*h.Conn).Write([]byte("HTTP/1.1 200 Connection established\r\n\r\n")); err != nil {
			return err
		}
	}
	return nil
}

func (h *HttpHandler) Read() (buffer []byte, err error) {
	if len(h.cacheBuffer) != 0{
		buffer = h.cacheBuffer
		h.cacheBuffer = []byte{}
		return 
	}
	buffer = make([]byte, 4096)
	n, err := (*h.Conn).Read(buffer)
	if err != nil {
		return
	}
	buffer = buffer[:n]
	return
}

func (h *HttpHandler) Write(buf []byte) (int, error) {
	return (*h.Conn).Write(buf)
}

func (h *HttpHandler) Close() error {
	return (*h.Conn).Close()
}

func (h *HttpHandler) GetDestAddr() string {
	return h.destAddr
}

func (h *HttpHandler) GetDestNetwork() string {
	return h.destNetwork
}

func (h *HttpHandler) Handshake() error {
	return nil
}

func (h *HttpHandler) SendDestAddr(addr string, network string, clientHello []byte) error {
	return nil
}

func (h *HttpHandler) AddUploadUsage(uploadCount uintptr) {
}

func (h *HttpHandler) AddDwonloadUsage(downloadCount uintptr) {
}



func (h *HttpHandler) SetReadDeadline(deadline int64) {
	if deadline == 0{
		deadline = 15
	}
	(*h.Conn).SetReadDeadline(time.Now().Add(time.Duration(deadline) * time.Second))
}

func (h *HttpHandler) SetWriteDeadline(deadline int64) {
	if deadline == 0{
		deadline = 15
	}
	(*h.Conn).SetWriteDeadline(time.Now().Add(time.Duration(deadline) * time.Second))
}

