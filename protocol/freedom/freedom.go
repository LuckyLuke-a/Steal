package freedom

import (
	"net"
	"time"
)

type FreedomHandler struct {
	Conn        *net.Conn
	destAddr    string
	destNetwork string
}


func (f *FreedomHandler) ReadDestAddr() error {
	return nil
}

func (f *FreedomHandler) ConnectionEstablished() error {
	return nil
}

func (f *FreedomHandler) Read() (buffer []byte, err error) {
	buffer = make([]byte, 4096)
	n, err := (*f.Conn).Read(buffer)
	if err != nil {
		return
	}
	buffer = buffer[:n]
	return
}

func (f *FreedomHandler) Write(buf []byte) (int, error) {
	return (*f.Conn).Write(buf)
}

func (f *FreedomHandler) Close() error {
	return (*f.Conn).Close()
}

func (f *FreedomHandler) GetDestAddr() string {
	return f.destAddr
}

func (f *FreedomHandler) GetDestNetwork() string {
	return f.destNetwork
}

func (f *FreedomHandler) Handshake() error {
	return nil
}

func (f *FreedomHandler) SendDestAddr(addr string, network string, clientHello []byte) error {
	return nil
}

func (f *FreedomHandler) AddUploadUsage(uploadCount uintptr) {

}

func (f *FreedomHandler) AddDwonloadUsage(downloadCount uintptr) {
}



func (f *FreedomHandler) SetReadDeadline(deadline int64) {
	if deadline == 0{
		deadline = 15
	}
	(*f.Conn).SetReadDeadline(time.Now().Add(time.Duration(deadline) * time.Second))
}

func (f *FreedomHandler) SetWriteDeadline(deadline int64) {
	if deadline == 0{
		deadline = 15
	}
	(*f.Conn).SetWriteDeadline(time.Now().Add(time.Duration(deadline) * time.Second))
}

