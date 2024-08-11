package reality

import (
	"bytes"
	"encoding/binary"
	"io"
	"steal/assistant"
)

// Http2 initial messages
var (
	h2StreamMagic []byte = []byte{80, 82, 73, 32, 42, 32, 72, 84, 84, 80, 47, 50, 46, 48, 13, 10, 13, 10, 83, 77, 13, 10, 13, 10}

	h2StreamSettings []byte = []byte{0, 0, 24, 4, 0, 0, 0, 0, 0, 0, 1, 0, 1, 0, 0, 0, 2, 0, 0, 0, 0, 0, 4, 0, 96, 0, 0, 0, 6, 0, 4, 0, 0}

	h2WindowUpdate []byte = []byte{0, 0, 4, 8, 0, 0, 0, 0, 0, 0, 239, 0, 1}

	h2Settings []byte = []byte{0, 0, 0, 4, 1, 0, 0, 0, 0}

	chromeUserAgent []byte = []byte("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/536.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/536.36")

	acceptData []byte = []byte("text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7")
)

// Retrive Magic, SETTINGS[0], WINDOW_UPDATE[0]
func getH2InitMessage() []byte {
	initMessage := append([]byte{}, h2StreamMagic...)
	initMessage = append(initMessage, h2StreamSettings...)
	initMessage = append(initMessage, h2WindowUpdate...)
	return initMessage
}

// Retrive HEADERS[1]
func getH2HeadersMessage(clientID, destAddr, destNetwork string, clientHello []byte) []byte {
	headerMessage := []byte{}

	// Add clientIDLen and clientID
	headerMessage = append(headerMessage, byte(len(clientID)))
	headerMessage = append(headerMessage, []byte(clientID)...)

	// Get clientHello len (TODO: convert uint32 to uint24)
	clientHelloLen := make([]byte, 4)
	binary.BigEndian.PutUint32(clientHelloLen, uint32(len(clientHello)))


	// Add clientHello len and clientHello to message
	headerMessage = append(headerMessage, clientHelloLen...)
	headerMessage = append(headerMessage, clientHello...)

	// Get destAddr len
	destAddrLen := byte(len(destAddr))

	// Add destAddr len and destAddr to message
	headerMessage = append(headerMessage, destAddrLen)
	headerMessage = append(headerMessage, destAddr...)

	// Get destNetwork code
	destNetworkCode := assistant.ProjectTransferTCPCode
	if destNetwork == "udp" {
		destNetworkCode = assistant.ProjectTransferUDPCode
	}

	// Add destNetwork code to message
	headerMessage = append(headerMessage, destNetworkCode)

	// Add "schema:https" method and "path:/" to message (should be added)
	headerMessage = append(headerMessage, []byte{135, 132}...)

	// Add chrome user agent to message (should be added)
	headerMessage = append(headerMessage, chromeUserAgent...)

	// Add accept data to message (should be added)
	headerMessage = append(headerMessage, acceptData...)

	return headerMessage
}



func decryptH2HeadersMessage(buffer []byte) (clientID, destAddr, destNetwork string, clientHello []byte, err error) {
	readBuffer := bytes.NewReader(buffer)

	// Read ClientID
	clientIDLen := make([]byte, 1)
	if _, err = io.ReadFull(readBuffer, clientIDLen); err != nil{
		return 
	}
	clientIDBytes := make([]byte, clientIDLen[0])
	if _, err = io.ReadFull(readBuffer, clientIDBytes); err != nil{
		return 
	}
	clientID = string(clientIDBytes)

	// Read clientHello
	clientHelloBytes := make([]byte, 4)
	if _, err = io.ReadFull(readBuffer, clientHelloBytes); err != nil{
		return 
	}
	clientHelloLen := binary.BigEndian.Uint32(clientHelloBytes)
	clientHello = make([]byte, clientHelloLen)
	if _, err = io.ReadFull(readBuffer, clientHello); err != nil{
		return 
	}
	// Read destAddr
	destAddrLen := make([]byte, 1)
	if _, err = io.ReadFull(readBuffer, destAddrLen); err != nil{
		return 
	}
	destAddrByte := make([]byte, destAddrLen[0])
	if _, err = io.ReadFull(readBuffer, destAddrByte); err != nil{
		return 
	}
	destAddr = string(destAddrByte)

	// Read destNetwork
	destNetworkLen := make([]byte, 1)
	if _, err = io.ReadFull(readBuffer, destNetworkLen); err != nil{
		return 
	}
	if destNetworkLen[0] == assistant.ProjectTransferTCPCode{
		destNetwork = "tcp"
	}else{
		destNetwork = "udp"
	}

	return

}


// Retrive Settings[0]
func getH2Settings() []byte {
	return h2Settings
}



