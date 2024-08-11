package assistant

import (
	"bytes"
	"encoding/binary"
	"io"
	"net"
)

type Alert uint8

var (
	ProjectTransferUDPCode byte = 101
	ProjectTransferTCPCode byte = 103

	AlertFailedToReadFull Alert = 254
	AlertSuccess          Alert = 255

	recordTypeApplicationData byte   = 23
	maxCiphertextTLS13        uint16 = 16640

	AlertLevelWarning Alert = 1
	AlertLevelError   Alert = 2

	AlertCloseNotify       Alert = 0
	AlertUnexpectedMessage Alert = 10
	AlertBadRecordMAC      Alert = 20
	AlertRecordOverflow    Alert = 22
	AlertProtocolVersion   Alert = 70
)

func CloseConnection(conns ...io.Closer) {
	for _, conn := range conns {
		if conn != nil {
			conn.Close()
		}
	}
}

func ReadFullMessage(conn *net.Conn) ([]byte, Alert, error) {
	recordHeader := make([]byte, 5)
	_, err := io.ReadFull(*conn, recordHeader)
	if err != nil {
		return nil, AlertFailedToReadFull, err
	}
	typ := recordHeader[0]
	if typ != recordTypeApplicationData {
		return nil, AlertUnexpectedMessage, nil
	}
	if !bytes.HasPrefix(recordHeader, []byte{recordTypeApplicationData, 3, 3}) {
		return nil, AlertProtocolVersion, nil
	}

	lengthOfMessage := binary.BigEndian.Uint16(recordHeader[3:5])
	if lengthOfMessage > maxCiphertextTLS13 {
		return nil, AlertRecordOverflow, nil
	}

	messageContent := make([]byte, lengthOfMessage)
	_, err = io.ReadFull(*conn, messageContent)
	if err != nil {
		return nil, AlertFailedToReadFull, err
	}
	recordHeader = append(recordHeader, messageContent...)
	return recordHeader, AlertSuccess, nil
}


func IsAlertBuffer(buffer []byte) bool{
	if (len(buffer) == 3) && (buffer[0] == byte(AlertLevelError) || buffer[0] == byte(AlertLevelWarning)){
		return true
	}
	return false
}

