package assistant

import (
	"io"
)

type Alert uint8

var (
	ProjectTransferUDPCode byte = 101
	ProjectTransferTCPCode byte = 103
)

func CloseConnection(conns ...io.Closer) {
	for _, conn := range conns {
		if conn != nil {
			conn.Close()
		}
	}
}