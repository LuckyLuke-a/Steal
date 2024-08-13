package structure

import (
	"encoding/json"
	"io"
	"os"
	"sync/atomic"
)

type ConfigFormat struct {
	Inbounds  []BaseBound `json:"inbounds"`
	Outbounds []BaseBound `json:"outbounds"`
	TunMode   Tun         `json:"tun"`
	RestApi   string      `json:"restapi"`
	Logging   bool        `json:"logging"`
	DebugMode bool        `json:"debug_mode"`
}

type BaseBound struct {
	Tag              string           `json:"tag"`
	Addr             string           `json:"addr"`
	Protocol         string           `json:"protocol"`
	ProtocolSettings ProtocolSettings `json:"protocol_settings"`
	Users            []*User          `json:"users"`
}

type User struct {
	ID            string `json:"id"`
	SystemID      string `json:"system_id"`
	UploadStats   atomic.Uintptr
	DownloadStats atomic.Uintptr
}

type ProtocolSettings struct {
	Reality
}

type Reality struct {
	SecretKey           string `json:"secret_key"`
	IntervalSecond      int64  `json:"interval_second"`
	SkewSecond          int64  `json:"skew_second"`
	SNI                 string `json:"sni"`
	ReadDeadLineSecond  int64  `json:"read_deadline_second"`
	WriteDeadLineSecond int64  `json:"write_deadline_second"`
	MinSplitPacket      int    `json:"min_split_packet"`
	MaxSplitPacket      int    `json:"max_split_packet"`
	Padding             int    `json:"padding"`
	SubChunk            int    `json:"sub_chunk"`
}

type Tun struct {
	Start bool   `json:"start"`
	Name  string `json:"name"`
	MTU   int    `json:"mtu"`
}

func (c *ConfigFormat) Unmarshal(data []byte) (err error) {
	if err = json.Unmarshal(data, c); err != nil {
		return
	}
	return
}

func ReadConfigFile(configPath string) ([]byte, error) {
	jsonFile, err := os.Open(configPath)
	if err != nil {
		return nil, err
	}
	defer jsonFile.Close()
	readJson, err := io.ReadAll(jsonFile)
	if err != nil {
		return nil, err
	}
	return readJson, nil
}
