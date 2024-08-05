package tun

import (
	"fmt"
	"runtime"
	"steal/tun/platform"
)


type TunMode interface{
	Start() error
	Stop() error
}



func GetTun() (handler TunMode, err error) {
	os := runtime.GOOS
	switch os {
	case "windows", "android":
		return &platform.TunHandler{}, nil
	}
	return nil, fmt.Errorf("os not supported: %s", os)
}


