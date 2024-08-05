//go:build android

package platform

import (
	"fmt"

	"steal/tun/tun2socks/engine"
	"steal/vars"
)

type TunHandler struct {
	isRunning bool
}

// Start tun mode in android
func (t *TunHandler) Start() error {
	selectFirstInbound := vars.LoadedConfig.Inbounds[0]

	key := engine.Key{
		MTU:      vars.LoadedConfig.TunMode.MTU,
		Device:   vars.LoadedConfig.TunMode.Name,
		LogLevel: "error",
		Proxy:    fmt.Sprintf("%s://%s", selectFirstInbound.Protocol, selectFirstInbound.Addr),
	}

	engine.Insert(&key)
	if err := engine.Start(); err != nil{
		return err
	}
	
	t.isRunning = true
	return nil
}

func (t *TunHandler) Stop() error {
	if t.isRunning{
		if err := engine.Stop(); err != nil{
			return err
		}
	}
	return nil
}


