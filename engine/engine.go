package engine

import (
	"fmt"
	"steal/api"
	"steal/connection"
	"steal/protocol"
	"steal/structure"
	"steal/tun"
	"steal/vars"
)

type StealEngine struct {
	ConfigPath string
	ConfigData string

	tunMode *tun.TunMode
	apiMode *api.Api
}

func (s *StealEngine) Start() error {
	// Read config
	var readedConf []byte
	var err error
	vars.LoadedConfig = structure.ConfigFormat{}

	if s.ConfigPath != "" {
		if readedConf, err = structure.ReadConfigFile(s.ConfigPath); err != nil {
			return err
		}
	} else if s.ConfigData != "" {
		readedConf = []byte(s.ConfigData)
	} else {
		return fmt.Errorf("failed to read config data")
	}

	if err = vars.LoadedConfig.Unmarshal(readedConf); err != nil {
		return err
	}

	// Hard code, select first outbound
	outbound := vars.LoadedConfig.Outbounds[0]

	// Start inbounds
	for _, inbound := range vars.LoadedConfig.Inbounds {
		if !protocol.IsSupportedProtocol(inbound.Protocol) {
			return fmt.Errorf("[Inbound] config type not supported: %s", inbound.Protocol)
		}
		conn := &connection.Connection{
			Inbound:   &inbound,
			Outbound:  &outbound,
			IsInbound: true,
		}
		go conn.Run()
		vars.ConnectionList = append(vars.ConnectionList, conn)
	}

	// Run outbounds (only used in debug mode)
	if vars.LoadedConfig.DebugMode {
		for _, inbound := range vars.LoadedConfig.Outbounds {
			if !protocol.IsSupportedProtocol(inbound.Protocol) {
				return fmt.Errorf("[Outbound] config type not supported: %s", inbound.Protocol)
			}
			outbound := structure.BaseBound{Protocol: "freedom"}
			conn := &connection.Connection{Inbound: &inbound, Outbound: &outbound}
			go conn.Run()
			vars.ConnectionList = append(vars.ConnectionList, conn)
		}
	}

	if vars.LoadedConfig.TunMode.Start{
		getTun, err := tun.GetTun()
		if err != nil {
			return err
		}
		if err = getTun.Start(); err != nil {
			return err
		}
		s.tunMode = &getTun
	}

	// Start api
	if vars.LoadedConfig.RestApi != ""{
		s.apiMode = &api.Api{}
		if err := s.apiMode.Start(vars.LoadedConfig.RestApi); err != nil{
			return err
		}
	}

	// Clear stored data
	vars.LoadedConfig.Inbounds = nil
	vars.LoadedConfig.Outbounds = nil

	return nil
}

func (s *StealEngine) Stop() error {
	// Stop api
	if s.apiMode != nil {
		(*s.apiMode).Stop()
	}
	// Stop inbounds/outbounds
	for _, conn := range vars.ConnectionList {
		if conn.Listener != nil {
			(*conn.Listener).Close()
		}
	}
	// Stop tun mode
	if s.tunMode != nil {
		(*s.tunMode).Stop()
	}
	return nil
}



func (s *StealEngine) Cleanup() {
	getTun, err := tun.GetTun()
	if err != nil{
		return
	}
	getTun.Stop()
}

