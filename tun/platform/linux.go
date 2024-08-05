//go:build linux && !android

package platform

import (
	"fmt"
)


type TunHandler struct{
}


func (t *TunHandler) Start() error{
	return fmt.Errorf("not implemented")
}

func (t *TunHandler) Stop() error{
	return fmt.Errorf("not implemented")
}

