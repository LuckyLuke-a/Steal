//go:build (linux && amd64) || (linux && arm64)

package fdbased

import (
	"fmt"

	"gvisor.dev/gvisor/pkg/tcpip/link/fdbased"

	"steal/tun/tun2socks/core/device"
)

func open(fd int, mtu uint32, offset int) (device.Device, error) {
	f := &FD{fd: fd, mtu: mtu}

	ep, err := fdbased.New(&fdbased.Options{
		FDs: []int{fd},
		MTU: mtu,
		// TUN only, ignore ethernet header.
		EthernetHeader: false,
	})
	if err != nil {
		return nil, fmt.Errorf("create endpoint: %w", err)
	}
	f.LinkEndpoint = ep

	return f, nil
}
