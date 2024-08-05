package engine

import (
	"net/url"

	"github.com/gorilla/schema"
	"golang.org/x/sys/windows"
	wun "golang.zx2c4.com/wireguard/tun"

	"steal/tun/tun2socks/core/device"
	"steal/tun/tun2socks/core/device/tun"
	"steal/tun/tun2socks/internal/version"
)

func init() {
	wun.WintunTunnelType = version.Name
}

func parseTUN(u *url.URL, mtu uint32) (device.Device, error) {
	opts := struct {
		GUID string
	}{}
	if err := schema.NewDecoder().Decode(&opts, u.Query()); err != nil {
		return nil, err
	}
	if opts.GUID != "" {
		guid, err := windows.GUIDFromString(opts.GUID)
		if err != nil {
			return nil, err
		}
		wun.WintunStaticRequestedGUID = &guid
	}
	return tun.Open(u.Host, mtu)
}
