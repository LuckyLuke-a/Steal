package vars

import (
	"steal/connection"
	"steal/structure"
	"sync"
)

var (
	// Store all active connections
	ConnectionList []*connection.Connection

	mutex sync.Mutex
	// Store config.json data temporary
	LoadedConfig structure.ConfigFormat
)

func AddUser(inboundTag, userID string) {
	mutex.Lock()
	defer mutex.Unlock()
	err := false
	for _, conn := range ConnectionList {
		if inboundTag == conn.Inbound.Tag {
			for _, user := range conn.Inbound.Users {
				if user.ID == userID {
					err = true
					break
				}
			}
			if !err {
				conn.Inbound.Users = append(conn.Inbound.Users, &structure.User{ID: userID, SystemID: userID})
			}
			break
		}
	}
}
