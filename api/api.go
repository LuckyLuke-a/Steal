package api

import (
	"encoding/json"
	"log"
	"net/http"
	"steal/vars"
)

type StatsModel struct {
	SystemID      string  `json:"system_id"`
	UploadStats   uintptr `json:"upload_stats"`
	DownloadStats uintptr `json:"download_stats"`
	IsInbound     bool    `json:"is_inbound"`
}

type Response struct {
	Status        string  `json:"status"`
}

type Api struct {
	server *http.Server
}

func (a *Api) Start(addr string) error {
	mux := http.NewServeMux()
	mux.HandleFunc("/stats", a.getStats)
	mux.HandleFunc("/addUser", a.addUser)
	a.server = &http.Server{Addr: addr, Handler: mux}
	go func(){
		if err := a.server.ListenAndServe(); err != nil{
			log.Println(err)
		}	
	}()
	return nil
}


func (a *Api) Stop() error {
	if a.server != nil{
		return (*a.server).Close()
	}
	return nil
}

func (a *Api) addUser(w http.ResponseWriter, r *http.Request) {
	inboundTag := r.URL.Query().Get("inboundTag")
	userId := r.URL.Query().Get("userId")
	resp := Response{Status: "ok"}
	defer func(){
		marshalJson, err := json.Marshal(resp)
		if err != nil{
			return
		}
		w.Header().Add("content-type", "application/json")
		w.Write(marshalJson)
	}()
	if inboundTag == "" || userId == "" {
		resp.Status = "fail"
		return
	}
	vars.AddUser(inboundTag, userId)
}

func (a *Api) getStats(w http.ResponseWriter, r *http.Request) {
	var allStats []StatsModel
	for _, conn := range vars.ConnectionList {
		for _, inboundUser := range conn.Inbound.Users {
			allStats = append(allStats, StatsModel{
				SystemID:      inboundUser.SystemID,
				UploadStats:   inboundUser.UploadStats.Swap(0),
				DownloadStats: inboundUser.DownloadStats.Swap(0),
				IsInbound:     true,
			})
		}
		for _, outboundUser := range conn.Outbound.Users {
			allStats = append(allStats, StatsModel{
				SystemID:      outboundUser.SystemID,
				UploadStats:   outboundUser.UploadStats.Swap(0),
				DownloadStats: outboundUser.DownloadStats.Swap(0),
			})
		}

	}
	resultMap := map[string][]StatsModel{"users": allStats}
	marshalJson, err := json.Marshal(resultMap)
	if err != nil {
		return
	}
	w.Header().Add("content-type", "application/json")
	w.Write(marshalJson)
}
