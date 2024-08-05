package main

import (
	"flag"
	"log"
	"os"
	"os/signal"
	"syscall"
	"steal/engine"
)


func main() {
	configPath := flag.String("c", "config.json", "path of config.json")
	cleanup := flag.Bool("cleanup", false, "cleanup tun mode rules on windows client")
    flag.Parse()


	engine := engine.StealEngine{ConfigPath: *configPath}

	if *cleanup{
		engine.Cleanup()
		return
	}
	if err := engine.Start(); err != nil{
		log.Fatal(err)
	}

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP, syscall.SIGQUIT)
	<-sig
	
	engine.Stop()
}
