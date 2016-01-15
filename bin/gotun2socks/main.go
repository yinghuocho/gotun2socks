package main

import (
	"flag"
	"log"

	"github.com/yinghuocho/gotun2socks"
)

func main() {
	var tunDevice string
	var localSocksAddr string
	flag.StringVar(&tunDevice, "tun-device", "tun0", "tun device name")
	flag.StringVar(&localSocksAddr, "local-socks-addr", "127.0.0.1:1080", "local SOCKS proxy address")
	flag.Parse()

	f, e := openTunDevice(tunDevice)
	if e != nil {
		log.Fatal(e)
	}
	tun := gotun2socks.New(f, localSocksAddr)
	tun.Run()
}
