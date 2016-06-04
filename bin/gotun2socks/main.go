package main

import (
	"flag"
	"log"
	"strings"

	"github.com/yinghuocho/gotun2socks"
)

func main() {
	var tunDevice string
	var localSocksAddr string
	var dnsServers string
	var publicOnly bool
	flag.StringVar(&tunDevice, "tun-device", "tun0", "tun device name")
	flag.StringVar(&localSocksAddr, "local-socks-addr", "127.0.0.1:1080", "local SOCKS proxy address")
	flag.BoolVar(&publicOnly, "public-only", false, "only forward packets with public address destination")
	flag.StringVar(&dnsServers, "dns-server", "", "dns servers, enable local dns cache if specified, format: server1,server2...")
	flag.Parse()

	f, e := openTunDevice(tunDevice)
	if e != nil {
		log.Fatal(e)
	}
	tun := gotun2socks.New(f, localSocksAddr, strings.Split(dnsServers, ","), publicOnly)
	tun.Run()
}
