package main

import (
	"flag"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/yinghuocho/gotun2socks"
)

func main() {
	var tunDevice string
	var tunAddr string
	var tunMask string
	var tunGW string
	var localSocksAddr string
	var dnsServers string
	var publicOnly bool
	var enableDnsCache bool
	flag.StringVar(&tunDevice, "tun-device", "tun0", "tun device name")
	flag.StringVar(&tunAddr, "tun-address", "10.0.0.2", "tun device address")
	flag.StringVar(&tunMask, "tun-mask", "255.255.255.0", "tun device netmask")
	flag.StringVar(&tunGW, "tun-gw", "10.0.0.1", "tun device gateway")
	flag.StringVar(&localSocksAddr, "local-socks-addr", "127.0.0.1:1080", "local SOCKS proxy address")
	flag.BoolVar(&publicOnly, "public-only", false, "only forward packets with public address destination")
	flag.StringVar(&dnsServers, "dns-server", "", "dns servers, enable quick release of DNS sessions, format: server1,server2...")
	flag.BoolVar(&enableDnsCache, "enable-dns-cache", false, "enable local dns cache if specified")
	flag.Parse()

	f, e := openTunDevice(tunDevice, tunAddr, tunGW, tunMask)
	if e != nil {
		log.Fatal(e)
	}
	tun := gotun2socks.New(f, tunAddr, tunGW, localSocksAddr, strings.Split(dnsServers, ","), publicOnly, enableDnsCache)

	ch := make(chan os.Signal, 1)
	signal.Notify(ch,
		syscall.SIGHUP,
		syscall.SIGINT,
		syscall.SIGTERM,
		syscall.SIGQUIT)
	go func() {
		s := <-ch
		switch s {
		default:
			tun.Stop()
		}
	}()

	tun.Run()
}
