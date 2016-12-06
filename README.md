# gotun2socks

A Golang implementation of tun2socks, including a library and a binary program. 

The binary program works on Linux, OS X and Windows. 

## Usage

Windows users need to install TAP-windows driver first. 

The binary program will create tun/tap device, config its IP address. On Windows, it also configs DNS resolvers of the opened tun/tap device. 

Users need to change routing table so that packets are sent through the tun/tap device. Generaly the process includes changing default route to the tun/tap device, and exclude IP addresses of remote servers to go through the original network device so that traffic forwarded from local SOCKS5 proxy to remote servers would not loop back. See <a href="https://code.google.com/p/badvpn/wiki/tun2socks"> Tun2Socks Introduction </a> for how to change routing table. Linux and OS X users may also need to change system DNS resolvers in case the resolvers are not accessible by remote servers. 

## UDP forwarding

This implementation forwards UDP using standard SOCKS5 UDP request/reply. Thus to make UDP-based protocols (such as DNS) work, it needs to be chained with a UDP-enabled SOCKS5 proxy.  


## Credits

- https://github.com/google/gopacket
- https://github.com/ambrop72/badvpn/
- https://github.com/songgao/water
- https://github.com/FlexibleBroadband/tun-go

