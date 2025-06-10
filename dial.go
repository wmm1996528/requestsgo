package requests

import (
	"bufio"
	"context"
	crand "crypto/rand"
	"crypto/tls"
	"encoding/binary"
	"errors"

	"fmt"
	"io"
	"math"
	"math/big"
	rand2 "math/rand"
	"math/rand/v2"
	"net"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/gospider007/gtls"
	"github.com/gospider007/ja3"
	"github.com/gospider007/tools"
	utls "github.com/refraction-networking/utls"
)

type msgClient struct {
	time time.Time
	ip   net.IP
}
type DialOption struct {
	LocalAddr   *net.TCPAddr //network card ip
	Dns         *net.UDPAddr
	GetAddrType func(host string) gtls.AddrType
	DialTimeout time.Duration
	KeepAlive   time.Duration
	AddrType    gtls.AddrType //first ip type
}
type dialer interface {
	DialContext(ctx context.Context, network string, address string) (net.Conn, error)
	LookupIPAddr(ctx context.Context, host string) ([]net.IPAddr, error)
}

// 自定义dialer
type Dialer struct {
	dnsIpData sync.Map
}
type myDialer struct {
	dialer *net.Dialer
}

func (d *myDialer) DialContext(ctx context.Context, network string, address string) (net.Conn, error) {
	return d.dialer.DialContext(ctx, network, address)
}
func (d *myDialer) LookupIPAddr(ctx context.Context, host string) ([]net.IPAddr, error) {
	return d.dialer.Resolver.LookupIPAddr(ctx, host)
}

func newDialer(option DialOption) dialer {
	if option.KeepAlive == 0 {
		option.KeepAlive = time.Second * 5
	}
	if option.DialTimeout == 0 {
		option.DialTimeout = time.Second * 5
	}
	var dialer myDialer
	dialer.dialer = &net.Dialer{
		Timeout:       option.DialTimeout,
		KeepAlive:     option.KeepAlive,
		LocalAddr:     option.LocalAddr,
		FallbackDelay: time.Nanosecond,
		Control:       Control,
		KeepAliveConfig: net.KeepAliveConfig{
			Enable:   true,
			Idle:     time.Second * 5,
			Interval: time.Second * 5,
			Count:    3,
		},
	}
	if option.LocalAddr != nil {
		dialer.dialer.LocalAddr = option.LocalAddr
	}
	if option.Dns != nil {
		dialer.dialer.Resolver = &net.Resolver{
			PreferGo: true,
			Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
				return (&net.Dialer{
					Timeout:   option.DialTimeout,
					KeepAlive: option.KeepAlive,
				}).DialContext(ctx, network, option.Dns.String())
			},
		}
	}
	dialer.dialer.SetMultipathTCP(true)
	return &dialer
}
func (obj *Dialer) dialContext(ctx *Response, network string, addr Address, isProxy bool) (net.Conn, error) {
	var err error
	if addr.Port == 0 {
		return nil, errors.New("port is nil")
	}
	if addr.IP == nil {
		addr.IP, err = obj.loadHost(ctx.Context(), addr.Host, ctx.option.DialOption)
	}
	if ctx.option != nil && ctx.option.Logger != nil {
		if isProxy {
			ctx.option.Logger(Log{
				Id:   ctx.requestId,
				Time: time.Now(),
				Type: LogType_ProxyDNSLookup,
				Msg:  addr.Host,
			})
		} else {
			ctx.option.Logger(Log{
				Id:   ctx.requestId,
				Time: time.Now(),
				Type: LogType_DNSLookup,
				Msg:  addr.Host,
			})
		}
	}
	if err != nil {
		return nil, err
	}
	con, err := newDialer(ctx.option.DialOption).DialContext(ctx.Context(), network, addr.String())
	if ctx.option != nil && ctx.option.Logger != nil {
		if isProxy {
			ctx.option.Logger(Log{
				Id:   ctx.requestId,
				Time: time.Now(),
				Type: LogType_ProxyTCPConnect,
				Msg:  addr,
			})
		} else {
			ctx.option.Logger(Log{
				Id:   ctx.requestId,
				Time: time.Now(),
				Type: LogType_TCPConnect,
				Msg:  addr,
			})
		}
	}
	if err == nil && addr.Compression != "" {
		return NewCompressionConn(addr.Compression, con)
	}
	return con, err
}
func (obj *Dialer) DialContext(ctx *Response, network string, addr Address) (net.Conn, error) {
	conn, err := obj.dialContext(ctx, network, addr, false)
	if err != nil {
		err = tools.WrapError(err, "DialContext error")
	}
	return conn, err
}
func (obj *Dialer) ProxyDialContext(ctx *Response, network string, addr Address) (net.Conn, error) {
	conn, err := obj.dialContext(ctx, network, addr, true)
	if err != nil {
		err = tools.WrapError(err, "ProxyDialContext error")
	}
	return conn, err
}
func (obj *Dialer) DialProxyContext(ctx *Response, network string, proxyTlsConfig *tls.Config, proxyUrls ...Address) (net.PacketConn, net.Conn, error) {
	proxyLen := len(proxyUrls)
	if proxyLen < 2 {
		return nil, nil, errors.New("proxyUrls is nil")
	}
	var conn net.Conn
	var err error
	var packCon net.PacketConn
	for index := range proxyLen - 1 {
		oneProxy := proxyUrls[index]
		remoteUrl := proxyUrls[index+1]
		if index == 0 {
			if conn, err = obj.dialProxyContext(ctx, network, oneProxy); err != nil {
				break
			}
		}
		packCon, conn, err = obj.verifyProxyToRemote(ctx, conn, proxyTlsConfig, oneProxy, remoteUrl, index == proxyLen-2, true)
	}
	return packCon, conn, err
}
func (obj *Dialer) dialProxyContext(ctx *Response, network string, proxyUrl Address) (net.Conn, error) {
	return obj.ProxyDialContext(ctx, network, proxyUrl)
}
func (obj *Dialer) verifyProxyToRemote(ctx *Response, conn net.Conn, proxyTlsConfig *tls.Config, proxyAddress Address, remoteAddress Address, isLast bool, forceHttp1 bool) (net.PacketConn, net.Conn, error) {
	var err error
	var packCon net.PacketConn
	if proxyAddress.Scheme == "https" {
		if conn, err = obj.addTls(ctx.Context(), conn, proxyAddress.Host, proxyTlsConfig, forceHttp1); err != nil {
			return packCon, conn, err
		}
		if ctx.option.Logger != nil {
			ctx.option.Logger(Log{
				Id:   ctx.requestId,
				Time: time.Now(),
				Type: LogType_ProxyTLSHandshake,
				Msg:  proxyAddress.String(),
			})
		}
	}
	done := make(chan struct{})
	go func() {
		switch proxyAddress.Scheme {
		case "http", "https":
			err = obj.clientVerifyHttps(ctx.Context(), conn, proxyAddress, remoteAddress)
			if ctx.option.Logger != nil {
				ctx.option.Logger(Log{
					Id:   ctx.requestId,
					Time: time.Now(),
					Type: LogType_ProxyConnectRemote,
					Msg:  remoteAddress.String(),
				})
			}
		case "socks5":
			if isLast && ctx.option.ForceHttp3 {
				packCon, err = obj.verifyUDPSocks5(ctx, conn, proxyAddress, remoteAddress)
			} else {
				err = obj.verifyTCPSocks5(ctx, conn, proxyAddress, remoteAddress)
			}
			if ctx.option.Logger != nil {
				ctx.option.Logger(Log{
					Id:   ctx.requestId,
					Time: time.Now(),
					Type: LogType_ProxyConnectRemote,
					Msg:  remoteAddress.String(),
				})
			}
		}
		close(done)
	}()
	select {
	case <-ctx.Context().Done():
		return packCon, conn, context.Cause(ctx.Context())
	case <-done:
		if err != nil {
			err = tools.WrapError(err, "verifyProxyToRemote error")
		}
		return packCon, conn, err
	}
}

func (obj *Dialer) loadHost(ctx context.Context, host string, option DialOption) (net.IP, error) {
	msgDataAny, ok := obj.dnsIpData.Load(host)
	if ok {
		msgdata := msgDataAny.(msgClient)
		if time.Since(msgdata.time) < time.Second*60*5 {
			return msgdata.ip, nil
		}
	}
	ip, ipInt := gtls.ParseHost(host)
	if ipInt != 0 {
		return ip, nil
	}
	var addrType gtls.AddrType
	if option.AddrType != 0 {
		addrType = option.AddrType
	} else if option.GetAddrType != nil {
		addrType = option.GetAddrType(host)
	}
	ips, err := newDialer(option).LookupIPAddr(ctx, host)
	if err != nil {
		return net.IP{}, err
	}
	if ip, err = obj.addrToIp(host, ips, addrType); err != nil {
		return nil, err
	}
	return ip, nil
}
func readUdpAddr(r io.Reader) (Address, error) {
	var UdpAddress Address
	var addrType [1]byte
	var err error
	if _, err = r.Read(addrType[:]); err != nil {
		return UdpAddress, err
	}
	switch addrType[0] {
	case ipv4Address:
		addr := make(net.IP, net.IPv4len)
		if _, err := io.ReadFull(r, addr); err != nil {
			return UdpAddress, err
		}
		UdpAddress.IP = addr
	case ipv6Address:
		addr := make(net.IP, net.IPv6len)
		if _, err := io.ReadFull(r, addr); err != nil {
			return UdpAddress, err
		}
		UdpAddress.IP = addr
	case fqdnAddress:
		if _, err := r.Read(addrType[:]); err != nil {
			return UdpAddress, err
		}
		addrLen := int(addrType[0])
		fqdn := make([]byte, addrLen)
		if _, err := io.ReadFull(r, fqdn); err != nil {
			return UdpAddress, err
		}
		UdpAddress.Host = string(fqdn)
	default:
		return UdpAddress, errors.New("invalid atyp")
	}
	var port [2]byte
	if _, err := io.ReadFull(r, port[:]); err != nil {
		return UdpAddress, err
	}
	UdpAddress.Port = int(binary.BigEndian.Uint16(port[:]))
	return UdpAddress, nil
}
func (obj *Dialer) ReadUdpAddr(ctx context.Context, r io.Reader, option DialOption) (Address, error) {
	udpAddress, err := readUdpAddr(r)
	if err != nil {
		return udpAddress, err
	}
	if udpAddress.Host != "" {
		udpAddress.IP, err = obj.loadHost(ctx, udpAddress.Host, option)
	}
	return udpAddress, err
}
func (obj *Dialer) addrToIp(host string, ips []net.IPAddr, addrType gtls.AddrType) (net.IP, error) {
	ip, err := obj.lookupIPAddr(ips, addrType)
	if err != nil {
		return ip, tools.WrapError(err, "addrToIp error,lookupIPAddr")
	}
	obj.dnsIpData.Store(host, msgClient{time: time.Now(), ip: ip})
	return ip, nil
}
func (obj *Dialer) verifySocks5(ctx *Response, conn net.Conn, network string, proxyAddr Address, remoteAddr Address) (proxyAddress Address, err error) {
	err = obj.verifySocks5Auth(conn, proxyAddr)
	if err != nil {
		err = tools.WrapError(err, "verifySocks5Auth error")
		return
	}
	err = obj.writeCmd(conn, network)
	if err != nil {
		err = tools.WrapError(err, "write cmd error")
		return
	}
	remoteAddr.NetWork = network
	err = WriteUdpAddr(conn, remoteAddr)
	if err != nil {
		err = tools.WrapError(err, "write addr error")
		return
	}
	readCon := make([]byte, 3)
	if _, err = io.ReadFull(conn, readCon); err != nil {
		err = tools.WrapError(err, "read socks5 proxy error")
		return
	}
	if readCon[0] != 5 {
		err = errors.New("socks version error")
		return
	}
	if readCon[1] != 0 {
		err = errors.New("socks conn error")
		return
	}
	proxyAddress, err = obj.ReadUdpAddr(ctx.Context(), conn, ctx.option.DialOption)
	return
}
func (obj *Dialer) verifyTCPSocks5(ctx *Response, conn net.Conn, proxyAddr Address, remoteAddr Address) (err error) {
	_, err = obj.verifySocks5(ctx, conn, "tcp", proxyAddr, remoteAddr)
	return
}
func (obj *Dialer) verifyUDPSocks5(ctx *Response, conn net.Conn, proxyAddr Address, remoteAddr Address) (wrapConn net.PacketConn, err error) {
	remoteAddr.NetWork = "udp"
	proxyAddress, err := obj.verifySocks5(ctx, conn, "udp", proxyAddr, remoteAddr)
	if err != nil {
		return
	}
	var listener net.ListenConfig
	wrapConn, err = listener.ListenPacket(ctx.Context(), "udp", ":0")
	if err != nil {
		return
	}
	var cnl context.CancelFunc
	udpCtx, cnl := context.WithCancel(context.TODO())
	wrapConn = NewUDPConn(udpCtx, wrapConn, &net.UDPAddr{IP: proxyAddress.IP, Port: proxyAddress.Port}, remoteAddr)
	go func() {
		io.Copy(io.Discard, conn)
		cnl()
	}()
	return
}
func (obj *Dialer) writeCmd(conn net.Conn, network string) (err error) {
	var cmd byte
	switch network {
	case "tcp":
		cmd = 1
	case "udp":
		cmd = 3
	default:
		return errors.New("not support network")
	}
	_, err = conn.Write([]byte{5, cmd, 0})
	return
}
func (obj *Dialer) verifySocks5Auth(conn net.Conn, proxyAddr Address) (err error) {
	if _, err = conn.Write([]byte{5, 2, 0, 2}); err != nil {
		return
	}
	readCon := make([]byte, 2)
	if _, err = io.ReadFull(conn, readCon); err != nil {
		return
	}
	switch readCon[1] {
	case 2:
		if _, err = conn.Write(append(
			append(
				[]byte{1, byte(len(proxyAddr.User))},
				tools.StringToBytes(proxyAddr.User)...,
			),
			append(
				[]byte{byte(len(proxyAddr.Password))},
				tools.StringToBytes(proxyAddr.Password)...,
			)...,
		)); err != nil {
			return tools.WrapError(err, "socks5 user or password error")
		}
		if _, err = io.ReadFull(conn, readCon); err != nil {
			return
		}
		switch readCon[1] {
		case 0:
		default:
			err = errors.New("socks5 auth error")
		}
	case 0:
	default:
		err = errors.New("not support auth format")
	}
	return
}
func (obj *Dialer) lookupIPAddr(ips []net.IPAddr, addrType gtls.AddrType) (net.IP, error) {
	for _, ipAddr := range ips {
		if ipType := gtls.ParseIp(ipAddr.IP); ipType == gtls.Ipv4 || ipType == gtls.Ipv6 {
			if addrType == gtls.AutoIp || addrType == ipType {
				return ipAddr.IP, nil
			}
		}
	}
	for _, ipAddr := range ips {
		if ipType := gtls.ParseIp(ipAddr.IP); ipType == gtls.Ipv4 || ipType == gtls.Ipv6 {
			return ipAddr.IP, nil
		}
	}
	return nil, errors.New("dns parse host error")
}
func (obj *Dialer) addTls(ctx context.Context, conn net.Conn, host string, tlsConfig *tls.Config, forceHttp1 bool) (*tls.Conn, error) {
	var tlsConn *tls.Conn
	tlsConfig.ServerName = gtls.GetServerName(host)
	if forceHttp1 {
		tlsConfig.NextProtos = []string{"http/1.1"}
	} else {
		tlsConfig.NextProtos = []string{"h2", "http/1.1"}
	}
	tlsConn = tls.Client(conn, tlsConfig)
	return tlsConn, tlsConn.HandshakeContext(ctx)
}
func (obj *Dialer) addJa3Tls(ctx context.Context, conn net.Conn, host string, spec *ja3.Spec, tlsConfig *utls.Config, forceHttp1 bool) (*utls.UConn, error) {
	//spec.CipherSuites = randomCipher(spec.CipherSuites)
	//spec.Extensions = ShuffleChromeTLSExtensions(spec.Extensions)

	return specClient.Client(ctx, conn, spec, tlsConfig, gtls.GetServerName(host), forceHttp1)
}
func (obj *Dialer) addJa3TlsByUtls(ctx context.Context, conn net.Conn, host string, tlsSpec utls.ClientHelloSpec, tlsConfig *utls.Config, forceHttp1 bool) (*utls.UConn, error) {
	//spec.CipherSuites = randomCipher(spec.CipherSuites)
	//spec.Extensions = ShuffleChromeTLSExtensions(spec.Extensions)

	return specClient.ClientUtls(ctx, conn, tlsSpec, tlsConfig, gtls.GetServerName(host), forceHttp1)
}
func randomCipher(suites []uint16) []uint16 {
	cipheres := make([]uint16, len(suites))
	cipheres[0] = suites[0]
	t := suites[1:]
	rand.Shuffle(len(t), func(i, j int) {
		t[i], t[j] = t[j], t[i]
	})
	copy(cipheres[1:], t)
	return cipheres
}
func (obj *Dialer) Socks5TcpProxy(ctx *Response, proxyAddr Address, remoteAddr Address) (conn net.Conn, err error) {
	if conn, err = obj.DialContext(ctx, "tcp", proxyAddr); err != nil {
		return
	}
	defer func() {
		if err != nil && conn != nil {
			conn.Close()
		}
	}()
	didVerify := make(chan struct{})
	go func() {
		defer close(didVerify)
		err = obj.verifyTCPSocks5(ctx, conn, proxyAddr, remoteAddr)
	}()
	select {
	case <-ctx.Context().Done():
		return conn, context.Cause(ctx.Context())
	case <-didVerify:
		return
	}
}
func (obj *Dialer) Socks5UdpProxy(ctx *Response, proxyAddress Address, remoteAddress Address) (udpConn net.PacketConn, err error) {
	conn, err := obj.ProxyDialContext(ctx, "tcp", proxyAddress)
	if err != nil {
		return nil, err
	}
	defer func() {
		if err != nil {
			if conn != nil {
				conn.Close()
			}
			if udpConn != nil {
				udpConn.Close()
			}
		}
	}()
	didVerify := make(chan struct{})
	go func() {
		defer close(didVerify)
		udpConn, err = obj.verifyUDPSocks5(ctx, conn, proxyAddress, remoteAddress)
		if ctx.option.Logger != nil {
			ctx.option.Logger(Log{
				Id:   ctx.requestId,
				Time: time.Now(),
				Type: LogType_ProxyConnectRemote,
				Msg:  remoteAddress.String(),
			})
		}
	}()
	select {
	case <-ctx.Context().Done():
		return udpConn, context.Cause(ctx.Context())
	case <-didVerify:
		return
	}
}
func (obj *Dialer) clientVerifyHttps(ctx context.Context, conn net.Conn, proxyAddress Address, remoteAddress Address) (err error) {
	hdr := make(http.Header)
	if proxyAddress.User != "" && proxyAddress.Password != "" {
		hdr.Set("Proxy-Authorization", "Basic "+tools.Base64Encode(proxyAddress.User+":"+proxyAddress.Password))
	}
	connectReq, err := NewRequestWithContext(ctx, http.MethodConnect, &url.URL{Opaque: remoteAddress.String()}, nil)
	if err != nil {
		return err
	}
	connectReq.Header = hdr
	connectReq.Host = remoteAddress.Host
	if err = connectReq.Write(conn); err != nil {
		return err
	}
	resp, err := http.ReadResponse(bufio.NewReader(conn), connectReq)
	if err != nil {
		return err
	}
	if resp.StatusCode != 200 {
		return errors.New(resp.Status)
	}
	return
}

func ShuffleChromeTLSExtensions(exts []ja3.Extension) []ja3.Extension {
	// unshufCheck checks if the exts[idx] is a GREASE/padding/pre_shared_key extension,
	// and returns true on success. For these extensions are considered positionally invariant.
	var skipShuf = func(idx int, exts []ja3.Extension) bool {
		switch exts[idx].Type {
		//*UtlsGREASEExtension, *UtlsPaddingExtension,
		case 0x0A0A, 0x1A1A, 0x2A2A, 0x3A3A, 0x4A4A, 0x5A5A, 0x6A6A, 0x7A7A, 0x8A8A, 0x9A9A, 0xAAAA, 0xBABA, 0xCACA, 0xDADA, 0xEAEA, 0xFAFA, 41:
			return true
		default:
			return false
		}
	}

	// Shuffle other extensions
	randInt64, err := crand.Int(crand.Reader, big.NewInt(math.MaxInt64))
	if err != nil {
		// warning: random could be deterministic
		rand2.Shuffle(len(exts), func(i, j int) {
			if skipShuf(i, exts) || skipShuf(j, exts) {
				return // do not shuffle some of the extensions
			}
			exts[i], exts[j] = exts[j], exts[i]
		})
		fmt.Println("Warning: failed to use a cryptographically secure random number generator. The shuffle can be deterministic.")
	} else {
		rand2.New(rand2.NewSource(randInt64.Int64())).Shuffle(len(exts), func(i, j int) {
			if skipShuf(i, exts) || skipShuf(j, exts) {
				return // do not shuffle some of the extensions
			}
			exts[i], exts[j] = exts[j], exts[i]
		})
	}

	return exts
}
