// dnstt-client is the client end of a DNS tunnel.
//
// Usage:
//
//	dnstt-client doh  [--pubkey-file FILE | --pubkey HEX] [--utls SPEC] DOMAIN LOCALADDR RESOLVER_URL
//	dnstt-client dot  [--pubkey-file FILE | --pubkey HEX] [--utls SPEC] DOMAIN LOCALADDR RESOLVER_ADDR
//	dnstt-client udp  [--pubkey-file FILE | --pubkey HEX] DOMAIN LOCALADDR RESOLVER_ADDR
//
// Examples:
//
//	dnstt-client doh --pubkey-file server.pub t.example.com 127.0.0.1:7000 https://resolver.example/dns-query
//	dnstt-client dot --pubkey-file server.pub t.example.com 127.0.0.1:7000 resolver.example:853
//	dnstt-client udp --pubkey-file server.pub t.example.com 127.0.0.1:7000 resolver.example:53
//
// The legacy single-flag syntax is also supported for backward compatibility:
//
//	dnstt-client -doh URL [-pubkey-file FILE|-pubkey HEX] [-utls SPEC] DOMAIN LOCALADDR
//	dnstt-client -dot ADDR [-pubkey-file FILE|-pubkey HEX] [-utls SPEC] DOMAIN LOCALADDR
//	dnstt-client -udp ADDR [-pubkey-file FILE|-pubkey HEX] DOMAIN LOCALADDR
package main

import (
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/spf13/cobra"
	utls "github.com/refraction-networking/utls"
	"github.com/xtaci/kcp-go/v5"
	"github.com/xtaci/smux"
	"www.bamsoftware.com/git/dnstt.git/dns"
	"www.bamsoftware.com/git/dnstt.git/noise"
	"www.bamsoftware.com/git/dnstt.git/turbotunnel"
)

// smux streams will be closed after this much time without receiving data.
const idleTimeout = 2 * time.Minute

// dnsNameCapacity returns the number of bytes remaining for encoded data after
// including domain in a DNS name.
func dnsNameCapacity(domain dns.Name) int {
	// Names must be 255 octets or shorter in total length.
	// https://tools.ietf.org/html/rfc1035#section-2.3.4
	capacity := 255
	// Subtract the length of the null terminator.
	capacity -= 1
	for _, label := range domain {
		// Subtract the length of the label and the length octet.
		capacity -= len(label) + 1
	}
	// Each label may be up to 63 bytes long and requires 64 bytes to
	// encode.
	capacity = capacity * 63 / 64
	// Base32 expands every 5 bytes to 8.
	capacity = capacity * 5 / 8
	return capacity
}

// readKeyFromFile reads a key from a named file.
func readKeyFromFile(filename string) ([]byte, error) {
	f, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return noise.ReadKey(f)
}

// sampleUTLSDistribution parses a weighted uTLS Client Hello ID distribution
// string of the form "3*Firefox,2*Chrome,1*iOS", matches each label to a
// utls.ClientHelloID from utlsClientHelloIDMap, and randomly samples one
// utls.ClientHelloID from the distribution.
func sampleUTLSDistribution(spec string) (*utls.ClientHelloID, error) {
	weights, labels, err := parseWeightedList(spec)
	if err != nil {
		return nil, err
	}
	ids := make([]*utls.ClientHelloID, 0, len(labels))
	for _, label := range labels {
		var id *utls.ClientHelloID
		if label == "none" {
			id = nil
		} else {
			id = utlsLookup(label)
			if id == nil {
				return nil, fmt.Errorf("unknown TLS fingerprint %q", label)
			}
		}
		ids = append(ids, id)
	}
	return ids[sampleWeighted(weights)], nil
}

func handle(local *net.TCPConn, sess *smux.Session, conv uint32) error {
	stream, err := sess.OpenStream()
	if err != nil {
		return fmt.Errorf("session %08x opening stream: %v", conv, err)
	}
	defer func() {
		log.Printf("end stream %08x:%d", conv, stream.ID())
		stream.Close()
	}()
	log.Printf("begin stream %08x:%d", conv, stream.ID())

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		_, err := io.Copy(stream, local)
		if err == io.EOF {
			// smux Stream.Write may return io.EOF.
			err = nil
		}
		if err != nil && !errors.Is(err, io.ErrClosedPipe) {
			log.Printf("stream %08x:%d copy stream←local: %v", conv, stream.ID(), err)
		}
		local.CloseRead()
		stream.Close()
	}()
	go func() {
		defer wg.Done()
		_, err := io.Copy(local, stream)
		if err == io.EOF {
			// smux Stream.WriteTo may return io.EOF.
			err = nil
		}
		if err != nil && !errors.Is(err, io.ErrClosedPipe) {
			log.Printf("stream %08x:%d copy local←stream: %v", conv, stream.ID(), err)
		}
		local.CloseWrite()
	}()
	wg.Wait()

	return err
}

func run(pubkey []byte, domain dns.Name, localAddr *net.TCPAddr, remoteAddr net.Addr, pconn net.PacketConn) error {
	defer pconn.Close()

	ln, err := net.ListenTCP("tcp", localAddr)
	if err != nil {
		return fmt.Errorf("opening local listener: %v", err)
	}
	defer ln.Close()

	mtu := dnsNameCapacity(domain) - 8 - 1 - numPadding - 1 // clientid + padding length prefix + padding + data length prefix
	if mtu < 80 {
		return fmt.Errorf("domain %s leaves only %d bytes for payload", domain, mtu)
	}
	log.Printf("effective MTU %d", mtu)

	// Open a KCP conn on the PacketConn.
	conn, err := kcp.NewConn2(remoteAddr, nil, 0, 0, pconn)
	if err != nil {
		return fmt.Errorf("opening KCP conn: %v", err)
	}
	defer func() {
		log.Printf("end session %08x", conn.GetConv())
		conn.Close()
	}()
	log.Printf("begin session %08x", conn.GetConv())
	// Permit coalescing the payloads of consecutive sends.
	conn.SetStreamMode(true)
	// Disable the dynamic congestion window (limit only by the maximum of
	// local and remote static windows).
	conn.SetNoDelay(
		0, // default nodelay
		0, // default interval
		0, // default resend
		1, // nc=1 => congestion window off
	)
	conn.SetWindowSize(turbotunnel.QueueSize/2, turbotunnel.QueueSize/2)
	if rc := conn.SetMtu(mtu); !rc {
		panic(rc)
	}

	// Put a Noise channel on top of the KCP conn.
	rw, err := noise.NewClient(conn, pubkey)
	if err != nil {
		return err
	}

	// Start a smux session on the Noise channel.
	smuxConfig := smux.DefaultConfig()
	smuxConfig.Version = 2
	smuxConfig.KeepAliveTimeout = idleTimeout
	smuxConfig.MaxStreamBuffer = 1 * 1024 * 1024 // default is 65536
	sess, err := smux.Client(rw, smuxConfig)
	if err != nil {
		return fmt.Errorf("opening smux session: %v", err)
	}
	defer sess.Close()

	for {
		local, err := ln.Accept()
		if err != nil {
			if err, ok := err.(net.Error); ok && err.Temporary() {
				continue
			}
			return err
		}
		go func() {
			defer local.Close()
			err := handle(local.(*net.TCPConn), sess, conn.GetConv())
			if err != nil {
				log.Printf("handle: %v", err)
			}
		}()
	}
}

// utlsFingerprints returns a formatted list of known TLS fingerprint names.
func utlsFingerprints() string {
	labels := make([]string, 0, len(utlsClientHelloIDMap)+1)
	labels = append(labels, "none")
	for _, entry := range utlsClientHelloIDMap {
		labels = append(labels, entry.Label)
	}
	var sb strings.Builder
	i := 0
	for i < len(labels) {
		fmt.Fprintf(&sb, "  %s", labels[i])
		w := 2 + len(labels[i])
		i++
		for i < len(labels) && w+1+len(labels[i]) <= 72 {
			fmt.Fprintf(&sb, " %s", labels[i])
			w += 1 + len(labels[i])
			i++
		}
		sb.WriteString("\n")
	}
	return sb.String()
}

// parsePubkey resolves a public key from --pubkey-file or --pubkey flags.
func parsePubkey(pubkeyFilename, pubkeyString string) ([]byte, error) {
	if pubkeyFilename != "" && pubkeyString != "" {
		return nil, fmt.Errorf("only one of --pubkey and --pubkey-file may be used")
	}
	if pubkeyFilename != "" {
		return readKeyFromFile(pubkeyFilename)
	}
	if pubkeyString != "" {
		return noise.DecodeKey(pubkeyString)
	}
	return nil, fmt.Errorf("one of --pubkey or --pubkey-file is required")
}

// parseCommonArgs validates and parses DOMAIN and LOCALADDR positional arguments.
func parseCommonArgs(args []string) (dns.Name, *net.TCPAddr, error) {
	if len(args) < 2 {
		return nil, nil, fmt.Errorf("DOMAIN and LOCALADDR arguments are required")
	}
	domain, err := dns.ParseName(args[0])
	if err != nil {
		return nil, nil, fmt.Errorf("invalid domain %+q: %v", args[0], err)
	}
	localAddr, err := net.ResolveTCPAddr("tcp", args[1])
	if err != nil {
		return nil, nil, fmt.Errorf("invalid local address %+q: %v", args[1], err)
	}
	return domain, localAddr, nil
}

// legacyTranslateClientArgs detects the old single-flag invocation style
// (e.g. -doh URL -pubkey-file FILE DOMAIN LOCALADDR) and translates it to
// the new subcommand style (e.g. doh --pubkey-file FILE DOMAIN LOCALADDR URL).
// Returns nil when no translation is needed (args already use subcommand style).
func legacyTranslateClientArgs(args []string) []string {
	if len(args) == 0 {
		return nil
	}
	// New-style subcommand syntax or built-in cobra commands – no translation.
	switch args[0] {
	case "doh", "dot", "udp", "help", "completion", "--help", "-h":
		return nil
	}
	// Old-style args always start with a dash (e.g. -doh, -dot, -udp).
	if !strings.HasPrefix(args[0], "-") {
		return nil
	}

	// Parse old-style flags.
	fs := flag.NewFlagSet("legacy", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	var dohURL, dotAddr, udpAddr string
	var pubkeyFile, pubkeyHex, utlsSpec string
	fs.StringVar(&dohURL, "doh", "", "")
	fs.StringVar(&dotAddr, "dot", "", "")
	fs.StringVar(&udpAddr, "udp", "", "")
	fs.StringVar(&pubkeyFile, "pubkey-file", "", "")
	fs.StringVar(&pubkeyHex, "pubkey", "", "")
	fs.StringVar(&utlsSpec, "utls", "", "")
	if err := fs.Parse(args); err != nil {
		return nil
	}

	// Determine transport subcommand and resolver value.
	var subcmd, resolver string
	switch {
	case dohURL != "":
		subcmd, resolver = "doh", dohURL
	case dotAddr != "":
		subcmd, resolver = "dot", dotAddr
	case udpAddr != "":
		subcmd, resolver = "udp", udpAddr
	default:
		return nil
	}

	// Positional args after flag parsing are [DOMAIN, LOCALADDR].
	positional := fs.Args()

	// Build new-style args: SUBCOMMAND [DOMAIN LOCALADDR] RESOLVER [--flags...]
	newArgs := []string{subcmd}
	newArgs = append(newArgs, positional...) // DOMAIN, LOCALADDR
	newArgs = append(newArgs, resolver)
	if pubkeyFile != "" {
		newArgs = append(newArgs, "--pubkey-file", pubkeyFile)
	}
	if pubkeyHex != "" {
		newArgs = append(newArgs, "--pubkey", pubkeyHex)
	}
	if utlsSpec != "" {
		newArgs = append(newArgs, "--utls", utlsSpec)
	}

	fmt.Fprintf(os.Stderr, "warning: legacy flag syntax is deprecated; use: dnstt-client %s\n",
		strings.Join(newArgs, " "))
	return newArgs
}

func main() {
	log.SetFlags(log.LstdFlags | log.LUTC)

	// Translate old single-flag syntax to new subcommand syntax for backward compatibility.
	if translated := legacyTranslateClientArgs(os.Args[1:]); translated != nil {
		os.Args = append([]string{os.Args[0]}, translated...)
	}

	const defaultUTLS = "4*random,3*Firefox_120,1*Firefox_105,3*Chrome_120,1*Chrome_102,1*iOS_14,1*iOS_13"

	rootCmd := &cobra.Command{
		Use:   "dnstt-client",
		Short: "DNS tunnel client",
		Long: `dnstt-client tunnels TCP connections through DNS queries.

Choose a transport subcommand (doh, dot, or udp) to connect to a DNS resolver.
The tunnel forwards local TCP connections to the remote upstream server via DNS.`,
	}

	// Shared flags across transport subcommands.
	var pubkeyFile string
	var pubkeyHex string

	addPubkeyFlags := func(cmd *cobra.Command) {
		cmd.Flags().StringVar(&pubkeyFile, "pubkey-file", "", "path to server public key file")
		cmd.Flags().StringVar(&pubkeyHex, "pubkey", "", fmt.Sprintf("server public key as hex (%d digits)", noise.KeyLen*2))
	}

	// ── doh subcommand ────────────────────────────────────────────────────
	var utlsDoh string
	dohCmd := &cobra.Command{
		Use:   "doh DOMAIN LOCALADDR RESOLVER_URL",
		Short: "Use DNS-over-HTTPS (DoH) as transport",
		Long: `Connect to the tunnel server using DNS-over-HTTPS (DoH).

DOMAIN      – root DNS zone delegated to the tunnel server (e.g. t.example.com)
LOCALADDR   – local TCP address to listen on (e.g. 127.0.0.1:7000)
RESOLVER_URL – HTTPS URL of the DoH resolver (e.g. https://dns.example/dns-query)

TLS fingerprint camouflage is enabled by default via uTLS.
Use --utls to select a specific fingerprint or distribution.

Known fingerprints for --utls:
` + utlsFingerprints(),
		Args: cobra.ExactArgs(3),
		RunE: func(cmd *cobra.Command, args []string) error {
			domain, localAddr, err := parseCommonArgs(args[:2])
			if err != nil {
				return err
			}
			dohURL := args[2]

			pubkey, err := parsePubkey(pubkeyFile, pubkeyHex)
			if err != nil {
				return err
			}

			utlsClientHelloID, err := sampleUTLSDistribution(utlsDoh)
			if err != nil {
				return fmt.Errorf("parsing --utls: %v", err)
			}
			if utlsClientHelloID != nil {
				log.Printf("uTLS fingerprint %s %s", utlsClientHelloID.Client, utlsClientHelloID.Version)
			}

			remoteAddr := turbotunnel.DummyAddr{}
			var rt http.RoundTripper
			if utlsClientHelloID == nil {
				transport := http.DefaultTransport.(*http.Transport).Clone()
				transport.Proxy = nil
				rt = transport
			} else {
				rt = NewUTLSRoundTripper(nil, utlsClientHelloID)
			}
			httpConn, err := NewHTTPPacketConn(rt, dohURL, 32)
			if err != nil {
				return err
			}

			pconn := NewDNSPacketConn(httpConn, remoteAddr, domain)
			return run(pubkey, domain, localAddr, remoteAddr, pconn)
		},
	}
	dohCmd.Flags().StringVar(&utlsDoh, "utls", defaultUTLS,
		"TLS fingerprint distribution (e.g. \"Firefox\", \"3*Firefox,2*Chrome\", \"none\")")
	addPubkeyFlags(dohCmd)

	// ── dot subcommand ────────────────────────────────────────────────────
	var utlsDot string
	dotCmd := &cobra.Command{
		Use:   "dot DOMAIN LOCALADDR RESOLVER_ADDR",
		Short: "Use DNS-over-TLS (DoT) as transport",
		Long: `Connect to the tunnel server using DNS-over-TLS (DoT).

DOMAIN        – root DNS zone delegated to the tunnel server (e.g. t.example.com)
LOCALADDR     – local TCP address to listen on (e.g. 127.0.0.1:7000)
RESOLVER_ADDR – host:port of the DoT resolver (e.g. dns.example:853)

TLS fingerprint camouflage is enabled by default via uTLS.
Use --utls to select a specific fingerprint or distribution.

Known fingerprints for --utls:
` + utlsFingerprints(),
		Args: cobra.ExactArgs(3),
		RunE: func(cmd *cobra.Command, args []string) error {
			domain, localAddr, err := parseCommonArgs(args[:2])
			if err != nil {
				return err
			}
			dotAddr := args[2]

			pubkey, err := parsePubkey(pubkeyFile, pubkeyHex)
			if err != nil {
				return err
			}

			utlsClientHelloID, err := sampleUTLSDistribution(utlsDot)
			if err != nil {
				return fmt.Errorf("parsing --utls: %v", err)
			}
			if utlsClientHelloID != nil {
				log.Printf("uTLS fingerprint %s %s", utlsClientHelloID.Client, utlsClientHelloID.Version)
			}

			remoteAddr := turbotunnel.DummyAddr{}
			var dialTLSContext func(ctx context.Context, network, addr string) (net.Conn, error)
			if utlsClientHelloID == nil {
				dialTLSContext = (&tls.Dialer{}).DialContext
			} else {
				dialTLSContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
					return utlsDialContext(ctx, network, addr, nil, utlsClientHelloID)
				}
			}
			tlsConn, err := NewTLSPacketConn(dotAddr, dialTLSContext)
			if err != nil {
				return err
			}

			pconn := NewDNSPacketConn(tlsConn, remoteAddr, domain)
			return run(pubkey, domain, localAddr, remoteAddr, pconn)
		},
	}
	dotCmd.Flags().StringVar(&utlsDot, "utls", defaultUTLS,
		"TLS fingerprint distribution (e.g. \"Firefox\", \"3*Firefox,2*Chrome\", \"none\")")
	addPubkeyFlags(dotCmd)

	// ── udp subcommand ────────────────────────────────────────────────────
	udpCmd := &cobra.Command{
		Use:   "udp DOMAIN LOCALADDR RESOLVER_ADDR",
		Short: "Use plain UDP DNS as transport",
		Long: `Connect to the tunnel server using plain UDP DNS.

DOMAIN        – root DNS zone delegated to the tunnel server (e.g. t.example.com)
LOCALADDR     – local TCP address to listen on (e.g. 127.0.0.1:7000)
RESOLVER_ADDR – host:port of the UDP DNS resolver (e.g. dns.example:53)

Note: UDP mode does not camouflage traffic and is recommended for testing only.`,
		Args: cobra.ExactArgs(3),
		RunE: func(cmd *cobra.Command, args []string) error {
			domain, localAddr, err := parseCommonArgs(args[:2])
			if err != nil {
				return err
			}
			udpAddr := args[2]

			pubkey, err := parsePubkey(pubkeyFile, pubkeyHex)
			if err != nil {
				return err
			}

			remoteAddr, err := net.ResolveUDPAddr("udp", udpAddr)
			if err != nil {
				return fmt.Errorf("invalid resolver address %+q: %v", udpAddr, err)
			}
			pconn, err := net.ListenUDP("udp", nil)
			if err != nil {
				return err
			}

			pconn2 := NewDNSPacketConn(pconn, remoteAddr, domain)
			return run(pubkey, domain, localAddr, remoteAddr, pconn2)
		},
	}
	addPubkeyFlags(udpCmd)

	rootCmd.AddCommand(dohCmd, dotCmd, udpCmd)

	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}
