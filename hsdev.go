package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"fmt"
mrand	"math/rand"
	"net"
	"os"
	"time"
)

// Constants from Handshake protocol
const (
	// Protocol constants
//	ProtocolVersion = 3
	ProtocolVersion = 1	// from HNSD
	MinVersion	= 1
//	LocalServices	= 1	// network service
	LocalServices	= 0	// From HNSD: no services
	UserAgent	= "/hsd-go-client:0.1.0/"

	// Network magic number for mainnet.
	MainnetMagic = 1533997779
	// Port for Handshake P2P communications.
	MainnetPort  = 12038

	// Message types

	MessageVersion = 0
	MessageVerack = 1
	MessagePing = 2
	MessagePong = 3
	MessageGetAddr = 4
	MessageAddr = 5
	MessageInv = 6
	MessageGetData = 7
	MessageNotFound = 8
	MessageGetBlocks = 9
	MessageGetHeaders = 10
	MessageHeaders = 11
	MessageSendHeaders = 12
	MessageBlock = 13
	MessageTx = 14
	MessageReject = 15
	MessageMempool = 16
	MessageFilterLoad = 17
	MessageFilterAdd = 18
	MessageFilterClear = 19
	MessageMerkleBlock = 20
	MessageFeeFilter = 21
	MessageSendCmpct = 22
	MessageCmpctBlock = 23
	MessageGetBlockTxn = 24
	MessageBlockTxn = 25
	MessageGetProof = 26
	MessageProof = 27
	MessageClaim = 28
	MessageAirdrop = 29
	MessageUnknown = 30
	// Internal
	MessageInternal = 31
	MessageData = 32

	// Other constants
	MaxMessage = 8 * 1000 * 1000
)

// seeds for peer discovery
var MainnetSeeds = []string{
	"seed.htools.work",		// Seems to work reliably as of 2025-10-15
//	"hs-mainnet.bcoin.ninja",	// From hsd source code. Flaky
//	"seed.easyhandshake.com",	// From hsd source code. Flaky
}

// NetAddress represents a network address
type NetAddress struct {
	Time	uint64
	Services uint32
	Host	net.IP
	Port	uint16
	Key	[33]byte
}

// VersionMessage for version
type VersionMessage struct {
	Version	uint32
	Services uint32
	Time	uint64
	Remote	NetAddress
	Nonce	[8]byte
	Agent	string
	Height	uint32
	NoRelay  bool
}

// Headers represents a block header
type Headers struct {
	Version		uint32
	PrevBlock	[32]byte
	MerkleRoot	[32]byte
	WitnessRoot	[32]byte
	TreeRoot	[32]byte
	ReservedRoot	[32]byte
	Time		uint64
	Bits		uint32
	Nonce		uint32
	ExtraNonce	[24]byte
	Mask		[32]byte
}

// Peer represents a connection to a Handshake node
type Peer struct {
	conn	net.Conn
	address string
}

const networkTimeout = 2*time.Second

// The following 3 functions implement a funny little
// random number generator copied from hnsd, used for
// creating nonces.
// TODO: Maybe replace this with a simple 64-bit random number.

func sysrandom() uint32 {
	r := mrand.New(mrand.NewSource(time.Now().UnixNano()))
	return r.Uint32()
}

func hsk_random() uint32 {
	var n uint32
	n = sysrandom();
	return n << 16 ^ sysrandom()
}

func hsk_nonce() uint64 {
	return uint64(hsk_random()) << 32 + uint64(hsk_random())
}

// hsk_now() returns Unix epoch seconds. Used for timestamping messages.
func hsk_now() int64 {
	return(time.Now().Unix())
}

// Connect establishes a connection to a peer
func (p *Peer) Connect(address string) error {
	conn, err := net.DialTimeout("tcp", address, networkTimeout)
	if err != nil {
		return err
	}
	p.conn = conn
	p.address = address
	return nil
}

// Close closes the peer connection
func (p *Peer) Close() {
	if p.conn != nil { p.conn.Close() }
}

const messageHeaderLength = 9

// createMessage creates a framed packet with header
func createMessage(cmd byte, payload []byte) []byte {
	msg := make([]byte, messageHeaderLength + len(payload))

	// Start with the magic number: 4 bytes, little-endian.
	binary.LittleEndian.PutUint32(msg[0:4], MainnetMagic)

	// Add the message (command) type: 1 byte.
	msg[4] = cmd

	// Add payload length: 4 bytes, little-endian.
	binary.LittleEndian.PutUint32(msg[5:9], uint32(len(payload)))

	// Add the payload.
	copy(msg[9:], payload)

	return msg
}

// parseMessageHeader reads and validates packet header
func parseMessageHeader(data []byte) (cmd byte, payloadLen uint32, err error) {
	if len(data) < 9 {
		return 0, 0, fmt.Errorf("packet too short")
	}

	magic := binary.LittleEndian.Uint32(data[0:4])
	if magic != MainnetMagic {
		return 0, 0, fmt.Errorf("invalid magic: %d", magic)
	}

	cmd = data[4]
	payloadLen = binary.LittleEndian.Uint32(data[5:9])

	return cmd, payloadLen, nil
}

// sendMessage sends a framed packet to the peer
func (p *Peer) sendMessage(cmd byte, payload []byte) error {
	// Create the message, using the command (message) type and payload.
	packet := createMessage(cmd, payload)
	// Send it.
	_, err := p.conn.Write(packet)
	return err
}

// receiveMessage receives and parses a packet
func (p *Peer) receiveMessage() (byte, []byte, error) {
	// Read header
	header := make([]byte, 9)
	_, err := p.conn.Read(header)
	if err != nil { return 0, nil, err }

	cmd, payloadLen, err := parseMessageHeader(header)
	if err != nil { return 0, nil, err }

	if payloadLen > MaxMessage {
		return 0, nil, fmt.Errorf("payload too large: %d", payloadLen)
	}

	// Read payload
	payload := make([]byte, payloadLen)
	if payloadLen > 0 {
		_, err = p.conn.Read(payload)
		if err != nil { return 0, nil, err }
	}

	return cmd, payload, nil
}

// encodeVersionMessage serializes a VERSION packet
func encodeVersionMessage(version *VersionMessage) []byte {
	buf := new(bytes.Buffer)

	binary.Write(buf, binary.LittleEndian, version.Version)
	binary.Write(buf, binary.LittleEndian, version.Services)
	binary.Write(buf, binary.LittleEndian, uint32(0)) // high services bits
	binary.Write(buf, binary.LittleEndian, version.Time)

	// Remote address (88 bytes)
	encodeNetAddress(buf, &version.Remote)

	// Nonce
	buf.Write(version.Nonce[:])

	// User agent
	buf.WriteByte(byte(len(version.Agent)))
	buf.WriteString(version.Agent)

	// Height
	binary.Write(buf, binary.LittleEndian, version.Height)

	// No relay
	if version.NoRelay { buf.WriteByte(1) } else { buf.WriteByte(0) }

	return buf.Bytes()
}

// encodeNetAddress serializes a NetAddress
func encodeNetAddress(buf *bytes.Buffer, addr *NetAddress) {
	binary.Write(buf, binary.LittleEndian, addr.Time)
	binary.Write(buf, binary.LittleEndian, addr.Services)
	binary.Write(buf, binary.LittleEndian, uint32(0)) // high services bits
	buf.WriteByte(0) // address type

	// IPv6 representation (16 bytes)
	if addr.Host.To4() != nil {
		// IPv4-mapped IPv6 address
		buf.Write([]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff})
		buf.Write(addr.Host.To4())
	} else {
		buf.Write(addr.Host.To16())
	}

	buf.Write(make([]byte, 20)) // reserved
	binary.Write(buf, binary.BigEndian, addr.Port)
	buf.Write(addr.Key[:])
}

// decodeNetAddress parses a NetAddress from bytes
func decodeNetAddress(data []byte) (*NetAddress, int, error) {
	if len(data) < 88 {
		return nil, 0, fmt.Errorf("data too short for NetAddress")
	}

	addr := &NetAddress{}
	addr.Time = binary.LittleEndian.Uint64(data[0:8])
	addr.Services = binary.LittleEndian.Uint32(data[8:12])

	// Skip high services bits (4 bytes) and type (1 byte)
	ipBytes := data[17:33]
	addr.Host = net.IP(ipBytes)

	// Skip reserved (20 bytes)
	addr.Port = binary.BigEndian.Uint16(data[53:55])
	copy(addr.Key[:], data[55:88])

	return addr, 88, nil
}

// sendVersionHandshake sends VERSION
func (p *Peer) sendVersionHandshake() error {
	var nonce [8]byte
	var err error

	// Create a VERSION packet.

	version := &VersionMessage{
		Version:  ProtocolVersion,
		Services: LocalServices,
		Time:	uint64(time.Now().Unix()),
		Remote: NetAddress{
			Services: LocalServices,
			Host:	net.ParseIP("0.0.0.0"),
			Port:	0,
		},
		Nonce:   [8]byte{1, 2, 3, 4, 5, 6, 7, 8},
		Agent:   UserAgent,
		Height:  0,
		NoRelay: false,
	}

	// Set a random nonce.

	_, err = rand.Read(nonce[:])
	if err != nil { return err }
	version.Nonce = nonce

	payload := encodeVersionMessage(version)

	// Send the VERSION packet.

	err = p.sendMessage(MessageVersion, payload)
	if err != nil {
		return fmt.Errorf("failed to send VERSION: %v", err)
	}

	fmt.Println("Sent VERSION packet")

	// Wait for VERACK from peer
	cmd, _, err := p.receiveMessage()
	if err != nil {
		return fmt.Errorf("failed to receive VERACK: %v", err)
	}

	if cmd != MessageVerack { return fmt.Errorf("expected VERACK, got %d", cmd) }

	fmt.Println("Received VERACK packet")

	// Wait for VERSION
	cmd, _, err = p.receiveMessage()
	if err != nil {
		return fmt.Errorf("failed to receive VERSION: %v", err)
	}

	if cmd != MessageVersion { return fmt.Errorf("expected VERSION, got %d", cmd) }

	fmt.Println("Received VERSION packet")

	// Send VERACK
	err = p.sendMessage(MessageVerack, []byte{})
	if err != nil {
		return fmt.Errorf("failed to send VERACK: %v", err)
	}

	fmt.Println("Sent VERACK packet\nInitial handshake complete")

	return nil
}

// requestPeerAddresses sends GETADDR request
func (p *Peer) requestPeerAddresses() error {
	err := p.sendMessage(MessageGetAddr, []byte{})
	if err != nil {
		return fmt.Errorf("failed to send GETADDR: %v", err)
	}

	fmt.Println("Sent GETADDR packet")
	return nil
}

// receivePeerAddresses receives ADDR response
func (p *Peer) receivePeerAddresses() ([]*NetAddress, error) {
	cmd, payload, err := p.receiveMessage()
	if err != nil {
		return nil, err
	}

	if cmd != MessageAddr {
		return nil, fmt.Errorf("expected ADDR, got %d", cmd)
	}

	// Parse varint count
	count, offset := decodeVarint(payload)

	addresses := make([]*NetAddress, 0, count)

	for i := uint64(0); i < count; i++ {
		addr, size, err := decodeNetAddress(payload[offset:])
		if err != nil {
			return nil, err
		}

		// Skip if empty. Use the port number to check for useless addr
		if addr.Port == 0 { continue }

		addresses = append(addresses, addr)
		offset += size
	}

	fmt.Printf("Received %d peer addresses\n", len(addresses))

	return addresses, nil
}

// requestHeaders sends GETHEADERS request
func (p *Peer) requestHeaders(locator [][32]byte, stopHash [32]byte) error {
	buf := new(bytes.Buffer)

	// Write locator count
	encodeVarint(buf, uint64(len(locator)))

	// Write locator hashes
	for _, hash := range locator {
		buf.Write(hash[:])
	}

	// Write stop hash
	buf.Write(stopHash[:])

	err := p.sendMessage(MessageGetHeaders, buf.Bytes())
	if err != nil {
		return fmt.Errorf("failed to send GETHEADERS: %v", err)
	}

	fmt.Println("Sent GETHEADERS packet")
	return nil
}

// receiveHeaders receives HEADERS response
func (p *Peer) receiveHeaders() ([]*Headers, error) {
	cmd, payload, err := p.receiveMessage()
	if err != nil { return nil, err }

	if cmd != MessageHeaders {
//		return nil, fmt.Errorf("expected HEADERS, got %d", cmd)
		fmt.Errorf("Received command: %d", cmd)

		cmd, payload, err = p.receiveMessage()
		if err != nil { return nil, err }

		if cmd != MessageHeaders {
			return nil, fmt.Errorf("expected HEADERS, got %d", cmd)
		}
	}

	// Parse varint count
	count, offset := decodeVarint(payload)

	if count > 2000 {
		return nil, fmt.Errorf("too many headers: %d", count)
	}

	headers := make([]*Headers, 0, count)

	for i := uint64(0); i < count; i++ {
		header, size, err := decodeHeader(payload[offset:])
		if err != nil {
			return nil, err
		}
		headers = append(headers, header)
		offset += size
	}

	fmt.Printf("Received %d block headers\n", len(headers))

	return headers, nil
}

// decodeHeader parses a block header
func decodeHeader(data []byte) (*Headers, int, error) {
	if len(data) < 196 {
		return nil, 0, fmt.Errorf("data too short for header")
	}

	h := &Headers{}
	offset := 0

	h.Version = binary.LittleEndian.Uint32(data[offset:])
	offset += 4

	copy(h.PrevBlock[:], data[offset:offset+32])
	offset += 32

	copy(h.MerkleRoot[:], data[offset:offset+32])
	offset += 32

	copy(h.WitnessRoot[:], data[offset:offset+32])
	offset += 32

	copy(h.TreeRoot[:], data[offset:offset+32])
	offset += 32

	copy(h.ReservedRoot[:], data[offset:offset+32])
	offset += 32

	h.Time = binary.LittleEndian.Uint64(data[offset:])
	offset += 8

	h.Bits = binary.LittleEndian.Uint32(data[offset:])
	offset += 4

	h.Nonce = binary.LittleEndian.Uint32(data[offset:])
	offset += 4

	copy(h.ExtraNonce[:], data[offset:offset+24])
	offset += 24

	copy(h.Mask[:], data[offset:offset+32])
	offset += 32

	return h, offset, nil
}

// encodeVarint encodes a varint
func encodeVarint(buf *bytes.Buffer, n uint64) {
	if n < 0xfd {
		buf.WriteByte(byte(n))
	} else if n <= 0xffff {
		buf.WriteByte(0xfd)
		binary.Write(buf, binary.LittleEndian, uint16(n))
	} else if n <= 0xffffffff {
		buf.WriteByte(0xfe)
		binary.Write(buf, binary.LittleEndian, uint32(n))
	} else {
		buf.WriteByte(0xff)
		binary.Write(buf, binary.LittleEndian, n)
	}
}

// decodeVarint decodes a varint
func decodeVarint(data []byte) (uint64, int) {
	if len(data) == 0 {
		return 0, 0
	}

	first := data[0]
	if first < 0xfd {
		return uint64(first), 1
	} else if first == 0xfd {
		return uint64(binary.LittleEndian.Uint16(data[1:3])), 3
	} else if first == 0xfe {
		return uint64(binary.LittleEndian.Uint32(data[1:5])), 5
	} else {
		return binary.LittleEndian.Uint64(data[1:9]), 9
	}
}

func lookupHostWithTimeout(host string) ([]string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), networkTimeout)
	defer cancel()

	resultChan := make(chan []string, 1)
	errChan := make(chan error, 1)

	go func() {
		addrs, err := net.LookupHost(host)
		if err != nil {
			errChan <- err
			return
		}
		resultChan <- addrs
	}()

	select {
	case <-ctx.Done():
		return nil, fmt.Errorf("lookup timeout after %s", networkTimeout)
	case err := <-errChan:
		return nil, err
	case addrs := <-resultChan:
		return addrs, nil
	}
}

// discoverPeers resolves seeds to get peer addresses
func discoverPeers() []string {
	var peers []string

	for _, seed := range MainnetSeeds {
		fmt.Printf("Resolving seed: %s\n", seed)
		addrs, err := lookupHostWithTimeout(seed)
		if err != nil {
			fmt.Printf("Failed to resolve %s: %v\n", seed, err)
			continue
		}
		
		for _, addr := range addrs {
			peerAddr := fmt.Sprintf("%s:%d", addr, MainnetPort)
			peers = append(peers, peerAddr)
			fmt.Printf("  Found peer: %s\n", peerAddr)
		}
	}

	return peers
}

func main() {
	fmt.Println("Handshake Peer Discovery and Block Header Download")

	// Discover peers from seeds

	fmt.Println("\nDiscovering peers ...")
	peers := discoverPeers()

	if len(peers) == 0 {
		fmt.Println("No peers found from seeds")
		return
	}

	// Connect to first available peer

	fmt.Println("\nConnecting to peer...")
	peer := &Peer{}
	var connected bool

	for _, peerAddr := range peers {
		fmt.Printf("Trying to connect to %s...\n", peerAddr)
		err := peer.Connect(peerAddr)
		if err != nil {
			fmt.Printf("Failed to connect: %v\n", err)
			continue
		}
		connected = true
		fmt.Printf("Connected to %s\n", peerAddr)
		break
	}

	if !connected {
		fmt.Println("Could not connect to any peer")
		return
	}

	defer peer.Close()

	// Perform version handshake

	fmt.Println("\nSending version message...")
	err := peer.sendVersionHandshake()
	if err != nil {
		fmt.Printf("Handshake failed: %v\n", err)
		return
	}

// WORK
/*
	//  Request peer addresses
	fmt.Println("\nRequesting peer addresses...")
	err = peer.requestPeerAddresses()
	if err != nil {
		fmt.Printf("Failed to request addresses: %v\n", err)
		return
	}

	// Receive peer addresses
	addresses, err := peer.receivePeerAddresses()
	if err != nil {
		fmt.Printf("Failed to receive addresses: %v\n", err)
	} else {
		fmt.Println("\nDiscovered peers:")

		for i, addr := range addresses {
			fmt.Printf("%4d  %s:%d (services: %d)\n", i, addr.Host, addr.Port, addr.Services)
			// print the first 10 addresses
			if i >= 10 {
				fmt.Printf("  ... and %d more\n", len(addresses)-10)
				break
			}
		}
	}
*/

	// Request block headers starting from genesis
	fmt.Println("\nRequesting block headers...")

	// Genesis block hash as locator
	genesisHash := [32]byte{}
	genesisHashHex := "5b6ef2d3c1f3cdcadfd9a030ba1811efdd17740f14e166489760741d075992e0"
	genesisBytes, _ := hex.DecodeString(genesisHashHex)
	copy(genesisHash[:], genesisBytes)

	locator := [][32]byte{genesisHash}
	stopHash := [32]byte{} // Zero hash means no stop

	err = peer.requestHeaders(locator, stopHash)
	if err != nil {
		fmt.Printf("Failed to request headers: %v\n", err)
		return
	}

	// Receive headers
	headers, err := peer.receiveHeaders()
	if err != nil {
		fmt.Printf("Failed to receive headers: %v\n", err)
		return
	}

	// Display received headers
	fmt.Println("\nReceived block headers:")
	for i, header := range headers {
		if i >= 5 {
			fmt.Printf("  ... and %d more headers\n", len(headers)-5)
			break
		}
		fmt.Printf("  Header %d:\n", i+1)
		fmt.Printf("    Version: %d\n", header.Version)
		fmt.Printf("    Previous Block: %x\n", header.PrevBlock)
		fmt.Printf("    Merkle Root: %x\n", header.MerkleRoot)
		fmt.Printf("    Time: %d\n", header.Time)
		fmt.Printf("    Bits: 0x%08x\n", header.Bits)
		fmt.Printf("    Nonce: %d\n", header.Nonce)
	}

	fmt.Println("\n[Complete] Successfully performed peer discovery and header download!")
os.Exit(0)
}
