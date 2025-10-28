package main

import (
	"bytes"
	"context"
//	"crypto/rand"
//	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
mrand	"math/rand"
	"net"
	"os"
	"time"
	"unsafe"
)

// Constants from Handshake protocol
const (
	// Protocol constants
	ProtocolVersion = 1	// from HNSD
	MinVersion	= 1
	LocalServices	= 0	// From HNSD: no services
	UserAgent	= "/cdnsd-client:0.1.0/"

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

var MainnetSeeds = []string{
	"seed.htools.work",		// Seems to work reliably as of 2025-10-23, but is it Handshake?
//	"hs-mainnet.bcoin.ninja",	// From hsd source code. Never works!
//	"seed.easyhandshake.com",	// From hsd source code. Never works!
	"seed.hns.to",			// Backup from hsd sources
	"seed.hns.network",		// Official community seed
	"seed.handshakealliance.org",	// Alliance-maintained
	"seed.hsd-dev.org",		// Developer seed
	"dnsseed.handshake.org",	// Primary official seed
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

// Header represents a block header
type Header struct {
	// Preheader.
	Nonce		uint32
	Time		uint64
	PrevBlock	[32]byte
	NameRoot	[32]byte	// same as "uint8_t name_root[32]" ?

	// Subheader.
	ExtraNonce	[24]byte
	ReservedRoot	[32]byte
	WitnessRoot	[32]byte
	MerkleRoot	[32]byte
	Version		uint32
	Bits		uint32

	// Mask.
	Mask		[32]byte

	Cache bool
	Hash [32]byte
	Height uint32
	Work [32]byte

	Next *Header
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

/*	The packet header is the following:
	4 bytes : Handshake Magic Number
	1 byte  : command/message type
	4 bytes : Payload length (32-bit integer)
	remaining bytes : The payload, which is added later.

	The magic number and length are sent little-endian.
	Note: The command is a SINGLE BYTE storing an integer
	from 0 (VERSION) to about (), and NOT a 12-byte
	string, which appears incorrectly in some documentation. */

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
	// check the packet's size
	if len(data) < 9 {
		return 0, 0, fmt.Errorf("packet too short")
	}

	// Check the magic number

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
	// Send it to the peer.
	_, err := p.conn.Write(packet)
	return err
}

// receiveMessage receives and parses a packet
func (p *Peer) receiveMessage() (byte, []byte, error) {
	// Read header
	header := make([]byte, 9)
	_, err := p.conn.Read(header)
	if err != nil || len(header) < 9 {
		return 0, nil, fmt.Errorf("failed to read from connection")
	}

fmt.Printf("Received packet magic: %d\n", binary.LittleEndian.Uint32(header[0:4]))

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

	// 4 bytes: Protocol version.
	// This uses 1, which is the same as HNSD.

	binary.Write(buf, binary.LittleEndian, version.Version)

	// Services that this node provides. Using 0, same as HNSD.
	// Services is a 64-bit integer, so write 2 32-bit zeros.

	binary.Write(buf, binary.LittleEndian, version.Services)
	binary.Write(buf, binary.LittleEndian, uint32(0)) // high services bits

	// 8 bytes; 64-bit Timestamp (Seconds since Unix epoch)

	binary.Write(buf, binary.LittleEndian, version.Time)

	// 88 bytes: Remote address
	encodeNetAddress(buf, &version.Remote)

	// 8 bytes (64 bits): Nonce
//	buf.Write(version.Nonce[:])
	binary.Write(buf, binary.LittleEndian, hsk_nonce())

	// 1 byte: Length of user agent string
	buf.WriteByte(byte(len(version.Agent)))
	// (length) bytes: User agent
	buf.WriteString(version.Agent)

	// 4 bytes: Height  (Using value of 0)
	binary.Write(buf, binary.LittleEndian, version.Height)

	// 1 byte: NoRelay
	if version.NoRelay { buf.WriteByte(1) } else { buf.WriteByte(0) }

	return buf.Bytes()
}

// Check this
// 1. Does it write 88 bytes (is that the correct number?)
// 2. Does it skip "high services" and "type"?
// 3. does hnsd write ...
//    time(8)
//    services(8)
//    type(1)
//    ip(36)
//    port(2 BE)
//    key(33)

// encodeNetAddress serializes a NetAddress
func encodeNetAddress(buf *bytes.Buffer, addr *NetAddress) {
	// 8 bytes; time
	binary.Write(buf, binary.LittleEndian, addr.Time)
	// 4 bytes: low bytes of Services
	binary.Write(buf, binary.LittleEndian, addr.Services)
	// 4 bytes: high bytes of Services
	binary.Write(buf, binary.LittleEndian, uint32(0))
	// 1 byte: address type
// TODO: check. always write a 0?
	buf.WriteByte(0)

// TODO: Check this against hnsd

	// 16 bytes: address
	if addr.Host.To4() != nil {
		// IPv4-mapped IPv6 address
		buf.Write([]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff})
		buf.Write(addr.Host.To4())
	} else {
		// regular address
		buf.Write(addr.Host.To16())
	}

	// 20 bytes: reserved
	buf.Write(make([]byte, 20))
	// 2 bytes, big endian: Port
	binary.Write(buf, binary.BigEndian, addr.Port)
	// 33 bytes: Key
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
//	var nonce [8]byte
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
		NoRelay: true,
	}

	// Set a random nonce.

// NOTE: The nonce is set in encodeVersionMessage()
// using hsk_nonce(), to match the behavior of HNSD
//	_, err = rand.Read(nonce[:])
//	if err != nil { return err }
//	version.Nonce = nonce

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

// WORK

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
func (p *Peer) receiveHeaders() ([]*Header, error) {
	cmd, payload, err := p.receiveMessage()
	if err != nil { return nil, err }

	if cmd != MessageHeaders {
//		return nil, fmt.Errorf("expected HEADERS, got %d", cmd)
		fmt.Errorf("Received command: %d", cmd)

// TODO: Do this in a loop to keep trying until HEADERS is received or there is a timeout.
// Reason: Peers may send other things, even though they have been informed this peer offers no services.

		// Try again
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

	headers := make([]*Header, 0, count)

	for i := uint64(0); i < count; i++ {
		header, size, err := decodeHeader(payload[offset:])
// size is 236
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
func decodeHeader(data []byte) (*Header, int, error) {
	if len(data) < 196 {
		return nil, 0, fmt.Errorf("data too short for header")
	}

	h := &Header{}
	offset := 0

// Order: Preheader, Subheader, Mask
// TODO: CHECK THIS PART !!

	h.Version = binary.LittleEndian.Uint32(data[offset:])
	offset += 4

	copy(h.PrevBlock[:], data[offset:offset+32])
	offset += 32

	copy(h.MerkleRoot[:], data[offset:offset+32])
	offset += 32

	copy(h.WitnessRoot[:], data[offset:offset+32])
	offset += 32

	copy(h.NameRoot[:], data[offset:offset+32])
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

func encodeHeader(buf *bytes.Buffer, _ *Header, h *Header) {
	// Preheader
	binary.Write(buf, binary.LittleEndian, h.Nonce)
	binary.Write(buf, binary.LittleEndian, h.Time)
	buf.Write(h.PrevBlock[:])
	buf.Write(h.NameRoot[:])

	// Subheader
	buf.Write(h.ExtraNonce[:])
	buf.Write(h.ReservedRoot[:])
	buf.Write(h.WitnessRoot[:])
	buf.Write(h.MerkleRoot[:])
	binary.Write(buf, binary.LittleEndian, h.Version)
	binary.Write(buf, binary.LittleEndian, h.Bits)

	// Mask
	buf.Write(h.Mask[:])
}

// Helper: convert any value to []byte via unsafe pointer
func structToBytes(v any) []byte {
	return (*(*[1 << 30]byte)(unsafe.Pointer(&v)))[:unsafe.Sizeof(v)]
}

func hexDump(v any) {
	// Convert struct to []byte using unsafe (fast, zero-copy)
	data := structToBytes(v)
//	fmt.Printf("%s\n", hex.Dump(data))
	fmt.Printf("length of header: %d\n",len(data))
	for i := range(data) {
		fmt.Printf("%d ",data[i])
	}
	fmt.Printf("\n")
}

var hexdigs = [16]uint8 {
        '0',
        '1',
        '2',
        '3',
        '4',
        '5',
        '6',
        '7',
        '8',
        '9',
        'a',
        'b',
        'c',
        'd',
        'e',
        'f',
}

func fillTestHeader(hdr *Header) {
	var c uint8

	hdr.Nonce = 1234567
        hdr.Time = 1761496325

        for i := 0; i < 32; i++ {
                c = hexdigs[i%16]
                hdr.PrevBlock[i] = c
                hdr.NameRoot[i] = c
                if i < 24 { hdr.ExtraNonce[i] = c }
                hdr.ReservedRoot[i] = c
                hdr.WitnessRoot[i] = c
                hdr.MerkleRoot[i] = c
                hdr.Hash[i] = c
                hdr.Work[i] = c
        }
        hdr.Bits = 1234567
        hdr.Cache = false
        hdr.Height = 0
}

func makeTestHeader() *Header {
	var h = Header{}
	var hdr *Header
	hdr = &h
	fillTestHeader(hdr)
	return hdr
}

func main() {

var testHeader *Header
var size int

	// Print the size of the header struct.

	size = int(unsafe.Sizeof(*testHeader))
	fmt.Printf("Size of header: %d bytes\n",size)

	// Create the test data. A fake header.

	testHeader = makeTestHeader()
	testHeader.Cache = false

	// Print the bytes in the header has hex uint8.

//	fmt.Printf("Test Header:\n"); hexDump(testHeader)

	fmt.Printf("Header Contents:")
	p := unsafe.Slice((*uint8)(unsafe.Pointer(testHeader)), size)
	for i := 0; i < size; i++ {
		if i%16 == 0 { fmt.Printf("\n") }
		fmt.Printf("%2x ",p[i])
	}
	fmt.Printf("\n")
	

	// Calculate the header's hash

	testHash := HeaderCache(testHeader)

	// Print it.

	fmt.Printf("Header hash:\n")
	fmt.Printf("%x\n", testHash)
	os.Exit(0)

/////////////////////////////////////////////////
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

/*
// (commented out temporarily to skip ahead to header downloading)

	// Request the peer's peer addresses. Multiple peers
	// are used to download blocks in parallel, saving
	// time and avoiding overloading individual peers.

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
	fmt.Println("\nStarting header sync...")

var locator [][32]byte
var stopHash [32]byte

	// Genesis block hash as locator
	genesisHash := [32]byte{}
	genesisHashHex := "5b6ef2d3c1f3cdcadfd9a030ba1811efdd17740f14e166489760741d075992e0"
	genesisBytes, _ := hex.DecodeString(genesisHashHex)
	copy(genesisHash[:], genesisBytes)

	locator = [][32]byte{genesisHash}
	stopHash = [32]byte{} // Zero hash means no stop

	var headers []*Header
	totalHeaders := 0

	// Get the headers, 2000 at a time.

	for {
		err = peer.requestHeaders(locator, stopHash)
		if err != nil {
			fmt.Printf("Failed to request headers: %v\n", err)
			return
		}

		// Receive headers
		headers, err := peer.receiveHeaders()
		if err != nil {
			fmt.Printf("Failed to receive headers: %v\n", err)
			os.Exit(1)
		}

		totalHeaders += len(headers)
		fmt.Printf("Received %d headers (total: %d)\n", len(headers), totalHeaders)
		// Print first header of this batch
		fmt.Printf("   First: ... hash: %x\n", HeaderCache(headers[0]))

		// Use last header as new locator
		lastHeader := headers[len(headers)-1]
size := unsafe.Sizeof(lastHeader)
fmt.Println("Size of Header:", size, "bytes")
os.Exit(1)

lastHash := HeaderCache(lastHeader)
fmt.Printf("Last Header: "); hexDump(lastHeader)
fmt.Printf("Last Hash: %x\n", lastHash)
os.Exit(0)
		locator = [][32]byte{lastHash}

		// If there are fewer than 2000 headers, it is at the tip.

		if len(headers) < 2000 {
			fmt.Printf("Sync complete. Tip hash: %x\n",lastHash)
			break
		}

		// to keep the peer from banning due to high demand on it.
		time.Sleep(100 * time.Millisecond)
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

	fmt.Println("\nCompleted peer discovery and header download.")
os.Exit(0)
}
