package main

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net"
	"time"
)

// Constants from Handshake protocol
const (
	// Protocol constants
	ProtocolVersion = 3
	MinVersion	= 1
	LocalServices	= 1 // NETWORK service
	UserAgent	= "/hsd-go-client:0.1.0/"
	
	// Network magic number for mainnet
	MainnetMagic = 1533997779
	MainnetPort  = 12038
	
	// Packet types
	PacketVersion	= 0
	PacketVerack	= 1
	PacketGetAddr	= 4
	PacketAddr	= 5
	PacketGetHeaders = 10
	PacketHeaders	= 11
	
	// Other constants
	MaxMessage = 8 * 1000 * 1000
)

// DNS seeds for peer discovery
var MainnetSeeds = []string{
	"seed.htools.work",		// Seems to work reliably as of 2025-10-15
/*
	"hs-mainnet.bcoin.ninja",	// From hsd source code. Flaky
	"seed.easyhandshake.com",	// From hsd source code. Flaky
*/
}

// NetAddress represents a network address
type NetAddress struct {
	Time	uint64
	Services uint32
	Host	net.IP
	Port	uint16
	Key	[33]byte
}

// VersionPacket for version handshake
type VersionPacket struct {
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

// Connect establishes a connection to a peer
func (p *Peer) Connect(address string) error {
//	conn, err := net.DialTimeout("tcp", address, 10*time.Second)
	conn, err := net.DialTimeout("tcp", address, 2*time.Second)
	if err != nil {
		return err
	}
	p.conn = conn
	p.address = address
	return nil
}

// Close closes the peer connection
func (p *Peer) Close() {
	if p.conn != nil {
		p.conn.Close()
	}
}

// framePacket creates a framed packet with header
func framePacket(cmd byte, payload []byte) []byte {
	msg := make([]byte, 9+len(payload))
	
	// Magic number (4 bytes, little-endian)
	binary.LittleEndian.PutUint32(msg[0:4], MainnetMagic)
	
	// Command type (1 byte)
	msg[4] = cmd
	
	// Payload length (4 bytes, little-endian)
	binary.LittleEndian.PutUint32(msg[5:9], uint32(len(payload)))
	
	// Payload
	copy(msg[9:], payload)
	
	return msg
}

// parsePacketHeader reads and validates packet header
func parsePacketHeader(data []byte) (cmd byte, payloadLen uint32, err error) {
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

// sendPacket sends a framed packet to the peer
func (p *Peer) sendPacket(cmd byte, payload []byte) error {
	packet := framePacket(cmd, payload)
	_, err := p.conn.Write(packet)
	return err
}

// receivePacket receives and parses a packet
func (p *Peer) receivePacket() (byte, []byte, error) {
	// Read header
	header := make([]byte, 9)
	_, err := p.conn.Read(header)
	if err != nil {
		return 0, nil, err
	}
	
	cmd, payloadLen, err := parsePacketHeader(header)
	if err != nil {
		return 0, nil, err
	}
	
	if payloadLen > MaxMessage {
		return 0, nil, fmt.Errorf("payload too large: %d", payloadLen)
	}
	
	// Read payload
	payload := make([]byte, payloadLen)
	if payloadLen > 0 {
		_, err = p.conn.Read(payload)
		if err != nil {
			return 0, nil, err
		}
	}
	
	return cmd, payload, nil
}

// encodeVersionPacket serializes a VERSION packet
func encodeVersionPacket(version *VersionPacket) []byte {
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
	if version.NoRelay {
		buf.WriteByte(1)
	} else {
		buf.WriteByte(0)
	}
	
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

// sendVersionHandshake sends VERSION and waits for VERACK
func (p *Peer) sendVersionHandshake() error {
	// Create VERSION packet
	version := &VersionPacket{
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
	
	payload := encodeVersionPacket(version)
	
	// Send VERSION
	err := p.sendPacket(PacketVersion, payload)
	if err != nil {
		return fmt.Errorf("failed to send VERSION: %v", err)
	}
	
	fmt.Println("Sent VERSION packet")
	
	// Wait for VERSION from peer
	cmd, _, err := p.receivePacket()
	if err != nil {
		return fmt.Errorf("failed to receive VERSION: %v", err)
	}

/*
	if cmd != PacketVersion {
		return fmt.Errorf("expected VERSION, got %d", cmd)
	}
*/
	if cmd != PacketVersion {
		fmt.Errorf("expected VERSION, got %d", cmd)
	}
	
	fmt.Println("Received VERSION packet")
	
	// Send VERACK
	err = p.sendPacket(PacketVerack, []byte{})
	if err != nil {
		return fmt.Errorf("failed to send VERACK: %v", err)
	}
	
	fmt.Println("Sent VERACK packet")
	
	// Wait for VERACK
	cmd, _, err = p.receivePacket()
	if err != nil {
		return fmt.Errorf("failed to receive VERACK: %v", err)
	}
/*
	if cmd != PacketVerack {
		return fmt.Errorf("expected VERACK, got %d", cmd)
	}
*/
	if cmd != PacketVerack {
		fmt.Errorf("expected VERACK, got %d", cmd)
	}
	
	fmt.Println("Received VERACK packet - handshake complete")
	
	return nil
}

// requestPeerAddresses sends GETADDR request
func (p *Peer) requestPeerAddresses() error {
	err := p.sendPacket(PacketGetAddr, []byte{})
	if err != nil {
		return fmt.Errorf("failed to send GETADDR: %v", err)
	}
	
	fmt.Println("Sent GETADDR packet")
	return nil
}

// receivePeerAddresses receives ADDR response
func (p *Peer) receivePeerAddresses() ([]*NetAddress, error) {
	cmd, payload, err := p.receivePacket()
	if err != nil {
		return nil, err
	}
	
	if cmd != PacketAddr {
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
	
	err := p.sendPacket(PacketGetHeaders, buf.Bytes())
	if err != nil {
		return fmt.Errorf("failed to send GETHEADERS: %v", err)
	}
	
	fmt.Println("Sent GETHEADERS packet")
	return nil
}

// receiveHeaders receives HEADERS response
func (p *Peer) receiveHeaders() ([]*Headers, error) {
	cmd, payload, err := p.receivePacket()
	if err != nil {
		return nil, err
	}
	
	if cmd != PacketHeaders {
		return nil, fmt.Errorf("expected HEADERS, got %d", cmd)
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

// discoverPeersFromDNS resolves DNS seeds to get peer addresses
func discoverPeersFromDNS() []string {
	var peers []string
	
	for _, seed := range MainnetSeeds {
		fmt.Printf("Resolving DNS seed: %s\n", seed)
		addrs, err := net.LookupHost(seed)
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
	fmt.Println("===================================================")
	
	// Step 1: Discover peers from DNS seeds
	fmt.Println("\n[Step 1] Discovering peers from DNS seeds...")
	peers := discoverPeersFromDNS()
	
	if len(peers) == 0 {
		fmt.Println("No peers found from DNS seeds")
		return
	}
	
	// Step 2: Connect to first available peer
	fmt.Println("\n[Step 2] Connecting to peer...")
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
	
	// Step 3: Perform version handshake
	fmt.Println("\n[Step 3] Performing version handshake...")
	err := peer.sendVersionHandshake()
	if err != nil {
		fmt.Printf("Handshake failed: %v\n", err)
		return
	}
	
	// Step 4: Request peer addresses
	fmt.Println("\n[Step 4] Requesting peer addresses...")
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
/*
// print the first 10 addresses
		for i, addr := range addresses {
			if i >= 10 {
				fmt.Printf("  ... and %d more\n", len(addresses)-10)
				break
			}
*/
// print all of the addresses
// TODO: empty ones after a certain point?? 'range addresses' is not stopping at the right place
		for i, addr := range addresses {
			fmt.Printf("%4d  %s:%d (services: %d)\n", i, addr.Host, addr.Port, addr.Services)
		}
	}
	
	// Step 5: Request block headers starting from genesis
	fmt.Println("\n[Step 5] Requesting block headers...")
	
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
}
