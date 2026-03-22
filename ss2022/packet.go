package ss2022

// UDP 多用户包封装（符合 SIP022 SS2022 标准协议）
//
// SS2022 UDP 包格式（客户端 → 服务端）：
//   [client_session_id (8B)] [packet_id (8B, BE)] [AEAD 密文 + tag]
//   AEAD 明文：type(1B=0x00) | timestamp(8B) | padding_len(2B) | padding | SOCKS5地址 | payload
//
// SS2022 UDP 包格式（服务端 → 客户端）：
//   [server_session_id (8B)] [packet_id (8B, BE)] [AEAD 密文 + tag]
//   AEAD 明文：type(1B=0x01) | timestamp(8B) | client_session_id(8B) | padding_len(2B) | padding | payload
//
// AEAD key：BLAKE3("shadowsocks 2022 session subkey", PSK || session_id[8B])
// AEAD nonce：packet_id_big_endian[8B] || [0x00 × 4]  = 12 字节
//             （packet_id 在前 8 字节，后 4 字节补零，与 sing-shadowsocks 一致）

import (
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"sync"
	"time"
)

const (
	udpSessionIDSize = 8                              // session_id: 8 字节
	udpPacketIDSize  = 8                              // packet_id: 8 字节（big-endian）
	udpOuterHdrSize  = udpSessionIDSize + udpPacketIDSize // 外层头部共 16 字节

	// 客户端内包固定头：type(1B) + timestamp(8B) + padding_len(2B) = 11 字节
	udpClientInnerFixed = 1 + 8 + 2

	// 服务端响应内包固定头：type(1B) + timestamp(8B) + client_session_id(8B) + padding_len(2B) = 19 字节
	udpServerInnerFixed = 1 + 8 + 8 + 2
)

var udpBufPool = sync.Pool{
	New: func() interface{} { return make([]byte, 64*1024) },
}

// udpSessionInfo 缓存单个客户端地址的会话状态。
type udpSessionInfo struct {
	psk             []byte
	clientSessionID [8]byte
	serverSessionID [8]byte
	serverPacketID  uint64
	mu              sync.Mutex
}

type packetConn struct {
	net.PacketConn
	store     *UserStore
	addrCache sync.Map // addr.String() → *udpSessionInfo
}

// buildUDPNonce 将 8 字节大端 packet_id 扩展为 12 字节 AES-GCM nonce：
//   nonce = packet_id_bytes[0:8] + [0x00, 0x00, 0x00, 0x00]
// 与 sing-shadowsocks 的实现一致：binary.BigEndian.PutUint64(nonce[:], packetID)
// packet_id 放在 nonce 的前 8 字节，后 4 字节补零。
func buildUDPNonce(packetIDBytes []byte) [aesgcmNonceSize]byte {
	var nonce [aesgcmNonceSize]byte
	copy(nonce[0:8], packetIDBytes[:8]) // packet_id 在 nonce[0:8]，nonce[8:12]=0
	return nonce
}

// ReadFrom 读取一个 SS2022 UDP 包，识别用户，解密，剥除内包头部，
// 返回明文（SOCKS5 地址 + payload）。
func (c *packetConn) ReadFrom(b []byte) (int, net.Addr, error) {
	buf := udpBufPool.Get().([]byte)
	defer udpBufPool.Put(buf)

	n, addr, err := c.PacketConn.ReadFrom(buf)
	if err != nil {
		return 0, addr, err
	}

	// ── DEBUG: 打印原始 UDP 包前 40 字节，帮助确认协议格式 ──
	dumpLen := n
	if dumpLen > 40 {
		dumpLen = 40
	}
	fmt.Printf("[ss2022 UDP DEBUG] from=%s  len=%d  hex[0:%d]=%s\n",
		addr, n, dumpLen, hex.EncodeToString(buf[:dumpLen]))
	// ────────────────────────────────────────────────────────

	// 最小包：外层头部(16) + AEAD tag(16) + 内包最小(11) = 43
	if n < udpOuterHdrSize+aesgcmOverhead+udpClientInnerFixed {
		return 0, addr, ErrUnknownUser
	}

	sessionID := buf[0:8]      // client_session_id
	packetIDBytes := buf[8:16] // packet_id（big-endian）
	ciphertext := buf[16:n]

	nonce := buildUDPNonce(packetIDBytes)

	// 查 addrCache，命中且 session_id 相同则复用 PSK
	var userPSK []byte
	var si *udpSessionInfo

	if v, ok := c.addrCache.Load(addr.String()); ok {
		cached := v.(*udpSessionInfo)
		var sid [8]byte
		copy(sid[:], sessionID)
		if cached.clientSessionID == sid {
			userPSK = cached.psk
			si = cached
		}
	}

	if userPSK == nil {
		// trial decryption：逐 PSK 尝试
		userPSK, err = c.store.identifyUDP(sessionID, nonce[:], ciphertext)
		if err != nil {
			return 0, addr, err
		}
		newSI := &udpSessionInfo{psk: userPSK}
		copy(newSI.clientSessionID[:], sessionID)
		if _, err2 := io.ReadFull(rand.Reader, newSI.serverSessionID[:]); err2 != nil {
			return 0, addr, err2
		}
		c.addrCache.Store(addr.String(), newSI)
		si = newSI
	}
	_ = si // si 在 WriteTo 时使用

	// 用 session_id（仅 8B）派生子密钥并解密
	subkey := blake3SessionSubkey(userPSK, sessionID)
	aead, err := makeAESGCM(subkey)
	if err != nil {
		return 0, addr, err
	}

	plain, err := aead.Open(b[:0], nonce[:], ciphertext, nil)
	if err != nil {
		c.addrCache.Delete(addr.String())
		return 0, addr, err
	}

	// 剥除内包固定头：type(1B) + timestamp(8B) + padding_len(2B) + padding
	if len(plain) < udpClientInnerFixed {
		return 0, addr, ErrUnknownUser
	}
	paddingLen := int(binary.BigEndian.Uint16(plain[9:11]))
	skip := udpClientInnerFixed + paddingLen
	if skip > len(plain) {
		return 0, addr, ErrUnknownUser
	}

	// 将有效 payload（SOCKS5 地址 + 数据）移到 b 头部
	payload := plain[skip:]
	copy(b, payload) // 安全：Go copy 正确处理重叠
	return len(payload), addr, nil
}

// WriteTo 加密 b 并发送到 addr（服务端 → 客户端），符合 SS2022 UDP 响应格式。
func (c *packetConn) WriteTo(b []byte, addr net.Addr) (int, error) {
	v, ok := c.addrCache.Load(addr.String())
	if !ok {
		return 0, ErrUnknownUser
	}
	si := v.(*udpSessionInfo)

	si.mu.Lock()
	packetID := si.serverPacketID
	si.serverPacketID++
	si.mu.Unlock()

	var packetIDBytes [8]byte
	binary.BigEndian.PutUint64(packetIDBytes[:], packetID)
	nonce := buildUDPNonce(packetIDBytes[:])

	subkey := blake3SessionSubkey(si.psk, si.serverSessionID[:])
	aead, err := makeAESGCM(subkey)
	if err != nil {
		return 0, err
	}

	// 构造响应内包明文：
	//   type(1B=0x01) + timestamp(8B) + client_session_id(8B) + padding_len(2B=0) + payload
	inner := make([]byte, udpServerInnerFixed+len(b))
	inner[0] = 0x01 // server response type
	binary.BigEndian.PutUint64(inner[1:], uint64(time.Now().Unix()))
	copy(inner[9:17], si.clientSessionID[:])
	binary.BigEndian.PutUint16(inner[17:19], 0) // padding_len = 0
	copy(inner[udpServerInnerFixed:], b)

	ciphertext := aead.Seal(nil, nonce[:], inner, nil)

	// 组装发送包：[server_session_id(8B)][packet_id(8B)][ciphertext]
	pkt := make([]byte, udpOuterHdrSize+len(ciphertext))
	copy(pkt[0:8], si.serverSessionID[:])
	copy(pkt[8:16], packetIDBytes[:])
	copy(pkt[16:], ciphertext)

	if _, err := c.PacketConn.WriteTo(pkt, addr); err != nil {
		return 0, err
	}
	return len(b), nil
}
