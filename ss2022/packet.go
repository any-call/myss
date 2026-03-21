package ss2022

// UDP 多用户包封装
//
// UDP 是无连接的，每个包必须自包含足够的信息用于解密。
//
// 发包格式（客户端 → 服务端）：
//   [session_id (keySize B)] [EIH (16 B)] [AEAD 密文 + tag]
//   AEAD key = BLAKE3_derive_key(serverPSK, session_id)
//   AEAD nonce = 零值（每个 UDP 包独立，session_id 已保证唯一性）
//
// 收包格式（服务端 → 客户端）：
//   [session_id (keySize B)] [AEAD 密文 + tag]
//   无 EIH（客户端持有 serverPSK 可直接解密）

import (
	"crypto/rand"
	"io"
	"net"
	"sync"
)

var _zeroNonce [128]byte // 只读零值 nonce，足够所有 AEAD nonce 长度

var udpBufPool = sync.Pool{
	New: func() interface{} { return make([]byte, 64*1024) },
}

type packetConn struct {
	net.PacketConn
	store *UserStore
}

// WriteTo 加密 b 并发送到 addr（服务端 → 客户端方向）。
// 格式：[session_id (keySize B)] [AEAD 密文 + tag]
func (c *packetConn) WriteTo(b []byte, addr net.Addr) (int, error) {
	buf := udpBufPool.Get().([]byte)
	defer udpBufPool.Put(buf)

	ks := c.store.keySize

	// 生成随机 session_id（用作 salt）
	sessionID := buf[:ks]
	if _, err := io.ReadFull(rand.Reader, sessionID); err != nil {
		return 0, err
	}

	// 派生 AEAD
	aead, err := c.store.serverCipher.Encrypter(sessionID)
	if err != nil {
		return 0, err
	}

	need := ks + len(b) + aead.Overhead()
	if need > len(buf) {
		buf = make([]byte, need)
		copy(buf, sessionID)
		sessionID = buf[:ks]
	}

	out := aead.Seal(buf[ks:ks], _zeroNonce[:aead.NonceSize()], b, nil)
	pkt := buf[:ks+len(out)]

	if _, err := c.PacketConn.WriteTo(pkt, addr); err != nil {
		return 0, err
	}
	return len(b), nil
}

// ReadFrom 从底层读取一个 UDP 包，验证 EIH，解密后写入 b。
// 格式：[session_id (keySize B)] [EIH (16 B)] [AEAD 密文 + tag]
func (c *packetConn) ReadFrom(b []byte) (int, net.Addr, error) {
	buf := udpBufPool.Get().([]byte)
	defer udpBufPool.Put(buf)

	n, addr, err := c.PacketConn.ReadFrom(buf)
	if err != nil {
		return 0, addr, err
	}

	ks := c.store.keySize
	minLen := ks + eihSize

	if n < minLen {
		return 0, addr, ErrUnknownUser // 包太短，直接丢弃
	}

	sessionID := buf[:ks]
	eih := buf[ks : ks+eihSize]
	ciphertext := buf[ks+eihSize : n]

	// EIH 用户识别
	if _, err := c.store.identifyUser(sessionID, eih); err != nil {
		return 0, addr, err // 未知用户，丢包
	}

	// 派生 AEAD 并解密
	aead, err := c.store.serverCipher.Decrypter(sessionID)
	if err != nil {
		return 0, addr, err
	}

	if len(ciphertext) < aead.Overhead() {
		return 0, addr, ErrUnknownUser
	}

	plain, err := aead.Open(b[:0], _zeroNonce[:aead.NonceSize()], ciphertext, nil)
	if err != nil {
		return 0, addr, err
	}

	return len(plain), addr, nil
}
