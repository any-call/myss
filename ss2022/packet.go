package ss2022

// UDP 多用户包封装
//
// 收包（客户端 → 服务端）：
//   [salt (keySize B)] [AEAD 密文 + tag]
//   试探解密识别用户 PSK，结果缓存到 addrCache（clientAddr → PSK）
//
// 发包（服务端 → 客户端）：
//   [responseSalt (keySize B)] [AEAD 密文 + tag]
//   从 addrCache 取对应用户 PSK 加密响应
//
// UDP 是无状态的，每个收包都可能来自不同 salt（session），
// addrCache 按客户端地址缓存 PSK，避免对同一客户端重复试探。

import (
	"crypto/rand"
	"io"
	"net"
	"sync"
)

var _zeroNonce [128]byte // 只读零值 nonce

var udpBufPool = sync.Pool{
	New: func() interface{} { return make([]byte, 64*1024) },
}

type packetConn struct {
	net.PacketConn
	store     *UserStore
	addrCache sync.Map // addr.String() → []byte (raw PSK)，收包后缓存，发包时使用
}

// ReadFrom 读取一个 UDP 包，试探解密识别用户，返回明文。
func (c *packetConn) ReadFrom(b []byte) (int, net.Addr, error) {
	buf := udpBufPool.Get().([]byte)
	defer udpBufPool.Put(buf)

	n, addr, err := c.PacketConn.ReadFrom(buf)
	if err != nil {
		return 0, addr, err
	}

	ks := c.store.keySize
	// 最小包：salt + AEAD overhead
	if n < ks+aesgcmOverhead {
		return 0, addr, ErrUnknownUser
	}

	salt := buf[:ks]
	ciphertext := buf[ks:n]

	// 先查 addrCache：同一客户端地址复用已识别的 PSK，避免重复试探
	var userPSK []byte
	if v, ok := c.addrCache.Load(addr.String()); ok {
		userPSK = v.([]byte)
	} else {
		userPSK, err = c.store.identifyUDP(salt, ciphertext)
		if err != nil {
			return 0, addr, err
		}
		c.addrCache.Store(addr.String(), userPSK)
	}

	// 用识别到的 PSK 解密
	subkey := blake3SessionSubkey(userPSK, salt)
	aead, err := makeAESGCM(subkey)
	if err != nil {
		return 0, addr, err
	}

	plain, err := aead.Open(b[:0], _zeroNonce[:aead.NonceSize()], ciphertext, nil)
	if err != nil {
		// PSK 可能已更新（用户重新生成 key），清缓存后用新 PSK 重试
		c.addrCache.Delete(addr.String())
		return 0, addr, err
	}

	return len(plain), addr, nil
}

// WriteTo 加密 b 并发送到 addr（服务端 → 客户端）。
func (c *packetConn) WriteTo(b []byte, addr net.Addr) (int, error) {
	// 从 addrCache 取该客户端的用户 PSK
	v, ok := c.addrCache.Load(addr.String())
	if !ok {
		return 0, ErrUnknownUser
	}
	userPSK := v.([]byte)

	buf := udpBufPool.Get().([]byte)
	defer udpBufPool.Put(buf)

	ks := c.store.keySize

	// 生成随机 responseSalt
	responseSalt := buf[:ks]
	if _, err := io.ReadFull(rand.Reader, responseSalt); err != nil {
		return 0, err
	}

	subkey := blake3SessionSubkey(userPSK, responseSalt)
	aead, err := makeAESGCM(subkey)
	if err != nil {
		return 0, err
	}

	need := ks + len(b) + aead.Overhead()
	if need > len(buf) {
		buf = make([]byte, need)
		copy(buf, responseSalt)
		responseSalt = buf[:ks]
	}

	out := aead.Seal(buf[ks:ks], _zeroNonce[:aead.NonceSize()], b, nil)
	pkt := buf[:ks+len(out)]

	if _, err := c.PacketConn.WriteTo(pkt, addr); err != nil {
		return 0, err
	}
	return len(b), nil
}
