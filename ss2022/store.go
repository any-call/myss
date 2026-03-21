package ss2022

// 标准 SS2022 多用户服务端实现（兼容 v2rayN / Xray / Clash / sing-box 等标准客户端）
//
// 用户识别方式：试探解密（trial decryption）
//   - 客户端发送格式与单用户完全相同：[requestSalt][AEAD 加密块流]
//   - 服务端读取 requestSalt + 首个 AEAD size chunk (2+16=18 字节)
//   - 逐一用每个用户 PSK 尝试解密，AES-GCM 认证通过即识别成功
//   - 无需 EIH，无需客户端特殊配置，标准协议

import (
	"crypto/aes"
	"crypto/cipher"
	"errors"
	"fmt"
	"net"
	"sync"

	"lukechampine.com/blake3"
)

var ErrUnknownUser = errors.New("ss2022: unknown user")

const (
	sessionContext  = "shadowsocks 2022 session subkey"
	aesgcmOverhead  = 16 // AES-GCM 认证 tag 长度
	aesgcmNonceSize = 12 // AES-GCM nonce 长度
)

// UserStore 是 SS2022 多用户服务端核心状态。
// 线程安全，用户表可在服务运行中随时增删。
//
//	store, _ := ss2022.NewUserStore(serverPSKBase64) // PSK 只用来确定 keySize
//	store.SetUsers([]string{key1, key2})             // 批量设置
//	store.AddUser(key3)                              // 运行时新增
//	conn = store.StreamConn(rawConn)                 // 包装连接，识别在内部完成
type UserStore struct {
	keySize int

	mu    sync.RWMutex
	users map[string][]byte // base64(PSK) → 原始 PSK 字节
}

// NewUserStore 创建 UserStore。
// serverPSKBase64 只用于确定 keySize（16=AES-128，32=AES-256），不参与加解密。
func NewUserStore(serverPSKBase64 string) (*UserStore, error) {
	var keySize int
	for _, size := range []int{16, 32} {
		if raw, err := decodeKey(serverPSKBase64, size); err == nil {
			_ = raw
			keySize = size
			break
		}
	}
	if keySize == 0 {
		return nil, fmt.Errorf("ss2022: server PSK must be a base64-encoded 16 or 32-byte key")
	}
	return &UserStore{
		keySize: keySize,
		users:   make(map[string][]byte),
	}, nil
}

// SetUsers 原子替换整张用户表。启动初始化和定时刷新均调此函数。
func (s *UserStore) SetUsers(keys []string) error {
	newMap := make(map[string][]byte, len(keys))
	for _, b64 := range keys {
		raw, err := decodeKey(b64, s.keySize)
		if err != nil {
			return fmt.Errorf("ss2022: invalid user key %q: %w", b64, err)
		}
		newMap[b64] = raw
	}
	s.mu.Lock()
	s.users = newMap
	s.mu.Unlock()
	return nil
}

// AddUser 新增或更新一个用户 key，运行时随时可调用。
func (s *UserStore) AddUser(iPSKBase64 string) error {
	raw, err := decodeKey(iPSKBase64, s.keySize)
	if err != nil {
		return err
	}
	s.mu.Lock()
	s.users[iPSKBase64] = raw
	s.mu.Unlock()
	return nil
}

// RemoveUser 删除一个用户 key，运行时随时可调用。
func (s *UserStore) RemoveUser(iPSKBase64 string) {
	s.mu.Lock()
	delete(s.users, iPSKBase64)
	s.mu.Unlock()
}

// UserCount 返回当前用户数。
func (s *UserStore) UserCount() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.users)
}

// StreamConn 包装 TCP 连接，用户识别在内部完成，上层透明。
func (s *UserStore) StreamConn(c net.Conn) net.Conn {
	return &streamConn{Conn: c, store: s}
}

// PacketConn 包装 UDP 连接，用户识别在内部完成，上层透明。
func (s *UserStore) PacketConn(c net.PacketConn) net.PacketConn {
	return &packetConn{PacketConn: c, store: s}
}

// ──────────────────────────────────────────────
// 内部加密工具函数
// ──────────────────────────────────────────────

// blake3SessionSubkey 用 BLAKE3 从 PSK + salt 派生会话子密钥。
func blake3SessionSubkey(psk, salt []byte) []byte {
	subkey := make([]byte, len(psk))
	km := make([]byte, 0, len(psk)+len(salt))
	km = append(km, psk...)
	km = append(km, salt...)
	blake3.DeriveKey(subkey, sessionContext, km)
	return subkey
}

// makeAESGCM 从 key 创建 AES-GCM AEAD。
func makeAESGCM(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// identifyTCP 通过试探解密找到用户 PSK（TCP 用）。
// peek 是首个 AEAD size chunk（2+16=18 字节），解密成功即认证通过。
func (s *UserStore) identifyTCP(salt, peek []byte) ([]byte, error) {
	var zeroNonce [aesgcmNonceSize]byte
	tmp := make([]byte, 2)

	s.mu.RLock()
	defer s.mu.RUnlock()

	for _, rawPSK := range s.users {
		subkey := blake3SessionSubkey(rawPSK, salt)
		aead, err := makeAESGCM(subkey)
		if err != nil {
			continue
		}
		if _, err = aead.Open(tmp[:0], zeroNonce[:], peek, nil); err == nil {
			return rawPSK, nil // AES-GCM 认证通过，找到用户
		}
	}
	return nil, ErrUnknownUser
}

// identifyUDP 通过试探解密找到用户 PSK（UDP 用）。
// ciphertext 是完整的 AEAD 密文（含 tag）。
func (s *UserStore) identifyUDP(salt, ciphertext []byte) ([]byte, error) {
	var zeroNonce [aesgcmNonceSize]byte
	tmp := make([]byte, len(ciphertext))

	s.mu.RLock()
	defer s.mu.RUnlock()

	for _, rawPSK := range s.users {
		subkey := blake3SessionSubkey(rawPSK, salt)
		aead, err := makeAESGCM(subkey)
		if err != nil {
			continue
		}
		if len(ciphertext) < aead.Overhead() {
			continue
		}
		if _, err = aead.Open(tmp[:0], zeroNonce[:], ciphertext, nil); err == nil {
			return rawPSK, nil
		}
	}
	return nil, ErrUnknownUser
}
