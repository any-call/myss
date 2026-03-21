package ss2022

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"sync"

	"github.com/any-call/myss/aeadstream"
)

// ErrUnknownUser 当 EIH 无法匹配任何已知用户 key 时返回。
var ErrUnknownUser = errors.New("ss2022: unknown user")

// UserStore 是 SS2022 多用户服务端的核心状态。
//
// 用户就是一把 key，没有单独的 userID 概念。
// SetUsers / AddUser / RemoveUser 的入参均为 base64 编码的 iPSK 字符串。
//
// 典型生命周期：
//
//	store, _ := ss2022.NewUserStore(serverPSKBase64)
//	store.SetUsers([]string{key1, key2, ...})  // 启动初始化 / 定时从 API 刷新
//	store.AddUser(newKey)                       // 运行时单个新增
//	store.RemoveUser(oldKey)                    // 运行时单个删除
//
//	conn = store.StreamConn(rawTCPConn)         // 包装连接，EIH 识别在内部完成
type UserStore struct {
	serverPSK     []byte
	serverPSKHash []byte           // BLAKE3(serverPSK)[:16]，缓存
	serverCipher  aeadstream.Cipher // 用于会话子密钥派生
	keySize       int

	mu    sync.RWMutex
	users map[string][]byte // base64(iPSK) → 原始 iPSK 字节，base64 作去重 key
}

// NewUserStore 根据 base64 编码的 server PSK 创建 UserStore。
// 传入 GenerateKey(16) 的输出则使用 AES-128，GenerateKey(32) 则使用 AES-256。
func NewUserStore(serverPSKBase64 string) (*UserStore, error) {
	var raw []byte
	var err error
	for _, size := range []int{16, 32} {
		raw, err = decodeKey(serverPSKBase64, size)
		if err == nil {
			break
		}
	}
	if err != nil {
		return nil, fmt.Errorf("ss2022: server PSK must be a base64-encoded 16 or 32-byte key")
	}

	ciph, err := aeadstream.AESGCM2022(raw)
	if err != nil {
		return nil, err
	}

	return &UserStore{
		serverPSK:     raw,
		serverPSKHash: blake3HashPrefix(raw),
		serverCipher:  ciph,
		keySize:       len(raw),
		users:         make(map[string][]byte),
	}, nil
}

// SetUsers 原子替换整张用户 key 表。
// 启动初始化和定时从 API 刷新都调此函数。
// keys 是 base64 编码的 iPSK 字符串切片，重复的自动去重。
func (s *UserStore) SetUsers(keys []string) error {
	newMap := make(map[string][]byte, len(keys))
	for _, b64 := range keys {
		raw, err := decodeKey(b64, s.keySize)
		if err != nil {
			return fmt.Errorf("ss2022: invalid user key %q: %w", b64, err)
		}
		newMap[b64] = raw // base64 字符串作 map key，天然去重
	}
	s.mu.Lock()
	s.users = newMap
	s.mu.Unlock()
	return nil
}

// AddUser 新增一个用户 key。
// 运行时随时可调用，不影响已建立的连接。
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

// RemoveUser 删除一个用户 key。
// 运行时随时可调用，不影响已建立的连接。
func (s *UserStore) RemoveUser(iPSKBase64 string) {
	s.mu.Lock()
	delete(s.users, iPSKBase64)
	s.mu.Unlock()
}

// UserCount 返回当前用户数量。
func (s *UserStore) UserCount() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.users)
}

// StreamConn 将一条原始 TCP 连接包装为 SS2022 多用户加密连接。
func (s *UserStore) StreamConn(c net.Conn) net.Conn {
	return &streamConn{Conn: c, store: s}
}

// PacketConn 将一条原始 UDP PacketConn 包装为 SS2022 多用户加密连接。
func (s *UserStore) PacketConn(c net.PacketConn) net.PacketConn {
	return &packetConn{PacketConn: c, store: s}
}

// identifyUser 遍历用户 key 表，逐一尝试解密 EIH。
// EIH 因含 session_id（每次随机）而每次不同，无法预建字典，O(n) 是协议约束。
// 匹配成功返回该用户的 base64 key，否则返回 ErrUnknownUser。
func (s *UserStore) identifyUser(sessionID, eih []byte) (string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	for b64Key, iPSK := range s.users {
		identitySubkey := blake3DeriveIdentitySubkey(iPSK, sessionID)
		decrypted, err := aesECBDecrypt(identitySubkey, eih)
		if err != nil {
			continue
		}
		if bytes.Equal(decrypted, s.serverPSKHash) {
			return b64Key, nil
		}
	}
	return "", ErrUnknownUser
}
