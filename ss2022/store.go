package ss2022

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"sync"

	"github.com/any-call/myss/aeadstream"
)

// ErrUnknownUser 当 EIH 无法匹配任何已知用户时返回。
var ErrUnknownUser = errors.New("ss2022: unknown user")

// UserStore 是 SS2022 多用户服务端的核心状态。
//
// 它持有：
//   - server PSK（固定，服务启动后不变）
//   - 用户表（动态，可随时 Add/Remove，读写均并发安全）
//
// 典型生命周期：
//
//	store, _ := ss2022.NewUserStore(serverPSKBase64)
//	store.SetUsers(usersFromAPI)           // 启动初始化 / 定时从 API 刷新，均调此函数
//	store.AddUser("uid_001", iPSKBase64)   // 运行时单个新增
//	store.RemoveUser("uid_002")            // 运行时单个删除
//
//	conn = store.StreamConn(rawTCPConn)    // 包装连接，EIH 识别在内部完成
type UserStore struct {
	serverPSK     []byte
	serverPSKHash []byte           // BLAKE3(serverPSK)[:16]，缓存避免重复计算
	serverCipher  aeadstream.Cipher // 用于会话子密钥派生
	keySize       int

	mu    sync.RWMutex
	users map[string][]byte // userID → 原始 iPSK 字节
}

// NewUserStore 根据 base64 编码的 server PSK 创建 UserStore。
// serverPSKBase64 必须是 GenerateKey(16) 或 GenerateKey(32) 的输出。
func NewUserStore(serverPSKBase64 string) (*UserStore, error) {
	// 先尝试 16 字节，再尝试 32 字节
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

// SetUsers 原子替换整张用户表。
// 启动时初始化、运行时定时从 API 刷新，都调这一个函数。
// users 是 map[userID]base64iPSK。
// 替换是原子的：新旧 map 整体切换，不会出现中间状态。
func (s *UserStore) SetUsers(users map[string]string) error {
	newMap := make(map[string][]byte, len(users))
	for id, b64 := range users {
		raw, err := decodeKey(b64, s.keySize)
		if err != nil {
			return fmt.Errorf("ss2022: user %q: %w", id, err)
		}
		newMap[id] = raw
	}
	s.mu.Lock()
	s.users = newMap
	s.mu.Unlock()
	return nil
}

// AddUser 新增或更新一个用户。
// 运行时随时可调用，不影响已建立的连接。
func (s *UserStore) AddUser(userID, iPSKBase64 string) error {
	raw, err := decodeKey(iPSKBase64, s.keySize)
	if err != nil {
		return err
	}
	s.mu.Lock()
	s.users[userID] = raw
	s.mu.Unlock()
	return nil
}

// RemoveUser 删除一个用户。
// 运行时随时可调用，不影响已建立的连接。
func (s *UserStore) RemoveUser(userID string) {
	s.mu.Lock()
	delete(s.users, userID)
	s.mu.Unlock()
}

// UserCount 返回当前用户数量。
func (s *UserStore) UserCount() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.users)
}

// StreamConn 将一条原始 TCP 连接包装为 SS2022 多用户加密连接。
// 上层直接当 net.Conn 使用，EIH 识别完全在内部完成。
func (s *UserStore) StreamConn(c net.Conn) net.Conn {
	return &streamConn{Conn: c, store: s}
}

// PacketConn 将一条原始 UDP PacketConn 包装为 SS2022 多用户加密连接。
func (s *UserStore) PacketConn(c net.PacketConn) net.PacketConn {
	return &packetConn{PacketConn: c, store: s}
}

// identifyUser 遍历用户表，尝试用每个 iPSK 解密 EIH。
// 解密结果等于 serverPSKHash 则识别成功，返回 userID。
// 时间复杂度 O(n)，n 为用户数。对于常见规模（千级以下）可接受。
func (s *UserStore) identifyUser(sessionID, eih []byte) (string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	for userID, iPSK := range s.users {
		identitySubkey := blake3DeriveIdentitySubkey(iPSK, sessionID)
		decrypted, err := aesECBDecrypt(identitySubkey, eih)
		if err != nil {
			continue
		}
		if bytes.Equal(decrypted, s.serverPSKHash) {
			return userID, nil
		}
	}
	return "", ErrUnknownUser
}
