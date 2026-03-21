package ss2022

// TCP 多用户连接封装
//
// 读方向（客户端 → 服务端）：
//   [session_id (keySize B)] [EIH (16 B)] [AEAD 加密块流...]
//   ① 读 session_id + EIH
//   ② identifyUser → 找到用户 / 拒绝
//   ③ BLAKE3_derive_key(serverPSK, session_id) → AEAD 解密器
//   ④ 后续字节交给 aeadstream.Reader 透明解密
//
// 写方向（服务端 → 客户端）：
//   [response_salt (keySize B)] [AEAD 加密块流...]
//   响应方向客户端持有 serverPSK 可直接解密，无需 EIH。

import (
	"crypto/rand"
	"io"
	"net"

	"github.com/any-call/myss/aeadstream"
)

// streamConn 实现 net.Conn，对上层透明。
// 上层感知不到 EIH 识别过程，直接 Read/Write 即可。
type streamConn struct {
	net.Conn
	store  *UserStore

	r      io.Reader
	w      io.Writer
	userID string // 识别成功后填充，可通过 UserID() 查询
}

// UserID 返回本次连接识别到的用户 ID。
// 在第一次 Read 之前调用会返回空字符串（识别尚未发生）。
func (c *streamConn) UserID() string {
	return c.userID
}

// initReader 在第一次 Read 时懒初始化：
// 读取 session_id + EIH，完成用户识别，建立 AEAD 解密器。
func (c *streamConn) initReader() error {
	// ① 读 session_id（同时也是请求方向的 salt）
	sessionID := make([]byte, c.store.keySize)
	if _, err := io.ReadFull(c.Conn, sessionID); err != nil {
		return err
	}

	// ② 读 EIH
	eih := make([]byte, eihSize)
	if _, err := io.ReadFull(c.Conn, eih); err != nil {
		return err
	}

	// ③ 用户识别：遍历用户表尝试解密 EIH
	uid, err := c.store.identifyUser(sessionID, eih)
	if err != nil {
		return err // ErrUnknownUser → 上层关闭连接
	}
	c.userID = uid

	// ④ 用 serverPSK + session_id 派生会话 AEAD（BLAKE3）
	aead, err := c.store.serverCipher.Decrypter(sessionID)
	if err != nil {
		return err
	}

	c.r = aeadstream.NewReader(c.Conn, aead)
	return nil
}

func (c *streamConn) Read(b []byte) (int, error) {
	if c.r == nil {
		if err := c.initReader(); err != nil {
			return 0, err
		}
	}
	return c.r.Read(b)
}

// initWriter 在第一次 Write 时懒初始化：
// 生成 response_salt，发送给客户端，建立 AEAD 加密器。
func (c *streamConn) initWriter() error {
	// 响应方向使用独立的随机 salt，客户端用 serverPSK + salt 解密
	salt := make([]byte, c.store.keySize)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return err
	}

	aead, err := c.store.serverCipher.Encrypter(salt)
	if err != nil {
		return err
	}

	// 先把 salt 明文发出去（客户端用它派生解密 key）
	if _, err := c.Conn.Write(salt); err != nil {
		return err
	}

	c.w = aeadstream.NewWriter(c.Conn, aead)
	return nil
}

func (c *streamConn) Write(b []byte) (int, error) {
	if c.w == nil {
		if err := c.initWriter(); err != nil {
			return 0, err
		}
	}
	return c.w.Write(b)
}
