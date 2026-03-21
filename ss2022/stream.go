package ss2022

// TCP 多用户连接封装
//
// 读方向（客户端 → 服务端）：
//   [requestSalt (keySize B)] [AEAD 加密块流 (size_chunk + payload_chunk + ...)]
//
//   ① 读 requestSalt
//   ② 偷看首个 size chunk（2+16=18 字节），试探解密识别用户 PSK
//   ③ 把偷看的字节"放回去"（io.MultiReader），用识别到的 PSK 建 AEAD Reader
//   ④ Reader 从 nonce=0 开始正常处理完整流
//
// 写方向（服务端 → 客户端）：
//   [responseSalt (keySize B)] [AEAD 加密块流]
//   响应使用同一用户 PSK + 新随机 responseSalt 派生子密钥。

import (
	"bytes"
	"crypto/rand"
	"io"
	"net"

	"github.com/any-call/myss/aeadstream"
)

type streamConn struct {
	net.Conn
	store   *UserStore
	userPSK []byte // 识别成功后填充，initWriter 依赖它

	r io.Reader
	w io.Writer
}

// initReader 在首次 Read 时触发：识别用户并建立解密流。
func (c *streamConn) initReader() error {
	ks := c.store.keySize

	// ① 读 requestSalt
	salt := make([]byte, ks)
	if _, err := io.ReadFull(c.Conn, salt); err != nil {
		return err
	}

	// ② 偷看首个 AEAD size chunk（2 字节明文大小 + 16 字节 GCM tag）
	//    这 18 字节足以完成 GCM 认证，用于试探解密
	peek := make([]byte, 2+aesgcmOverhead)
	if _, err := io.ReadFull(c.Conn, peek); err != nil {
		return err
	}

	// ③ 试探解密：用每个用户 PSK 尝试，GCM 认证通过即找到用户
	userPSK, err := c.store.identifyTCP(salt, peek)
	if err != nil {
		return err
	}
	c.userPSK = userPSK

	// ④ 建 AEAD Reader：
	//    用 io.MultiReader 把偷看的字节放回流头部，Reader 从 nonce=0 正常处理
	subkey := blake3SessionSubkey(userPSK, salt)
	aead, err := makeAESGCM(subkey)
	if err != nil {
		return err
	}

	combined := io.MultiReader(bytes.NewReader(peek), c.Conn)
	c.r = aeadstream.NewReader(combined, aead)
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

// initWriter 在首次 Write 时触发：用识别到的用户 PSK 建立加密流。
// SS 服务端模式下，客户端总是先发数据（Read 先于 Write），
// 所以 initReader 一定在 initWriter 之前完成，userPSK 已有值。
func (c *streamConn) initWriter() error {
	if c.userPSK == nil {
		return ErrUnknownUser
	}

	// 生成随机 responseSalt，发给客户端用于派生解密 key
	salt := make([]byte, c.store.keySize)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return err
	}

	subkey := blake3SessionSubkey(c.userPSK, salt)
	aead, err := makeAESGCM(subkey)
	if err != nil {
		return err
	}

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
