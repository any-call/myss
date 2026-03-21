package ss2022

// TCP 多用户连接封装（符合 SIP022 SS2022 标准协议）
//
// SS2022 TCP 连接格式（客户端 → 服务端）：
//
//   [requestSalt (keySize B)]
//   [固定头部密文 (fixedReqHeaderLen+16 = 27 B), nonce=0, standalone]
//     明文: type(1B=0x00) | timestamp(8B) | varHeaderLen(2B)
//   [可变头部密文 (varHeaderLen+16 B), nonce=1, standalone]
//     明文: SOCKS5 目标地址 (addr_type + addr + port)
//   [length chunk (2+16 B), nonce=2] [payload chunk (N+16 B), nonce=3] ...
//
// SS2022 TCP 连接格式（服务端 → 客户端）：
//
//   [responseSalt (keySize B)]
//   [固定响应头密文 (1+8+keySize+2+16 B), nonce=0, standalone]
//     明文: type(1B=0x01) | timestamp(8B) | requestSalt(keySize B) | varRespHeaderLen(2B=0)
//   [空可变响应头密文 (16 B), nonce=1, standalone]
//   [length chunk (2+16 B), nonce=2] [payload chunk (N+16 B), nonce=3] ...
//
// 用户识别：
//   读取 salt + 固定头部密文（27 B），对每个用户 PSK 尝试 GCM 解密，
//   认证通过即找到用户（trial decryption），无需 EIH。

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"io"
	"net"
	"time"

	"github.com/any-call/myss/aeadstream"
)

type streamConn struct {
	net.Conn
	store       *UserStore
	userPSK     []byte // initReader 成功后填充，initWriter 依赖它
	requestSalt []byte // initReader 保存，initWriter 写入响应头时使用

	r io.Reader
	w io.Writer
}

// initReader 在首次 Read 时触发：
//   1. 读 requestSalt
//   2. 读固定头部密文（27 B）→ trial decryption 识别用户
//   3. 解密固定头部，取出 varHeaderLen
//   4. 读 + 解密可变头部（SOCKS5 目标地址）
//   5. 组合：MultiReader( SOCKS5地址 | aeadstream payload @nonce=2 )
func (c *streamConn) initReader() error {
	ks := c.store.keySize

	// ① 读 requestSalt
	salt := make([]byte, ks)
	if _, err := io.ReadFull(c.Conn, salt); err != nil {
		return err
	}
	c.requestSalt = salt

	// ② 读固定头部密文（27 字节 = fixedReqHeaderLen+aesgcmOverhead）
	//    这是 SS2022 的第一个 standalone chunk，nonce=0
	peekFixed := make([]byte, fixedReqHeaderLen+aesgcmOverhead)
	if _, err := io.ReadFull(c.Conn, peekFixed); err != nil {
		return err
	}

	// ③ Trial decryption：识别用户 PSK
	userPSK, err := c.store.identifyTCP(salt, peekFixed)
	if err != nil {
		return err
	}
	c.userPSK = userPSK

	// ④ 用识别到的 PSK 建立 AEAD，从 nonce=0 开始解密固定头部
	subkey := blake3SessionSubkey(userPSK, salt)
	aead, err := makeAESGCM(subkey)
	if err != nil {
		return err
	}

	// nonce 计数器，小端，从 0 开始
	nonce := make([]byte, aesgcmNonceSize)

	// 解密固定头部（nonce=0）：type(1B) | timestamp(8B) | varHeaderLen(2B)
	plainFixed := make([]byte, fixedReqHeaderLen)
	if _, err = aead.Open(plainFixed[:0], nonce, peekFixed, nil); err != nil {
		return err
	}
	incrementNonce(nonce) // nonce → 1

	// 取出 varHeaderLen（固定头部最后 2 字节，大端）
	varHeaderLen := int(binary.BigEndian.Uint16(plainFixed[fixedReqHeaderLen-2:]))

	// ⑤ 读 + 解密可变头部（nonce=1）：SOCKS5 目标地址
	if varHeaderLen < 0 {
		return ErrUnknownUser
	}
	varChunk := make([]byte, varHeaderLen+aesgcmOverhead)
	if _, err = io.ReadFull(c.Conn, varChunk); err != nil {
		return err
	}
	plainVar := make([]byte, varHeaderLen)
	if _, err = aead.Open(plainVar[:0], nonce, varChunk, nil); err != nil {
		return err
	}
	incrementNonce(nonce) // nonce → 2

	// ⑥ 组合解密流：
	//    - 先把 SOCKS5 地址字节（plainVar）交给上层（mysocks5.ReadAddr）
	//    - 之后的 payload 由 aeadstream 从 nonce=2 继续读取
	c.r = io.MultiReader(
		bytes.NewReader(plainVar),
		aeadstream.NewReaderWithNonce(c.Conn, aead, nonce),
	)
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

// initWriter 在首次 Write 时触发：
//   用识别到的用户 PSK + 新随机 responseSalt 派生子密钥，
//   写入 SS2022 响应固定头部和空可变头部，之后 payload 用 aeadstream @nonce=2。
//
// initReader 一定先于 initWriter 执行（SS 服务端客户端总是先发数据），
// 因此 userPSK 和 requestSalt 在此函数调用时已有值。
func (c *streamConn) initWriter() error {
	if c.userPSK == nil {
		return ErrUnknownUser
	}

	ks := c.store.keySize

	// 生成随机 responseSalt
	responseSalt := make([]byte, ks)
	if _, err := io.ReadFull(rand.Reader, responseSalt); err != nil {
		return err
	}

	subkey := blake3SessionSubkey(c.userPSK, responseSalt)
	aead, err := makeAESGCM(subkey)
	if err != nil {
		return err
	}

	// nonce 计数器，从 0 开始
	nonce := make([]byte, aesgcmNonceSize)

	// 响应固定头部 plaintext：
	//   type(1B=0x01) | timestamp(8B) | requestSalt(ks B) | varRespHeaderLen(2B=0)
	fixedRespLen := 1 + 8 + ks + 2
	plainResp := make([]byte, fixedRespLen)
	plainResp[0] = 0x01 // server response
	binary.BigEndian.PutUint64(plainResp[1:], uint64(time.Now().Unix()))
	copy(plainResp[9:9+ks], c.requestSalt)
	binary.BigEndian.PutUint16(plainResp[9+ks:], 0) // varRespHeaderLen = 0

	// 加密响应固定头部（nonce=0）
	fixedChunk := aead.Seal(nil, nonce, plainResp, nil)
	incrementNonce(nonce) // nonce → 1

	// 加密空可变响应头部（nonce=1）：plaintext = empty → 只有 16 字节 tag
	emptyChunk := aead.Seal(nil, nonce, []byte{}, nil)
	incrementNonce(nonce) // nonce → 2

	// 先发 responseSalt，再发两个响应头密文
	header := make([]byte, 0, ks+len(fixedChunk)+len(emptyChunk))
	header = append(header, responseSalt...)
	header = append(header, fixedChunk...)
	header = append(header, emptyChunk...)
	if _, err = c.Conn.Write(header); err != nil {
		return err
	}

	// payload 流从 nonce=2 开始
	c.w = aeadstream.NewWriterWithNonce(c.Conn, aead, nonce)
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
