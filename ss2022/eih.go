package ss2022

// EIH (Extended Identity Header) — 身份识别层
//
// 协议约定：
//   客户端发送:  [session_id (keySize B)] [EIH (16 B)] [AEAD 加密的正文流]
//   服务端响应:  [session_id (keySize B)]              [AEAD 加密的正文流]
//
// EIH 构造（客户端）：
//   identity_subkey = BLAKE3_derive_key("shadowsocks 2022 identity subkey", iPSK || session_id)
//   EIH             = AES-128-ECB_encrypt(key=identity_subkey[:16], plain=BLAKE3(serverPSK)[:16])
//
// EIH 验证（服务端）：
//   对每个已知用户 iPSK，尝试解密 EIH，
//   结果等于 BLAKE3(serverPSK)[:16] 即识别成功。

import (
	"crypto/aes"

	"lukechampine.com/blake3"
)

const (
	identityContext = "shadowsocks 2022 identity subkey"
	eihSize         = 16 // EIH 固定 16 字节（一个 AES 块）
)

// blake3DeriveIdentitySubkey 派生身份子密钥（16 字节）。
// key_material = iPSK || session_id
func blake3DeriveIdentitySubkey(iPSK, sessionID []byte) []byte {
	subkey := make([]byte, 16)
	km := make([]byte, 0, len(iPSK)+len(sessionID))
	km = append(km, iPSK...)
	km = append(km, sessionID...)
	blake3.DeriveKey(subkey, identityContext, km)
	return subkey
}

// blake3HashPrefix 返回 BLAKE3(data) 的前 16 字节。
// 用于服务端缓存 BLAKE3(serverPSK)[:16]，EIH 验证时做比较。
func blake3HashPrefix(data []byte) []byte {
	h := blake3.Sum256(data)
	out := make([]byte, 16)
	copy(out, h[:])
	return out
}

// aesECBEncrypt 用 AES-ECB 加密恰好一个 16 字节块。
// ECB 对单块是安全的：没有多块重复明文问题，这里仅用于 EIH 构造。
func aesECBEncrypt(key, plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	ciphertext := make([]byte, 16)
	block.Encrypt(ciphertext, plaintext)
	return ciphertext, nil
}

// aesECBDecrypt 用 AES-ECB 解密恰好一个 16 字节块。
func aesECBDecrypt(key, ciphertext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	plaintext := make([]byte, 16)
	block.Decrypt(plaintext, ciphertext)
	return plaintext, nil
}

// EncodeEIH 供客户端使用：构造 EIH 字节。
//
//	iPSK      — 当前用户的 identity PSK（原始字节）
//	sessionID — 本次连接的随机 session_id（= 请求方向的 salt）
//	serverPSK — 服务端 PSK（原始字节）
func EncodeEIH(iPSK, sessionID, serverPSK []byte) ([]byte, error) {
	identitySubkey := blake3DeriveIdentitySubkey(iPSK, sessionID)
	serverPSKHash := blake3HashPrefix(serverPSK)
	return aesECBEncrypt(identitySubkey, serverPSKHash)
}
