package ss2022

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"io"
	"testing"

	"lukechampine.com/blake3"
)

// clientSideSubkey 模拟 v2rayN 客户端的子密钥派生
func clientSideSubkey(pskRaw, salt []byte) []byte {
	subkey := make([]byte, len(pskRaw))
	km := append(append([]byte{}, pskRaw...), salt...)
	blake3.DeriveKey(subkey, "shadowsocks 2022 session subkey", km)
	return subkey
}

// TestTrialDecrypt 端到端验证：客户端加密固定头部 → 服务端 trial decryption 识别
func TestTrialDecrypt(t *testing.T) {
	pskBase64 := "cAhxN4ND0lV3dOVdWT39nw=="

	// 1. 创建 UserStore 并添加用户
	store, err := NewUserStore(pskBase64) // 用该 PSK 确定 keySize=16
	if err != nil {
		t.Fatalf("NewUserStore: %v", err)
	}
	if err := store.SetUsers([]string{pskBase64}); err != nil {
		t.Fatalf("SetUsers: %v", err)
	}
	t.Logf("store.keySize = %d, userCount = %d", store.keySize, store.UserCount())

	// 2. 模拟客户端：base64 解码 PSK
	pskRaw, err := base64.StdEncoding.DecodeString(pskBase64)
	if err != nil {
		t.Fatalf("decode PSK: %v", err)
	}
	t.Logf("PSK raw (%d bytes): %x", len(pskRaw), pskRaw)

	// 3. 生成 requestSalt
	salt := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		t.Fatalf("generate salt: %v", err)
	}
	t.Logf("salt (%d bytes): %x", len(salt), salt)

	// 4. 客户端推导 session subkey
	clientSubkey := clientSideSubkey(pskRaw, salt)
	t.Logf("client subkey: %x", clientSubkey)

	// 5. 创建客户端 AES-GCM
	block, err := aes.NewCipher(clientSubkey)
	if err != nil {
		t.Fatalf("NewCipher: %v", err)
	}
	clientAEAD, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatalf("NewGCM: %v", err)
	}

	// 6. 用 nonce=0 加密 SS2022 固定头部（27 字节密文 = 11B 明文 + 16B tag）
	//    明文: type(1B=0x00) | timestamp(8B=0) | varHeaderLen(2B=0x00,0x00)
	var zeroNonce [12]byte
	plainFixed := make([]byte, fixedReqHeaderLen) // 11 bytes, 全零
	plainFixed[0] = 0x00                          // type = client request
	// timestamp 和 varHeaderLen 保持零值
	peek := clientAEAD.Seal(nil, zeroNonce[:], plainFixed, nil) // 11 + 16 = 27 bytes
	t.Logf("peek (%d bytes): %x", len(peek), peek)

	// 7. 验证服务端 identifyTCP
	foundPSK, err := store.identifyTCP(salt, peek)
	if err != nil {
		t.Fatalf("identifyTCP FAILED: %v", err)
	}
	t.Logf("identifyTCP OK, foundPSK: %x", foundPSK)

	if string(foundPSK) != string(pskRaw) {
		t.Errorf("PSK mismatch: want %x got %x", pskRaw, foundPSK)
	} else {
		t.Log("✓ PSK match confirmed!")
	}
}

// TestServerSubkeyMatchesClient 直接比对服务端和客户端推导的 subkey 是否相同
func TestServerSubkeyMatchesClient(t *testing.T) {
	pskBase64 := "cAhxN4ND0lV3dOVdWT39nw=="
	pskRaw, _ := base64.StdEncoding.DecodeString(pskBase64)

	salt := make([]byte, 16)
	io.ReadFull(rand.Reader, salt)

	clientKey := clientSideSubkey(pskRaw, salt)
	serverKey := blake3SessionSubkey(pskRaw, salt)

	if string(clientKey) != string(serverKey) {
		t.Errorf("subkey mismatch!\nclient: %x\nserver: %x", clientKey, serverKey)
	} else {
		t.Logf("✓ subkeys match: %x", serverKey)
	}
}

// TestDecodeKey 验证 decodeKey 正常工作
func TestDecodeKey(t *testing.T) {
	keys := []string{
		"cAhxN4ND0lV3dOVdWT39nw==",
		"AndyC4FZkJJXIXjYQ/6Www==",
	}
	for _, k := range keys {
		raw, err := decodeKey(k, 16)
		if err != nil {
			t.Errorf("decodeKey(%q): %v", k, err)
		} else {
			t.Logf("key %q → %d bytes: %x", k, len(raw), raw)
		}
	}
}
