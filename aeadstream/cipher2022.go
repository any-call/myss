package aeadstream

import (
	"crypto/aes"
	"crypto/cipher"

	"lukechampine.com/blake3"
)

// ss2022Context is the fixed context string defined by the 2022 edition spec.
const ss2022Context = "shadowsocks 2022 session subkey"

// blake3DeriveSubkey derives a session subkey using BLAKE3's key-derivation mode.
// key_material = psk || salt, output length = len(psk).
func blake3DeriveSubkey(psk, salt []byte) []byte {
	subkey := make([]byte, len(psk))
	km := make([]byte, 0, len(psk)+len(salt))
	km = append(km, psk...)
	km = append(km, salt...)
	blake3.DeriveKey(subkey, ss2022Context, km)
	return subkey
}

// metaCipher2022 is the 2022-edition counterpart of metaCipher.
// The only difference is that it uses BLAKE3 instead of HKDF-SHA1.
type metaCipher2022 struct {
	psk      []byte
	makeAEAD func(key []byte) (cipher.AEAD, error)
}

func (a *metaCipher2022) KeySize() int  { return len(a.psk) }
func (a *metaCipher2022) SaltSize() int { return len(a.psk) } // 2022 spec: salt length == key length

func (a *metaCipher2022) Encrypter(salt []byte) (cipher.AEAD, error) {
	return a.makeAEAD(blake3DeriveSubkey(a.psk, salt))
}

func (a *metaCipher2022) Decrypter(salt []byte) (cipher.AEAD, error) {
	return a.makeAEAD(blake3DeriveSubkey(a.psk, salt))
}

// AESGCM2022 creates a Cipher for 2022-blake3-aes-128-gcm or 2022-blake3-aes-256-gcm.
// psk must be a raw high-entropy key (16 or 32 bytes).
// Unlike the classic AEAD ciphers, psk must NOT be produced by the MD5-based kdf —
// pass the base64-decoded key directly.
func AESGCM2022(psk []byte) (Cipher, error) {
	switch l := len(psk); l {
	case 16, 32: // AES-128-GCM or AES-256-GCM
	default:
		return nil, aes.KeySizeError(l)
	}
	return &metaCipher2022{psk: psk, makeAEAD: aesGCM}, nil
}
