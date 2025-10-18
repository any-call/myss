package myss

import (
	"crypto/md5"
	"errors"
	"github.com/any-call/myss/aeadstream"
	"github.com/any-call/myss/ssstream"
	"net"
	"sort"
)

var ErrCipherNotSupported = errors.New("cipher not supported")

var aeadList = map[string]struct {
	KeySize int
	New     func([]byte) (aeadstream.Cipher, error)
}{
	"aes-128-gcm":            {16, aeadstream.AESGCM},
	"aes-192-gcm":            {24, aeadstream.AESGCM},
	"aes-256-gcm":            {32, aeadstream.AESGCM},
	"chacha20-ietf-poly1305": {32, aeadstream.Chacha20IETFPoly1305},
}

var streamList = map[string]struct {
	KeySize int
	New     func(key []byte) (ssstream.Cipher, error)
}{
	"aes-128-ctr": {16, ssstream.AESCTR},
	"aes-192-ctr": {24, ssstream.AESCTR},
	"aes-256-ctr": {32, ssstream.AESCTR},
	"aes-128-cfb": {16, ssstream.AESCFB},
	"aes-192-cfb": {24, ssstream.AESCFB},
	"aes-256-cfb": {32, ssstream.AESCFB},
}

func ListCipher() []string {
	var l []string
	for k := range aeadList {
		l = append(l, k)
	}
	for k := range streamList {
		l = append(l, k)
	}
	sort.Strings(l)
	return l
}

type aeadCipher struct{ aeadstream.Cipher }

func (aead *aeadCipher) StreamConn(c net.Conn) net.Conn { return aeadstream.NewConn(c, aead) }
func (aead *aeadCipher) PacketConn(c net.PacketConn) net.PacketConn {
	return aeadstream.NewPacketConn(c, aead)
}

type streamCipher struct{ ssstream.Cipher }

func (ciph *streamCipher) StreamConn(c net.Conn) net.Conn { return ssstream.NewConn(c, ciph) }
func (ciph *streamCipher) PacketConn(c net.PacketConn) net.PacketConn {
	return ssstream.NewPacketConn(c, ciph)
}

// dummy cipher does not encrypt

type dummy struct{}

func (dummy) StreamConn(c net.Conn) net.Conn             { return c }
func (dummy) PacketConn(c net.PacketConn) net.PacketConn { return c }

// key-derivation function from original Shadowsocks
func kdf(password string, keyLen int) []byte {
	var b, prev []byte
	h := md5.New()
	for len(b) < keyLen {
		h.Write(prev)
		h.Write([]byte(password))
		b = h.Sum(b)
		prev = b[len(b)-h.Size():]
		h.Reset()
	}
	return b[:keyLen]
}
