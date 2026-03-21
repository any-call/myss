package myss

import (
	"encoding/base64"
	"fmt"
	"github.com/any-call/myss/aeadstream"
	"github.com/any-call/myss/ssstream"
	"net"
	"strings"
)

type listener struct {
	net.Listener
	StreamConnCipher
}

// PickCipher returns a Cipher of the given name. Derive key from password if given key is empty.
func PickCipher(name string, key []byte, password string) (Cipher, error) {
	name = strings.ToLower(name)

	if name == "dummy" {
		return &dummy{}, nil
	}

	// 2022-edition ciphers: PSK must be high-entropy raw bytes.
	// When key is empty, decode it from the base64-encoded password.
	// The MD5-based kdf is intentionally not used here.
	if choice, ok := ss2022List[name]; ok {
		if len(key) == 0 {
			var err error
			key, err = base64.StdEncoding.DecodeString(password)
			if err != nil {
				return nil, fmt.Errorf("2022 cipher requires a base64-encoded PSK as password: %w", err)
			}
		}
		if len(key) != choice.KeySize {
			return nil, aeadstream.KeySizeError(choice.KeySize)
		}
		aead, err := choice.New(key)
		return &AeadCipher{aead}, err
	}

	if choice, ok := aeadList[name]; ok {
		if len(key) == 0 {
			key = kdf(password, choice.KeySize)
		}
		if len(key) != choice.KeySize {
			return nil, aeadstream.KeySizeError(choice.KeySize)
		}

		aead, err := choice.New(key)
		return &AeadCipher{aead}, err
	}

	if choice, ok := streamList[name]; ok {
		if len(key) == 0 {
			key = kdf(password, choice.KeySize)
		}
		if len(key) != choice.KeySize {
			return nil, ssstream.KeySizeError(choice.KeySize)
		}
		ciph, err := choice.New(key)
		return &StreamCipher{ciph}, err
	}

	return nil, ErrCipherNotSupported
}

func Listen(network, address string, ciph StreamConnCipher) (net.Listener, error) {
	l, err := net.Listen(network, address)
	return &listener{l, ciph}, err
}

func (l *listener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	return l.StreamConn(c), err
}

func Dial(network, address string, ciph StreamConnCipher) (net.Conn, error) {
	c, err := net.Dial(network, address)
	return ciph.StreamConn(c), err
}

func ListenPacket(network, address string, ciph PacketConnCipher) (net.PacketConn, error) {
	c, err := net.ListenPacket(network, address)
	return ciph.PacketConn(c), err
}
