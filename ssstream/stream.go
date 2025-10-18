package ssstream

import (
	"bytes"
	"crypto/cipher"
	"crypto/rand"
	"io"
	"net"
	"sync"
)

var (
	streamPool = sync.Pool{
		New: func() interface{} {
			return make([]byte, 32*1024)
		},
	}
)

type writer struct {
	io.Writer
	cipher.Stream
}

// NewWriter wraps an io.Writer with stream cipher encryption.
func NewWriter(w io.Writer, s cipher.Stream) io.Writer {
	return &writer{Writer: w, Stream: s}
}

func (w *writer) ReadFrom(r io.Reader) (n int64, err error) {
	cBuf := streamPool.Get().([]byte)
	defer streamPool.Put(cBuf)
	for {
		buf := cBuf
		nr, er := r.Read(buf)
		if nr > 0 {
			n += int64(nr)
			buf = buf[:nr]
			w.XORKeyStream(buf, buf)
			_, ew := w.Writer.Write(buf)
			if ew != nil {
				err = ew
				break
			}
		}

		if er != nil {
			if er != io.EOF { // ignore EOF as per io.ReaderFrom contract
				err = er
			}
			break
		}
	}

	return n, err
}

func (w *writer) Write(b []byte) (int, error) {
	n, err := w.ReadFrom(bytes.NewBuffer(b))
	return int(n), err
}

type reader struct {
	io.Reader
	cipher.Stream
}

// NewReader wraps an io.Reader with stream cipher decryption.
func NewReader(r io.Reader, s cipher.Stream) io.Reader {
	return &reader{Reader: r, Stream: s}
}

func (r *reader) Read(b []byte) (int, error) {
	n, err := r.Reader.Read(b)
	if err != nil {
		return 0, err
	}
	b = b[:n]
	r.XORKeyStream(b, b)
	return n, nil
}

func (r *reader) WriteTo(w io.Writer) (n int64, err error) {
	cBuf := streamPool.Get().([]byte)
	defer streamPool.Put(cBuf)
	for {
		buf := cBuf
		nr, er := r.Read(buf)
		if nr > 0 {
			nw, ew := w.Write(buf[:nr])
			n += int64(nw)

			if ew != nil {
				err = ew
				break
			}
		}

		if er != nil {
			if er != io.EOF { // ignore EOF as per io.Copy contract (using src.WriteTo shortcut)
				err = er
			}
			break
		}
	}

	return n, err
}

type SSConn struct {
	net.Conn
	Cipher
	r *reader
	w *writer
}

// NewConn wraps a stream-oriented net.Conn with stream cipher encryption/decryption.
func NewConn(c net.Conn, ciph Cipher) net.Conn {
	return &SSConn{Conn: c, Cipher: ciph}
}

func (c *SSConn) initReader() error {
	if c.r == nil {
		buf := streamPool.Get().([]byte)
		defer streamPool.Put(buf)
		iv := buf[:c.IVSize()]
		if _, err := io.ReadFull(c.Conn, iv); err != nil {
			return err
		}
		c.r = &reader{Reader: c.Conn, Stream: c.Decrypter(iv)}
	}
	return nil
}

func (c *SSConn) Read(b []byte) (int, error) {
	if c.r == nil {
		if err := c.initReader(); err != nil {
			return 0, err
		}
	}

	return c.r.Read(b)

}

func (c *SSConn) WriteTo(w io.Writer) (int64, error) {
	if c.r == nil {
		if err := c.initReader(); err != nil {
			return 0, err
		}
	}

	return c.r.WriteTo(w)
}

func (c *SSConn) initWriter() error {
	if c.w == nil {
		buf := streamPool.Get().([]byte)
		defer streamPool.Put(buf)
		iv := buf[:c.IVSize()]
		if _, err := io.ReadFull(rand.Reader, iv); err != nil {
			return err
		}
		if _, err := c.Conn.Write(iv); err != nil {
			return err
		}
		c.w = &writer{Writer: c.Conn, Stream: c.Encrypter(iv)}
	}
	return nil
}

func (c *SSConn) Write(b []byte) (int, error) {
	if c.w == nil {
		if err := c.initWriter(); err != nil {
			return 0, err
		}
	}
	return c.w.Write(b)
}

func (c *SSConn) ReadFrom(r io.Reader) (int64, error) {
	if c.w == nil {
		if err := c.initWriter(); err != nil {
			return 0, err
		}
	}
	return c.w.ReadFrom(r)
}

type closeWriter interface {
	CloseWrite() error
}

type closeReader interface {
	CloseRead() error
}

func (c *SSConn) CloseRead() error {
	if c, ok := c.Conn.(closeReader); ok {
		return c.CloseRead()
	}
	return nil
}

func (c *SSConn) CloseWrite() error {
	if c, ok := c.Conn.(closeWriter); ok {
		return c.CloseWrite()
	}
	return nil
}
