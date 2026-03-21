package aeadstream

import (
	"bytes"
	"crypto/cipher"
	"crypto/rand"
	"io"
	"net"
)

// payloadSizeMask is the maximum size of payload in bytes.
const payloadSizeMask = 0x3FFF // 16*1024 - 1

type Writer struct {
	io.Writer
	cipher.AEAD
	nonce []byte
	buf   []byte
}

// NewWriter wraps an io.Writer with AEAD encryption.
func NewWriter(w io.Writer, aead cipher.AEAD) io.Writer {
	return newWriter(w, aead)
}

// NewWriterWithNonce wraps an io.Writer with AEAD encryption, starting at startNonce.
// startNonce must have the same length as aead.NonceSize(); it is copied and then
// incremented in place after each sealed chunk.
// Use this when the nonce counter must resume from a value > 0 (e.g. after two
// standalone SS2022 header chunks the payload writer should start at nonce 2).
func NewWriterWithNonce(w io.Writer, aead cipher.AEAD, startNonce []byte) io.Writer {
	wr := newWriter(w, aead)
	if len(startNonce) == len(wr.nonce) {
		copy(wr.nonce, startNonce)
	}
	return wr
}

func newWriter(w io.Writer, aead cipher.AEAD) *Writer {
	return &Writer{
		Writer: w,
		AEAD:   aead,
		buf:    make([]byte, 2+aead.Overhead()+payloadSizeMask+aead.Overhead()),
		nonce:  make([]byte, aead.NonceSize()),
	}
}

// Write encrypts b and writes to the embedded io.Writer.
func (w *Writer) Write(b []byte) (int, error) {
	n, err := w.ReadFrom(bytes.NewBuffer(b))
	return int(n), err
}

// ReadFrom reads from the given io.Reader until EOF or error, encrypts and
// writes to the embedded io.Writer. Returns number of bytes read from r and
// any error encountered.
func (w *Writer) ReadFrom(r io.Reader) (n int64, err error) {
	for {
		buf := w.buf
		payloadBuf := buf[2+w.Overhead() : 2+w.Overhead()+payloadSizeMask]
		nr, er := r.Read(payloadBuf)

		if nr > 0 {
			n += int64(nr)
			buf = buf[:2+w.Overhead()+nr+w.Overhead()]
			payloadBuf = payloadBuf[:nr]
			buf[0], buf[1] = byte(nr>>8), byte(nr) // big-endian payload size
			w.Seal(buf[:0], w.nonce, buf[:2], nil)
			increment(w.nonce)

			w.Seal(payloadBuf[:0], w.nonce, payloadBuf, nil)
			increment(w.nonce)

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

type Reader struct {
	io.Reader
	cipher.AEAD
	nonce    []byte
	buf      []byte
	leftover []byte
}

// NewReader wraps an io.Reader with AEAD decryption.
func NewReader(r io.Reader, aead cipher.AEAD) io.Reader {
	return newReader(r, aead)
}

// NewReaderWithNonce wraps an io.Reader with AEAD decryption, starting at startNonce.
// startNonce must have the same length as aead.NonceSize(); it is copied and then
// incremented in place after each opened chunk part (size + payload = +2 per record).
// Use this when the nonce counter must resume from a value > 0 (e.g. after two
// standalone SS2022 header chunks the payload reader should start at nonce 2).
func NewReaderWithNonce(r io.Reader, aead cipher.AEAD, startNonce []byte) io.Reader {
	rd := newReader(r, aead)
	if len(startNonce) == len(rd.nonce) {
		copy(rd.nonce, startNonce)
	}
	return rd
}

func newReader(r io.Reader, aead cipher.AEAD) *Reader {
	return &Reader{
		Reader: r,
		AEAD:   aead,
		buf:    make([]byte, payloadSizeMask+aead.Overhead()),
		nonce:  make([]byte, aead.NonceSize()),
	}
}

// read and decrypt a record into the internal buffer. Return decrypted payload length and any error encountered.
func (r *Reader) read() (int, error) {
	//add by luis
	//在解包前，如果有上次没有传完的数据，则先将上次数据返出
	if len(r.leftover) > 0 {
		n := copy(r.buf, r.leftover)
		r.leftover = r.leftover[n:]
		return n, nil
	}
	//end add
	var allTotalSize int64 = 0
	// decrypt payload size
	buf := r.buf[:2+r.Overhead()]
	mylen, err := io.ReadFull(r.Reader, buf)
	if err != nil {
		return 0, err
	}
	allTotalSize += int64(mylen)

	_, err = r.Open(buf[:0], r.nonce, buf, nil)
	increment(r.nonce)
	if err != nil {
		return 0, err
	}

	size := (int(buf[0])<<8 + int(buf[1])) & payloadSizeMask

	// decrypt payload
	buf = r.buf[:size+r.Overhead()]
	mylen, err = io.ReadFull(r.Reader, buf)
	if err != nil {
		return 0, err
	}
	allTotalSize += int64(mylen)

	_, err = r.Open(buf[:0], r.nonce, buf, nil)
	increment(r.nonce)
	if err != nil {
		return 0, err
	}

	return size, nil
}

// Read reads from the embedded io.Reader, decrypts and writes to b.
func (r *Reader) Read(b []byte) (int, error) {
	// copy decrypted bytes (if any) from previous record first
	if len(r.leftover) > 0 {
		n := copy(b, r.leftover)
		r.leftover = r.leftover[n:]
		return n, nil
	}

	n, err := r.read()
	m := copy(b, r.buf[:n])
	if m < n { // insufficient len(b), keep leftover for next read
		r.leftover = r.buf[m:n]
	}
	return m, err
}

// WriteTo reads from the embedded io.Reader, decrypts and writes to w until
// there's no more data to write or when an error occurs. Return number of
// bytes written to w and any error encountered.
func (r *Reader) WriteTo(w io.Writer) (n int64, err error) {
	for {
		nr, er := r.read()
		if nr > 0 {
			nw, ew := w.Write(r.buf[:nr])
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

// increment little-endian encoded unsigned integer b. Wrap around on overflow.
func increment(b []byte) {
	for i := range b {
		b[i]++
		if b[i] != 0 {
			return
		}
	}
}

type closeWriter interface {
	CloseWrite() error
}

type closeReader interface {
	CloseRead() error
}

const payloadHeaderSize = 5 ///定义tcp playload 的前5个字节，用于判定请求类型

type StreamConn struct {
	net.Conn
	Cipher
	r *Reader
	w *Writer
}

func (c *StreamConn) initReader() error {
	salt := make([]byte, c.SaltSize())
	if _, err := io.ReadFull(c.Conn, salt); err != nil {
		return err
	}

	aead, err := c.Decrypter(salt)
	if err != nil {
		return err
	}

	c.r = newReader(c.Conn, aead)
	return nil
}

func (c *StreamConn) Read(b []byte) (int, error) {
	if c.r == nil {
		if err := c.initReader(); err != nil {
			return 0, err
		}
	}
	return c.r.Read(b)
}

func (c *StreamConn) WriteTo(w io.Writer) (int64, error) {
	if c.r == nil {
		if err := c.initReader(); err != nil {
			return 0, err
		}
	}
	return c.r.WriteTo(w)
}

func (c *StreamConn) initWriter() error {
	salt := make([]byte, c.SaltSize())
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return err
	}
	aead, err := c.Encrypter(salt)
	if err != nil {
		return err
	}
	_, err = c.Conn.Write(salt)
	if err != nil {
		return err
	}
	c.w = newWriter(c.Conn, aead)
	return nil
}

func (c *StreamConn) Write(b []byte) (int, error) {
	if c.w == nil {
		if err := c.initWriter(); err != nil {
			return 0, err
		}
	}
	return c.w.Write(b)
}

func (c *StreamConn) ReadFrom(r io.Reader) (int64, error) {
	if c.w == nil {
		if err := c.initWriter(); err != nil {
			return 0, err
		}
	}
	return c.w.ReadFrom(r)
}

func (c *StreamConn) CloseRead() error {
	if c, ok := c.Conn.(closeReader); ok {
		return c.CloseRead()
	}
	return nil
}

func (c *StreamConn) CloseWrite() error {
	if c, ok := c.Conn.(closeWriter); ok {
		return c.CloseWrite()
	}
	return nil
}

// NewConn wraps a stream-oriented net.Conn with cipher.
func NewConn(c net.Conn, ciph Cipher) net.Conn { return &StreamConn{Conn: c, Cipher: ciph} }
