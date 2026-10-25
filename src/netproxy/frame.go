package main

import (
	"encoding/binary"
	"errors"
	"io"
)

func readFrame(r io.Reader) ([]byte, error) {
	var header [4]byte
	if _, err := io.ReadFull(r, header[:]); err != nil {
		return nil, err
	}
	n := binary.BigEndian.Uint32(header[:])
	if n < 14 || n > 65536 {
		return nil, errors.New("invalid Ethernet frame length")
	}
	b := make([]byte, n)
	_, err := io.ReadFull(r, b)
	return b, err
}

func writeFrame(w io.Writer, b []byte) error {
	if len(b) < 14 || len(b) > 65536 {
		return errors.New("invalid Ethernet frame length")
	}
	var header [4]byte
	binary.BigEndian.PutUint32(header[:], uint32(len(b)))
	for _, p := range [][]byte{header[:], b} {
		for len(p) > 0 {
			n, err := w.Write(p)
			if err != nil {
				return err
			}
			if n <= 0 {
				return io.ErrShortWrite
			}
			p = p[n:]
		}
	}
	return nil
}
