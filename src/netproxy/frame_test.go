package main

import (
	"bytes"
	"encoding/binary"
	"io"
	"testing"
)

func TestQEMUFramesAreBoundedAndExact(t *testing.T) {
	payload := bytes.Repeat([]byte{0x42}, 64)
	var wire bytes.Buffer
	if err := writeFrame(&wire, payload); err != nil {
		t.Fatal(err)
	}
	got, err := readFrame(&wire)
	if err != nil || !bytes.Equal(got, payload) {
		t.Fatalf("frame mismatch: %v", err)
	}
	for _, size := range []uint32{0, 13, 65537, 0xffffffff} {
		var header [4]byte
		binary.BigEndian.PutUint32(header[:], size)
		if _, err := readFrame(bytes.NewReader(header[:])); err == nil {
			t.Fatalf("invalid size accepted: %d", size)
		}
	}
	if _, err := readFrame(bytes.NewReader([]byte{0, 0, 0, 20, 1, 2})); err != io.ErrUnexpectedEOF {
		t.Fatalf("truncated frame error: %v", err)
	}
}
