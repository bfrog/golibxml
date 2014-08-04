package xml

import "C"

import (
	"io"
	"reflect"
	"unsafe"
)

// ioWriter used internally for libxml output callback context
type ioWriter struct {
	w   io.Writer
	err error
}

// newWriter
func newWriter(w io.Writer) *ioWriter {
	return &ioWriter{
		w:   w,
		err: nil,
	}
}

// UnsafePtr to writer
func (w *ioWriter) UnsafePtr() unsafe.Pointer {
	return unsafe.Pointer(w)
}

//export xmlWriteCallback
func xmlWriteCallback(ctx unsafe.Pointer, dataPtr *C.char, dataLen C.int) C.int {
	w := (*ioWriter)(ctx)
	if dataLen > 0 {
		bytes := *(*[]byte)(unsafe.Pointer(&reflect.SliceHeader{Len: int(dataLen), Cap: int(dataLen), Data: uintptr(unsafe.Pointer(dataPtr))}))
		if n, err := w.w.Write(bytes); err != nil {
			w.err = err
			return C.int(-1)
		} else {
			return C.int(n)
		}
	}
	return C.int(0)
}

// ioReader used internally for libxml input callback context
type ioReader struct {
	r   io.Reader
	err error
}

// newReader
func newReader(r io.Reader) *ioReader {
	return &ioReader{
		r:   r,
		err: nil,
	}
}

func (r *ioReader) UnsafePtr() unsafe.Pointer {
	return unsafe.Pointer(r)
}

//export xmlReadCallback
func xmlReadCallback(ctx unsafe.Pointer, dataPtr *C.char, dataLen C.int) C.int {
	r := (*ioReader)(ctx)
	if dataLen > 0 {
		bytes := *(*[]byte)(unsafe.Pointer(&reflect.SliceHeader{Len: int(dataLen), Cap: int(dataLen), Data: uintptr(unsafe.Pointer(dataPtr))}))
		var n int
		n, r.err = r.r.Read(bytes)
		if r.err != nil {
			return -1
		}
		return C.int(n)
	}
	return 0
}
