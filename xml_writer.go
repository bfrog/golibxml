package golibxml

import "C"

import (
	"io"
	"unsafe"
)

// writer used internally for libxml OutputBuffer callback context
type writer struct {
	w   io.Writer
	err error
}

// newWriter
func newWriter(w io.Writer) *writer {
	return &writer{
		w:   w,
		err: nil,
	}
}

// UnsafePtr to writer
func (w *writer) UnsafePtr() unsafe.Pointer {
	return unsafe.Pointer(w)
}

//export xmlWriteCallback
func xmlWriteCallback(ctx unsafe.Pointer, dataPtr *C.char, dataLen C.int) C.int {
	w := (*writer)(ctx)
	if dataLen > 0 {
		data := C.GoBytes(unsafe.Pointer(dataPtr), dataLen)
		if n, err := w.w.Write(data); err != nil {
			w.err = err
			return C.int(-1)
		} else {
			return C.int(n)
		}
	}
	return C.int(0)
}
