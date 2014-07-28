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

//export xmlWriteCallback
func xmlWriteCallback(ctx unsafe.Pointer, data *C.char, dataLen C.int) C.int {
	w := (*writer)(ctx)
	if dataLen > 0 {
		if n, err := w.w.Write(C.GoBytes(unsafe.Pointer(data), dataLen)); err != nil {
			w.err = err
			return C.int(-1)
		} else {
			return C.int(n)
		}
	}
	return C.int(0)
}
