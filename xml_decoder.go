package xml

/*
#include "xml.h"
*/
import "C"

import (
	"errors"
	"io"
	"unsafe"
)

var ErrDecoding = errors.New("error decoding xml")

// Decoder decodes xml using a io.Reader as input
type Decoder struct {
	reader  io.Reader
	options ParserOption
}

func NewDecoder(reader io.Reader, opts ParserOption) *Decoder {
	return &Decoder{
		reader:  reader,
		options: opts,
	}
}

// Decode from the reader creating a Document
func (dec *Decoder) Decode() (doc *Document, err error) {
	r := newReader(dec.reader)
	var docPtr C.xmlDocPtr
	docPtr = C.xmlDecode(r.UnsafePtr(), (*C.char)(unsafe.Pointer(nil)), C.int(dec.options))
	if docPtr != nil {
		doc = makeDoc(docPtr)
	} else {
		if r.err != nil {
			return nil, r.err
		}
		return doc, ErrDecoding
	}
	return doc, nil
}
