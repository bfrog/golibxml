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

var ErrEncoding = errors.New("error encoding xml")

// EncodingOption is a set of flags used to control how a node is written out.
type EncodingOption int

const (
	XML_SAVE_FORMAT   EncodingOption = 1 << iota // format save output
	XML_SAVE_NO_DECL                             //drop the xml declaration
	XML_SAVE_NO_EMPTY                            //no empty tags
	XML_SAVE_NO_XHTML                            //disable XHTML1 specific rules
	XML_SAVE_XHTML                               //force XHTML1 specific rules
	XML_SAVE_AS_XML                              //force XML serialization on HTML doc
	XML_SAVE_AS_HTML                             //force HTML serialization on XML doc
	XML_SAVE_WSNONSIG                            //format with non-significant whitespace
)

// Encoder encodes xml using a io.Writer as output
type Encoder struct {
	node    *Node
	writer  io.Writer
	options EncodingOption
}

func NewEncoder(node *Node, writer io.Writer, opts EncodingOption) *Encoder {
	return &Encoder{
		node:    node,
		writer:  writer,
		options: opts,
	}
}

func (enc *Encoder) Encode() error {
	w := newWriter(enc.writer)
	res := C.xmlEncode(w.UnsafePtr(), enc.node.Ptr, (*C.char)(unsafe.Pointer(nil)), C.int(enc.options))
	if res < 0 {
		if w.err != nil {
			return w.err
		}
		return ErrEncoding
	}
	return nil
}
