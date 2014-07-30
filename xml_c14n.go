//
// Package xml is a simple wrapper for libxml2.
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

// C14NMode
type C14NMode int

// C14NMode Variations
// http://www.w3.org/TR/xml-c14n
// http://www.w3.org/TR/xml-exc-c14n/
// http://www.w3.org/TR/xml-c14n11/
const (
	XML_C14N_1_0 C14NMode = iota // C14N 1.0
	XML_C14N_EXCLUSIVE_1_0
	XML_C14N_1_1
)

// C14NEncoder
type C14NEncoder struct {
	doc          *Document
	mode         C14NMode
	nodeSet      NodeSet
	namespaces   []string
	withComments bool
	writer       io.Writer
}

// C14NError
var C14NError = errors.New("error encoding xml document to C14N")

// NewC14NEncoder creates a new C14N xml document encoder that will write
// its output to the given writer.
func NewC14NEncoder(doc *Document, mode C14NMode, w io.Writer) *C14NEncoder {
	if w == nil {
		panic("writer must not be nil")
	}
	return &C14NEncoder{
		doc:    doc,
		mode:   mode,
		writer: w,
	}
}

// Sets the encoders C14N Mode
func (enc *C14NEncoder) SetMode(mode C14NMode) {
	enc.mode = mode
}

func (enc *C14NEncoder) SetNodeSet(nodeSet *NodeSet) {
	enc.nodeSet.Ptr = nodeSet.Ptr
}

func (enc *C14NEncoder) SetInclusiveNamespaces(namespaces []string) {
	enc.namespaces = namespaces
}

func (enc *C14NEncoder) SetWithComments(withComments bool) {
	enc.withComments = withComments
}

func (enc *C14NEncoder) Encode() error {
	w := newWriter(enc.writer)
	var namespacesPtr **C.xmlChar
	if len(enc.namespaces) > 0 && enc.mode == XML_C14N_EXCLUSIVE_1_0 {
		var cNamespaces []*C.char
		size := len(enc.namespaces) + 1
		cNamespaces = make([]*C.char, size)
		for i, namespace := range enc.namespaces {
			cNamespace := C.CString(namespace)
			defer C.free(unsafe.Pointer(cNamespace))
			cNamespaces[i] = cNamespace
		}
		cNamespaces[size-1] = (*C.char)(unsafe.Pointer(nil))
		namespacesPtr = (**C.xmlChar)(unsafe.Pointer(&cNamespaces[0]))
	}
	var cComments C.int
	if enc.withComments {
		cComments = 1
	} else {
		cComments = 0
	}

	res := int(C.xmlC14NEncode(w.UnsafePtr(), enc.doc.Ptr, enc.nodeSet.Ptr, C.int(enc.mode), namespacesPtr, cComments))
	if res < 0 {
		if w.err != nil {
			return w.err
		}
		return C14NError
	}
	return nil
}
