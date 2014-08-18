//
// Package xml is a simple wrapper for libxml2.
package xml

/*
#include <stdlib.h>
#include "xml.h"
*/
import "C"

import (
	"errors"
	"unsafe"
)

/* TODO add wrappers for these and provide methods instead of plain functions
type KeysManager struct {
	Ptr C.xmlSecKeysMngrPtr
}

type DigitalSignature struct {
	Ptr C.xmlSecDSigCtxPtr
}
*/

// Digitally sign a node in a document using the key and cert pem encoded data
func DigitallySign(doc *Document, node *Node, keyName string, key []byte, cert []byte) error {
	keyNameCStr := C.CString(keyName)
	defer C.free(unsafe.Pointer(keyNameCStr))
	keyPtr := unsafe.Pointer(&key[0])
	keyLen := (C.size_t)(len(key))
	certPtr := unsafe.Pointer(&cert[0])
	certLen := (C.size_t)(len(cert))
	res := C.xmlSign(doc.Ptr, node.Ptr, keyNameCStr, keyPtr, keyLen, certPtr, certLen)

	if int(res) != 0 {
		return errors.New("error digitally signing xml")
	}
	return nil
}

// DigitallyVerify a signed node in a document using a given pem encoded cert data
func VerifySignature(node *Node, keyName string, key []byte) (bool, error) {
	if node == nil || node.Ptr == nil {
		return false, nil
	}
	keyNameCStr := C.CString(keyName)
	defer C.free(unsafe.Pointer(keyNameCStr))
	keyPtr := unsafe.Pointer(&key[0])
	keyLen := (C.size_t)(len(key))
	res := int(C.xmlVerify(node.Ptr, keyNameCStr, keyPtr, keyLen))

	if res < 0 {
		return false, errors.New("error verifying digitally signing xml")
	} else if res == 1 {
		return true, nil
	}
	return false, nil
}
