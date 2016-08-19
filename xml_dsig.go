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

type SHAAlgorithm int

const (
	SHA0Algorithm SHAAlgorithm = iota
	SHA1Algorithm
	SHA224Algorithm
	SHA256Algorithm
	SHA384Algorithm
	SHA512Algorithm
)

// DigitallySign a node in a document using the key and cert pem encoded data
func DigitallySign(doc *Document, node *Node, key []byte, shaAlgorithm SHAAlgorithm) error {
	var signMethodID C.xmlSecTransformId
	var digestMethodID C.xmlSecTransformId
	switch shaAlgorithm {
	case SHA1Algorithm:
		signMethodID = C.xmlSecTransformRsaSha1Id
		digestMethodID = C.xmlSecTransformSha1Id
	case SHA224Algorithm:
		signMethodID = C.xmlSecTransformRsaSha224Id
		digestMethodID = C.xmlSecTransformSha224Id
	case SHA256Algorithm:
		signMethodID = C.xmlSecTransformRsaSha256Id
		digestMethodID = C.xmlSecTransformSha256Id
	case SHA384Algorithm:
		signMethodID = C.xmlSecTransformRsaSha384Id
		digestMethodID = C.xmlSecTransformSha384Id
	case SHA512Algorithm:
		signMethodID = C.xmlSecTransformRsaSha512Id
		digestMethodID = C.xmlSecTransformSha512Id
	}

	keyPtr := unsafe.Pointer(&key[0])
	keyLen := (C.size_t)(len(key))
	res := C.xmlSign(doc.Ptr, node.Ptr, keyPtr, keyLen, signMethodID, digestMethodID)
	if int(res) != 0 {
		return errors.New("error digitally signing xml")
	}
	return nil
}

// VerifySignature a signed node in a document using a given pem encoded cert data
func VerifySignature(node *Node, cert []byte) (bool, error) {
	if node == nil || node.Ptr == nil {
		return false, nil
	}
	certPtr := unsafe.Pointer(&cert[0])
	certLen := (C.size_t)(len(cert))
	res := int(C.xmlVerify(node.Ptr, certPtr, certLen))

	if res < 0 {
		return false, errors.New("error verifying digitally signed xml")
	} else if res == 1 {
		return true, nil
	}
	return false, nil
}
