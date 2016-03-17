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

// Decrypt a node in a document using the key  pem encoded data
func Decrypt(node *Node, key []byte) error {
	keyLen := (C.size_t)(len(key))
	if keyLen == 0 {
		return errors.New("cannot decrypt XML due to empty decryption key")
	}
	keyPtr := unsafe.Pointer(&key[0])
	res := C.xmlDecrypt(node.Ptr, keyPtr, keyLen)
	if int(res) != 0 {
		return errors.New("error decrypting xml")
	}
	return nil
}
