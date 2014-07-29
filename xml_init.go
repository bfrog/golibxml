//
// Package xml is a simple wrapper for libxml2.
package xml

/*
#cgo pkg-config: libxml-2.0 libxslt xmlsec1-openssl
#include "xml.h"

*/
import "C"

func init() {
	if int(C.init()) != 0 {
		panic("failed to initialize xml library")
	}
}
