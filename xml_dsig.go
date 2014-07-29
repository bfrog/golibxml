//
// Package xml is a simple wrapper for libxml2.
package xml

/*
#include <libxml/tree.h>
#include <libxslt/xslt.h>
#include <libxslt/security.h>

#include <xmlsec/xmlsec.h>
#include <xmlsec/xmltree.h>
#include <xmlsec/xmldsig.h>
#include <xmlsec/templates.h>
#include <xmlsec/crypto.h>

inline int
xmlSign(xmlNodePtr node, char* keyname, char* key, size_t keyLen, char* cert, size_t certLen)
{
	return 0;
}

inline int
xmlVerify(xmlNodePtr node, char* cert, size_t certLen)
{
	return 0;
}

*/
import "C"
