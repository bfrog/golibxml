#ifndef __XML_H__
#define __XML_H__

#include <libxml/tree.h>
#include <libxml/xmlsave.h>

#include <libxslt/xslt.h>
#include <libxslt/security.h>

#include <xmlsec/xmlsec.h>
#include <xmlsec/xmltree.h>
#include <xmlsec/xmldsig.h>
#include <xmlsec/templates.h>
#include <xmlsec/crypto.h>

// inline go/cstr/xmlChar helpers
static inline void free_string(char* s) { free(s); }
static inline void free_xmlstring(xmlChar* s) { free(s); }
static inline xmlChar *to_xmlcharptr(const char *s) { return (xmlChar *)s; }
static inline char *to_charptr(const xmlChar *s) { return (char *)s; }

// initialize the xml and cryptographic libraries
int init();

// io.Writer callback
int xmlWriteCallback(void *ctx, char* data, int dataLen);

// io.Reader callback
int xmlReadCallback(void *ctx, char* data, int dataLen);

// c14n encode
int xmlC14NEncode(void *ctx, xmlDocPtr doc, xmlNodeSetPtr nodes, int mode,
        xmlChar **inclusive_ns_prefixes, int with_Comment);

// encode into an io stream
int xmlEncode(void *ctx, xmlNodePtr node, char* encoding, int options);

// decode from an io stream creating and setting a xmlDocPtr if it succeeds
// the caller is responsible for freeing the returned xmlDoc
xmlDocPtr xmlDecode(void *ctx, char *encoding, int options);

// sign a node in an xml tree with a key and cert (pem encoded)
int xmlSign(xmlDocPtr doc, xmlNodePtr node, char *keyName, void *key, size_t keyLen, void *cert, size_t certLen);

// verify a signed node in an xml tree with a known key
int xmlVerify(xmlNodePtr node, char *keyName, void* key, size_t keyLen);

#endif
