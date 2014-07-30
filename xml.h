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

int init();

// io.Writer callback
int xmlWriteCallback(void *ctx, char* data, int dataLen);

// c14n encode
int xmlC14NEncode(void *ctx, xmlDocPtr doc, xmlNodeSetPtr nodes, int mode,
        xmlChar **inclusive_ns_prefixes, int with_Comment);

// encode
int xmlEncode(void *ctx, xmlNodePtr node, char* encoding, int options);

int xmlSign(xmlDocPtr doc, xmlNodePtr node, char *keyName, void *key, size_t keyLen, void *cert, size_t certLen);

int xmlVerify(xmlNodePtr node, char *keyName, void* key, size_t keyLen);

#endif
