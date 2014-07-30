#ifndef __XML_H__
#define __XML_H__

#include <libxml/tree.h>

#include <libxslt/xslt.h>
#include <libxslt/security.h>

#include <xmlsec/xmlsec.h>
#include <xmlsec/xmltree.h>
#include <xmlsec/xmldsig.h>
#include <xmlsec/templates.h>
#include <xmlsec/crypto.h>


int init();

int xmlSign(xmlDocPtr doc, xmlNodePtr node, char *keyName, void *key, size_t keyLen, void *cert, size_t certLen);

#endif


