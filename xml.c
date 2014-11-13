#include "xml.h"
	
int init()
{
    /* Init libxml and libxslt libraries */
    xmlInitParser();
    LIBXML_TEST_VERSION
        xmlLoadExtDtdDefaultValue = XML_DETECT_IDS | XML_COMPLETE_ATTRS;
    xmlSubstituteEntitiesDefault(1);
#ifndef XMLSEC_NO_XSLT
    xmlIndentTreeOutput = 1; 
#endif /* XMLSEC_NO_XSLT */

    /* Init xmlsec library */
    if(xmlSecInit() < 0) {
        fprintf(stderr, "Error: xmlsec initialization failed.\n");
        return(-1);
    }

    /* Check loaded library version */
    if(xmlSecCheckVersion() != 1) {
        fprintf(stderr, "Error: loaded xmlsec library version is not compatible.\n");
        return(-1);
    }    

    /* Load default crypto engine if we are supporting dynamic
     * loading for xmlsec-crypto libraries. Use the crypto library
     * name ("openssl", "nss", etc.) to load corresponding 
     * xmlsec-crypto library.
     * TODO use XMLSEC_CRYPTO define when its fixed to work with go build
     */
#ifdef XMLSEC_CRYPTO_DYNAMIC_LOADING
    if(xmlSecCryptoDLLoadLibrary("openssl") < 0) {
        fprintf(stderr, "Error: unable to load default xmlsec-crypto library. Make sure\n"
                "that you have it installed and check shared libraries path\n"
                "(LD_LIBRARY_PATH) envornment variable.\n");
        return(-1);	
    }
#endif /* XMLSEC_CRYPTO_DYNAMIC_LOADING */

    /* Init crypto library */
    if(xmlSecCryptoAppInit(NULL) < 0) {
        fprintf(stderr, "Error: crypto initialization failed.\n");
        return(-1);
    }

    /* Init xmlsec-crypto library */
    if(xmlSecCryptoInit() < 0) {
        fprintf(stderr, "Error: xmlsec-crypto initialization failed.\n");
        return(-1);
    }

	fprintf(stderr, "Finished xml init()\n");
	return 0;
}

int xmlEncode(void *ctx, xmlNodePtr node, char* encoding, int options) 
{
    int ret = -1;
    xmlSaveCtxtPtr savectx = NULL;
    savectx = xmlSaveToIO((xmlOutputWriteCallback)xmlWriteCallback,
            NULL,
            ctx,
            "UTF-8",
            options);
    if(savectx != NULL) {
        ret = xmlSaveTree(savectx, node);
    }
    ret = xmlSaveClose(savectx);
    return ret;
}

xmlDocPtr xmlDecode(void *ctx, char* encoding, int options) 
{
    xmlDocPtr doc = NULL;
	doc = xmlReadIO((xmlInputReadCallback)xmlReadCallback,
			NULL, ctx, NULL, encoding, options);
    return doc;
}

int xmlC14NEncode(void *ctx, xmlDocPtr doc, xmlNodeSetPtr nodes, int mode,
        xmlChar** inclusive_ns_prefixes, int with_comments)
{
    xmlOutputBufferPtr output = xmlAllocOutputBuffer(NULL);
    if (output == NULL) {
        return -1;
    }
    output->context = ctx;
    output->writecallback = (xmlOutputWriteCallback)xmlWriteCallback;
    int ret = xmlC14NDocSaveTo(doc, nodes, mode, inclusive_ns_prefixes,
            with_comments, output);
    xmlOutputBufferClose(output);
    return ret;
}

int xmlSign(xmlDocPtr doc, xmlNodePtr node, char *keyName, void *key, size_t keyLen, void *cert, size_t certLen)
{
    xmlNodePtr signNode = NULL;
    xmlNodePtr refNode = NULL;
    xmlNodePtr keyInfoNode = NULL;
    xmlSecDSigCtxPtr dsigCtx = NULL;
    int res = -1;

    /* create signature template for RSA-SHA1 enveloped signature */
    signNode = xmlSecTmplSignatureCreate(doc, xmlSecTransformExclC14NId,
            xmlSecTransformRsaSha1Id, NULL);
    if(signNode == NULL) {
        fprintf(stderr, "Error: failed to create signature template\n");
        goto done;              
    }

    /* add <dsig:Signature/> node to the doc */
    xmlAddChild(node, signNode);

    /* add reference */
    refNode = xmlSecTmplSignatureAddReference(signNode, xmlSecTransformSha1Id,
            NULL, NULL, NULL);
    if(refNode == NULL) {
        fprintf(stderr, "Error: failed to add reference to signature template\n");
        goto done;              
    }

    /* add enveloped transform */
    if(xmlSecTmplReferenceAddTransform(refNode, xmlSecTransformEnvelopedId) == NULL) {
        fprintf(stderr, "Error: failed to add enveloped transform to reference\n");
        goto done;              
    }

    /* add <dsig:KeyInfo/> and <dsig:X509Data/> */
    keyInfoNode = xmlSecTmplSignatureEnsureKeyInfo(signNode, NULL);
    if(keyInfoNode == NULL) {
        fprintf(stderr, "Error: failed to add key info\n");
        goto done;              
    }

    if(xmlSecTmplKeyInfoAddX509Data(keyInfoNode) == NULL) {
        fprintf(stderr, "Error: failed to add X509Data node\n");
        goto done;              
    }

    /* create signature context, we don't need keys manager in this example */
    dsigCtx = xmlSecDSigCtxCreate(NULL);
    if(dsigCtx == NULL) {
        fprintf(stderr,"Error: failed to create signature context\n");
        goto done;
    }

    /* load private key, assuming that there is not password */
    dsigCtx->signKey = xmlSecCryptoAppKeyLoadMemory(key, keyLen, xmlSecKeyDataFormatPem, NULL, NULL, NULL);
    if(dsigCtx->signKey == NULL) {
        fprintf(stderr,"Error: failed to load private binary key from\n");
        goto done;
    }

    /* load certificate and add to the key */
    if(xmlSecCryptoAppKeyCertLoadMemory(dsigCtx->signKey, cert, certLen, xmlSecKeyDataFormatCertPem) < 0) {
        fprintf(stderr,"Error: failed to load binary certificate\n");
        goto done;
    }

    /* set key name to the file name, this is just an example! */
    if(xmlSecKeySetName(dsigCtx->signKey, keyName) < 0) {
        fprintf(stderr,"Error: failed to set key name to \"%s\"\n", keyName);
        goto done;
    }

    /* sign the template */
    if(xmlSecDSigCtxSign(dsigCtx, signNode) < 0) {
        fprintf(stderr,"Error: signature failed\n");
        goto done;
    }

done:
    if(dsigCtx != NULL) {
        xmlSecDSigCtxDestroy(dsigCtx);
    }

    return 0;
}

int xmlVerify(xmlNodePtr node, char* keyName, void* cert, size_t certLen)
{
	xmlSecKeysMngrPtr mngr = NULL;
    xmlNodePtr dsigNode = NULL;
    xmlSecDSigCtxPtr dsigCtx = NULL;
    int res = -1;

    /* create keys manager and load keys */
    mngr = xmlSecKeysMngrCreate();
    if(mngr == NULL) {
        fprintf(stderr, "Error: could not create key manager\n");
        goto done;
    }
    if(xmlSecCryptoAppDefaultKeysMngrInit(mngr) < 0) {
        fprintf(stderr, "Error: could not initialize key manager\n");
        goto done;
    }

    /* load trusted cert from memory */
    if(xmlSecCryptoAppKeysMngrCertLoadMemory(mngr, cert, certLen, xmlSecKeyDataFormatCertPem, xmlSecKeyDataTypeNone) < 0) {
        fprintf(stderr, "Error: could not load cert\n");
        goto done;
    }

    /* find start node */
    dsigNode = xmlSecFindNode(node, xmlSecNodeSignature, xmlSecDSigNs);
    if(node == NULL) {
        fprintf(stderr, "Error: start node not found\n");
        goto done;      
    }

    /* create signature context */
    dsigCtx = xmlSecDSigCtxCreate(NULL);
    if(dsigCtx == NULL) {
        fprintf(stderr,"Error: failed to create signature context\n");
        goto done;
    }

    /* load private key, assuming that there is not password */
    dsigCtx->signKey = xmlSecCryptoAppKeyLoadMemory(cert, certLen, xmlSecKeyDataFormatCertPem, NULL, NULL, NULL);
    if(dsigCtx->signKey == NULL) {
        fprintf(stderr,"Error: failed to load private binary key from\n");
        goto done;
    }

    /* Verify signature */
    if(xmlSecDSigCtxVerify(dsigCtx, dsigNode) < 0) {
        fprintf(stderr,"Error: signature verify\n");
        goto done;
    }

    /* print verification result to stdout */
    if(dsigCtx->status == xmlSecDSigStatusSucceeded) {
        fprintf(stdout, "Signature is OK\n");
        res = 1;
    } else {
        fprintf(stdout, "Signature is INVALID\n");
        res = 0;
    }    

done:
    /* cleanup */

    if(dsigCtx != NULL) {
        xmlSecDSigCtxDestroy(dsigCtx);
    }
    if(mngr != NULL) {
        xmlSecKeysMngrDestroy(mngr);
    }

    return(res);
}



