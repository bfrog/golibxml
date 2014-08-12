# XML Library for Go

[![Build Status](https://secure.travis-ci.org/bfrog/xml.png)](http://travis-ci.org/treetopllc/xml)

XML is a simple wrapper for libxml, libxslt, and xmlsec for Go

Reading and writting documents is done using Encoders and Decodings much like
the encoding/xml library with some explicit structs that define each document
object in the XML DOM.

Most of libxml2 has been wrapped and the functions simply align with the various
libxml2 API calls for their various data structures.

Some simple functionality from xmlsec is being provided for doing xml digital
signing which is used by various XML messaging protocols.
