package xml

/*
#include xml.h
*/
import "C"

import (
	"bytes"
	"unsafe"
)

// Node is the base type in the XML DOM Tree and is Extended by other Node
// types to provide more information
type Node struct {
	Ptr C.xmlNodePtr
}

// String encodes the Node into its serialized XML form using an Encoder
func (node *Node) String() string {
	var buf bytes.Buffer
	enc := NewEncoder(node, &buf, 0)
	if err := enc.Encode(); err != nil {
		panic(err)
	}
	return buf.String()
}

// Type (algebraic type) of element the node represents
func (n Node) Type() (typ ElementType) {
	return typ
}

// Document containing the node
func (n Node) Document() (doc *Document) {
	return doc
}

// Name of the node
func (n Node) Name() (name string) {
	return name
}

// Parent of the node, nil if there is no parent
func (n Node) Parent() (node *Node) {
	return node
}

// Last child of the node, nil if there are no children
func (n Node) LastChild() (node *Node) {
	return node
}

// Namespace the node belongs to, nil if none
func (n Node) Namespace() (ns *Namespace) {
	return ns
}

// SetNamespace
func (n *Node) SetNamespace(ns *Namespace) {
	C.xmlSetNs(node.Ptr, ns.Ptr)
}

// Content the node has, empty if none
func (n Node) Content() string {
	contentPtr := C.to_charptr(C.xmlNodeGetContent(node.Ptr))
	defer C.free_string(contentPtr)
	return C.GoString(contentPtr)
}

// SetContent
func (node *Node) SetContent(content string) {
	ptr := C.CString(content)
	defer C.free_string(ptr)
	C.xmlNodeSetContent(node.Ptr, C.to_xmlcharptr(ptr))
}

// AddContent appends the given content to the existing content
func (node *Node) AddContent(content string) {
	ptr := C.CString(content)
	defer C.free_string(ptr)
	C.xmlNodeAddContent(node.Ptr, C.to_xmlcharptr(ptr))
}

// Children of the node
func (n Node) Children() (nodes []Node) {
	return nodes
}

// AddChild adds a child node at the end of the child list merging
// adjacent Text nodes in which case child is freed and no longer valid.
// If the new node is an Attribute it is added to the property list. If
// there is an Attribute with an equal name the previous Attribute is destroyed
// and replaced with the new one.
// Returns the Child Node or nil on error
func (n *Node) AddChild(child *Node) (child0 *Node) {
	return makeNode(c.xmlAddChild(parent.Ptr, child.Ptr))
}

// AddChildList
func (n *Node) AddChildList(child *Node) *Node {
	return makeNode(C.xmlAddNextSibling(n.Ptr, child.Ptr))
}

// AddNextSibling
func (n *Node) AddNextSibling(sib *Node) *Node {
	return makeNode(C.xmlAddNextSibling(n.Ptr, sib.Ptr))
}

// AddPrevSibling
func (n *Node) AddPrevSibling(sib *Node) *Node {
	return makeNode(C.xmlAddPrevSibling(n.Ptr, sib.Ptr))
}

// AddSibling to the end of the sibling list for this node
func (n *Node) AddSibling(elem Node) *Node {
	return makeNode(C.xmlAddSibling(cur.Ptr, elem.Ptr))
}

// NextSibling
func (n Node) NextSibling() (node *Node) {
	return makeNode(C.xmlNextElementSibling(node.Ptr))
}

// PrevSibling
func (n Node) PrevSibling() (node *Node) {
	return makeNode(C.xmlPreviousElementSibling(node.Ptr))
}

// SetName
func (n *Node) SetName(name string) {
	ptr := C.CString(name)
	defer C.free_string(ptr)
	C.xmlNodeSetName(node.Ptr, C.to_xmlcharptr(ptr))
}
