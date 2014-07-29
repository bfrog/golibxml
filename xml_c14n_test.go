package xml

import (
	"bytes"
	"testing"
)

func TestC14N_1_0(t *testing.T) {
	doc := NewDoc("1.0")
	defer doc.Free()
	node := NewNode(nil, "blackbox")
	node.SetContent("magic")
	doc.AddChild(node)
	var buf bytes.Buffer
	c14n := NewC14NEncoder(doc, XML_C14N_1_0, &buf)
	c14n.Encode()
	result := buf.String()
	expect := "<blackbox>magic</blackbox>"
	if result != expect {
		t.Fatalf("expected c14n output to be %s, got %s", expect, result)
	}
}
