package xml

import (
	"bytes"
	"testing"
)

func TestDecoder(t *testing.T) {
	doc := NewDoc("1.0")
	defer doc.Free()
	node := NewNode(nil, "blackbox")
	node.SetContent("magic")
	doc.SetRoot(node)
	var buf bytes.Buffer
	enc := NewEncoder(node, &buf, 0)
	enc.Encode()
	result := buf.String()
	expect := "<blackbox>magic</blackbox>"
	if result != expect {
		t.Fatalf("expected encoder output to be %s, got %s", expect, result)
	}
	decoder := NewDecoder(&buf, 0)
	if doc0, err := decoder.Decode(); err != nil {
		t.Errorf("unexpected error decoding %s", err)
	} else if doc0 == nil {
		t.Error("nil document")
	}
}
