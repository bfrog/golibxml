package xml

import (
	"bytes"
	"testing"
)

func TestEncoder(t *testing.T) {
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
}
