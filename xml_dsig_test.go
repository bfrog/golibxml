package xml

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"testing"
	"time"
)

func TestDigitalSignature(t *testing.T) {
	name := "Johnny"
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	now := time.Now()

	certTmpl := x509.Certificate{
		SerialNumber: new(big.Int).SetInt64(1),
		Subject: pkix.Name{
			CommonName:   name,
			Organization: []string{"Acme Co"},
		},
		IsCA:         true,
		NotBefore:    now.Add(-5 * time.Minute).UTC(),
		NotAfter:     now.AddDate(1, 0, 0).UTC(),
		SubjectKeyId: []byte{1, 2, 3, 4},
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
	}
	certBytes, err := x509.CreateCertificate(rand.Reader, &certTmpl, &certTmpl,
		&privKey.PublicKey, privKey)
	if err != nil {
		t.Fatal(err)
	}
	certPem := pem.EncodeToMemory(
		&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: certBytes,
		},
	)
	t.Logf("certPem %s", string(certPem))
	privPem := pem.EncodeToMemory(
		&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PrivateKey(privKey),
		},
	)
	doc := NewDoc("1.0")
	defer doc.Free()
	node := NewNode(nil, "blackbox")
	node.SetContent("magic")
	doc.AddChild(node)
	if err := DigitallySign(doc, node, privPem); err != nil {
		t.Fatalf("xml %s could not be signed, err: %s", node.StringDump(), err)
	}
	if signed, err := VerifySignature(node, certPem); err != nil {
		t.Fatalf("xml %s could not be verified, err: %s", node.StringDump(), err)
	} else if !signed {
		t.Errorf("expected verify to be true")
	}

	if signed, err := VerifySignature(nil, certPem); err != nil {
		t.Fatalf("xml nil node could not be verified, err: %s", err)
	} else if signed {
		t.Errorf("expected verify to be false for nil node")
	}
	node.Ptr = nil
	if signed, err := VerifySignature(node, certPem); err != nil {
		t.Fatalf("xml node with nil ptr could not be verified, err: %s", err)
	} else if signed {
		t.Errorf("expected verify to be false for node with nil ptr")
	}
}
