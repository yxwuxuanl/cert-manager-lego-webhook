package solver

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"testing"
)

func TestParsePrivateKey(t *testing.T) {
	t.Parallel()

	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate RSA key: %v", err)
	}

	ecdsaKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate ECDSA key: %v", err)
	}

	rsaPKCS8, err := x509.MarshalPKCS8PrivateKey(rsaKey)
	if err != nil {
		t.Fatalf("marshal PKCS#8 key: %v", err)
	}

	ecdsaSEC1, err := x509.MarshalECPrivateKey(ecdsaKey)
	if err != nil {
		t.Fatalf("marshal EC private key: %v", err)
	}

	tests := []struct {
		name      string
		der       []byte
		assertKey func(*testing.T, crypto.Signer)
	}{
		{
			name: "pkcs1 rsa",
			der:  x509.MarshalPKCS1PrivateKey(rsaKey),
			assertKey: func(t *testing.T, signer crypto.Signer) {
				t.Helper()
				if _, ok := signer.(*rsa.PrivateKey); !ok {
					t.Fatalf("expected *rsa.PrivateKey, got %T", signer)
				}
			},
		},
		{
			name: "pkcs8 rsa",
			der:  rsaPKCS8,
			assertKey: func(t *testing.T, signer crypto.Signer) {
				t.Helper()
				if _, ok := signer.(*rsa.PrivateKey); !ok {
					t.Fatalf("expected *rsa.PrivateKey, got %T", signer)
				}
			},
		},
		{
			name: "sec1 ecdsa",
			der:  ecdsaSEC1,
			assertKey: func(t *testing.T, signer crypto.Signer) {
				t.Helper()
				if _, ok := signer.(*ecdsa.PrivateKey); !ok {
					t.Fatalf("expected *ecdsa.PrivateKey, got %T", signer)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			signer, err := parsePrivateKey(tt.der)
			if err != nil {
				t.Fatalf("parse key: %v", err)
			}

			tt.assertKey(t, signer)
		})
	}
}

func TestParsePrivateKeyInvalid(t *testing.T) {
	t.Parallel()

	if _, err := parsePrivateKey([]byte("not-a-private-key")); err == nil {
		t.Fatal("expected invalid key to fail")
	}
}
