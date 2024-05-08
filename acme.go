package main

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	acmev1 "github.com/cert-manager/cert-manager/pkg/apis/acme/v1"
	certmanagerv1 "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	certmanagermetav1 "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
	"github.com/go-jose/go-jose/v3"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func (ls *LegoSolver) getKeyAuthorization(namespace, dnsName, key string) (keyAuth, token string, err error) {
	challenge, err := ls.getChallenge(dnsName, key)
	if err != nil {
		return "", "", fmt.Errorf("failed to get challenge: %w", err)
	}

	privKey, err := ls.getIssuerPrivKey(challenge.Spec.IssuerRef, namespace)
	if err != nil {
		return "", "", fmt.Errorf("failed to get issuer private key: %w", err)
	}

	keyAuthorization, err := getKeyAuthorization(privKey, challenge.Spec.Token)
	if err != nil {
		return "", "", fmt.Errorf("failed to get key authorization: %w", err)
	}

	keyAuthShaBytes := sha256.Sum256([]byte(keyAuthorization))
	value := base64.RawURLEncoding.EncodeToString(keyAuthShaBytes[:sha256.Size])

	if value != key {
		return "", "", errors.New("key authorization mismatch")
	}

	return keyAuthorization, challenge.Spec.Token, nil
}

func (ls *LegoSolver) getIssuerPrivKey(issuerRef certmanagermetav1.ObjectReference, namespace string) (crypto.PrivateKey, error) {
	var secretKeySelector certmanagermetav1.SecretKeySelector

	switch issuerRef.Kind {
	case certmanagerv1.ClusterIssuerKind:
		clusterIssuer, err := ls.ClusterIssuers().Get(ls.ctx, issuerRef.Name, metav1.GetOptions{})
		if err != nil {
			return nil, fmt.Errorf("failed to get clusterissuer: %w", err)
		}

		secretKeySelector = clusterIssuer.Spec.ACME.PrivateKey
	case certmanagerv1.IssuerKind:
		issuer, err := ls.Issuers(namespace).Get(ls.ctx, issuerRef.Name, metav1.GetOptions{})
		if err != nil {
			return nil, fmt.Errorf("failed to get issuer: %w", err)
		}

		secretKeySelector = issuer.Spec.ACME.PrivateKey
	default:
		return nil, errors.New("unknown issuer kind")
	}

	secret, err := ls.Secrets(namespace).Get(ls.ctx, secretKeySelector.Name, metav1.GetOptions{})
	if err != nil {
		return nil, fmt.Errorf("get secret error: %w", err)
	}

	var data []byte
	if secretKeySelector.Key != "" {
		data = secret.Data[secretKeySelector.Key]
	} else {
		data = secret.Data[corev1.TLSPrivateKeyKey]
	}

	if len(data) == 0 {
		return nil, fmt.Errorf("key %s not found in secret %s", secretKeySelector.Key, secretKeySelector.Name)
	}

	block, _ := pem.Decode(data)
	if block == nil {
		return nil, errors.New("failed to decode PEM block containing the private key")
	}

	return x509.ParsePKCS1PrivateKey(block.Bytes)
}

func (ls *LegoSolver) getChallenge(dnsName, key string) (*acmev1.Challenge, error) {
	for _, v := range ls.challengeIndexer.List() {
		challenge := v.(*acmev1.Challenge)
		if challenge.Spec.DNSName == dnsName && challenge.Spec.Key == key {
			return challenge, nil
		}
	}

	return nil, errors.New("no challenge match")
}

func getKeyAuthorization(privKey crypto.PrivateKey, token string) (string, error) {
	var publicKey crypto.PublicKey
	switch k := privKey.(type) {
	case *ecdsa.PrivateKey:
		publicKey = k.Public()
	case *rsa.PrivateKey:
		publicKey = k.Public()
	}

	// Generate the Key Authorization for the challenge
	jwk := &jose.JSONWebKey{Key: publicKey}

	thumbBytes, err := jwk.Thumbprint(crypto.SHA256)
	if err != nil {
		return "", err
	}

	// unpad the base64URL
	keyThumb := base64.RawURLEncoding.EncodeToString(thumbBytes)

	return token + "." + keyThumb, nil
}
