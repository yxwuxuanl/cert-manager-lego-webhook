package main

import (
	"cmp"
	"crypto"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"

	"github.com/cert-manager/cert-manager/pkg/acme/webhook/apis/acme/v1alpha1"
	acmev1 "github.com/cert-manager/cert-manager/pkg/apis/acme/v1"
	certmanagerv1 "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	certmanagermetav1 "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
	"golang.org/x/crypto/acme"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func (ls *LegoSolver) getKeyAuthorization(ch *v1alpha1.ChallengeRequest) (keyAuth, token string, err error) {
	challenge, err := ls.getChallenge(ch)
	if err != nil {
		return "", "", fmt.Errorf("failed to get challenge: %w", err)
	}

	privKey, err := ls.getIssuerPrivKey(challenge.Spec.IssuerRef, ch.ResourceNamespace)
	if err != nil {
		return "", "", fmt.Errorf("failed to get issuer private key: %w", err)
	}

	th, err := acme.JWKThumbprint(privKey.(crypto.Signer).Public())
	if err != nil {
		return "", "", fmt.Errorf("failed to get JWK thumbprint: %w", err)
	}

	keyAuth = fmt.Sprintf("%s.%s", challenge.Spec.Token, th)

	b := sha256.Sum256([]byte(keyAuth))
	key := base64.RawURLEncoding.EncodeToString(b[:])

	if key != ch.Key {
		return "", "", errors.New("keyAuth authorization mismatch")
	}

	return keyAuth, challenge.Spec.Token, nil
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

	key := cmp.Or(secretKeySelector.Key, corev1.TLSPrivateKeyKey)

	data := secret.Data[key]
	if len(data) == 0 {
		return nil, errors.New("private key not found in secret")
	}

	block, _ := pem.Decode(data)
	if block == nil {
		return nil, errors.New("failed to decode PEM block")
	}

	return x509.ParsePKCS1PrivateKey(block.Bytes)
}

func (ls *LegoSolver) getChallenge(ch *v1alpha1.ChallengeRequest) (*acmev1.Challenge, error) {
	for _, v := range ls.challengeStore.List() {
		challenge := v.(*acmev1.Challenge)
		if challenge.Spec.Type == acmev1.ACMEChallengeTypeDNS01 &&
			challenge.Spec.DNSName == ch.DNSName &&
			challenge.Spec.Key == ch.Key {
			return challenge, nil
		}
	}

	return nil, errors.New("no challenge match")
}
