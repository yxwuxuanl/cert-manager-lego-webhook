package solver

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

func (ls *Solver) getKeyAuthorization(ch *v1alpha1.ChallengeRequest) (keyAuth, token string, err error) {
	challenge, err := ls.getChallenge(ch)
	if err != nil {
		return "", "", fmt.Errorf("failed to get challenge: %w", err)
	}

	signer, err := ls.getIssuerPrivateKeySigner(challenge.Spec.IssuerRef, ch.ResourceNamespace)
	if err != nil {
		return "", "", fmt.Errorf("failed to get issuer private key: %w", err)
	}

	th, err := acme.JWKThumbprint(signer.Public())
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

func (ls *Solver) getIssuerPrivateKeySigner(issuerRef certmanagermetav1.IssuerReference, resourceNamespace string) (crypto.Signer, error) {
	var secretKeySelector certmanagermetav1.SecretKeySelector

	switch issuerRef.Kind {
	case certmanagerv1.ClusterIssuerKind:
		clusterIssuer, err := ls.ClusterIssuers().Get(ls.ctx, issuerRef.Name, metav1.GetOptions{})
		if err != nil {
			return nil, fmt.Errorf("failed to get clusterissuer: %w", err)
		}

		secretKeySelector = clusterIssuer.Spec.ACME.PrivateKey
	case certmanagerv1.IssuerKind:
		issuer, err := ls.Issuers(resourceNamespace).Get(ls.ctx, issuerRef.Name, metav1.GetOptions{})
		if err != nil {
			return nil, fmt.Errorf("failed to get issuer: %w", err)
		}

		secretKeySelector = issuer.Spec.ACME.PrivateKey
	default:
		return nil, errors.New("unknown issuer kind")
	}

	// cert-manager passes the issuer namespace for Issuers and the configured
	// cluster resource namespace for ClusterIssuers via ChallengeRequest.
	secret, err := ls.Secrets(resourceNamespace).Get(ls.ctx, secretKeySelector.Name, metav1.GetOptions{})
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

	return parsePrivateKey(block.Bytes)
}

func parsePrivateKey(der []byte) (crypto.Signer, error) {
	if key, err := x509.ParsePKCS1PrivateKey(der); err == nil {
		return key, nil
	}

	if key, err := x509.ParsePKCS8PrivateKey(der); err == nil {
		signer, ok := key.(crypto.Signer)
		if !ok {
			return nil, fmt.Errorf("unsupported PKCS#8 private key type %T", key)
		}

		return signer, nil
	}

	if key, err := x509.ParseECPrivateKey(der); err == nil {
		return key, nil
	}

	return nil, errors.New("unsupported private key format")
}

func (ls *Solver) getChallenge(ch *v1alpha1.ChallengeRequest) (*acmev1.Challenge, error) {
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
