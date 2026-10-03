// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: Apache-2.0

// Package gwtest holds certificate-fixture helpers shared by the gateway's
// package tests. It is not part of the gateway's public API.
package gwtest

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"fmt"
	"time"

	pki "github.com/varwof/types"
)

// SelfAuthorizeDA turns aic into a verifiable self-authorized delegation: the
// principal is the agent itself, so PrincipalUid.KeyHash becomes the leaf key's
// SPKI hash and the DelegationAuthorization is signed over its DelegationAuthTBS
// with the same key.
//
// DelegationAuthorization verification is mandatory in the agent-certificate
// verification procedure (draft-wei-aic-identity-cert-02 step 4), so a fixture
// carrying a placeholder DA (zero KeyHash, dummy signature) is now correctly
// refused. A self-authorized delegation is a legitimate shape and keeps the
// fixture on the strict default path instead of switching the check off.
//
// Call it after the leaf key exists and before the AIC is marshalled into the
// certificate. key must be the leaf private key whose public key the
// certificate carries.
func SelfAuthorizeDA(key crypto.Signer, aic *pki.AIC) error {
	spki, err := x509.MarshalPKIXPublicKey(key.Public())
	if err != nil {
		return fmt.Errorf("marshal spki: %w", err)
	}
	keyHash := sha256.Sum256(spki)
	aic.PrincipalUid.KeyHash = keyHash[:]
	aic.PrincipalUid.HashAlgo = pki.AlgorithmIdentifier{Algorithm: pki.OIDSHA256}
	if aic.Version == 0 {
		aic.Version = pki.DAVersion1
	}
	da := &aic.DelegationAuthorization
	if da.RequestedLifetime == 0 {
		da.RequestedLifetime = 86400
	}
	if da.Timestamp.IsZero() {
		da.Timestamp = time.Now().UTC()
	}
	if len(da.Nonce) == 0 {
		da.Nonce = make([]byte, 32)
	}

	tbs := pki.DelegationAuthTBS{
		Version:                  aic.Version,
		AgentId:                  aic.AgentId,
		PrincipalUid:             aic.PrincipalUid,
		Reason:                   da.Reason,
		Capabilities:             aic.Capabilities,
		DelegationMode:           aic.DelegationMode,
		AuthorizationConstraints: aic.AuthorizationConstraints,
		RequestedLifetime:        da.RequestedLifetime,
		Timestamp:                da.Timestamp,
		Nonce:                    da.Nonce,
	}
	der, err := asn1.Marshal(tbs)
	if err != nil {
		return fmt.Errorf("marshal delegation TBS: %w", err)
	}
	digest := sha256.Sum256(der)

	switch k := key.(type) {
	case *ecdsa.PrivateKey:
		sig, err := ecdsa.SignASN1(rand.Reader, k, digest[:])
		if err != nil {
			return fmt.Errorf("sign delegation TBS: %w", err)
		}
		da.SignatureAlgorithm = pki.AlgorithmIdentifier{Algorithm: pki.OIDSigECDSAWithSHA256}
		da.SignatureValue = sig
	case *rsa.PrivateKey:
		sig, err := rsa.SignPKCS1v15(rand.Reader, k, crypto.SHA256, digest[:])
		if err != nil {
			return fmt.Errorf("sign delegation TBS: %w", err)
		}
		da.SignatureAlgorithm = pki.AlgorithmIdentifier{Algorithm: pki.OIDSigRSAWithSHA256}
		da.SignatureValue = sig
	default:
		return fmt.Errorf("self-authorize DA: unsupported key type %T", key)
	}
	return nil
}

// SelfAuthorizeExtension rewrites an AIC extension in place: if ext has the AIC
// OID, the decoded AIC is self-authorized with key and re-marshalled. Other
// extensions are returned unchanged. It lets a cert builder that only has the
// raw extension bytes route them through SelfAuthorizeDA.
func SelfAuthorizeExtension(key crypto.Signer, extID asn1.ObjectIdentifier, value []byte) ([]byte, error) {
	if !extID.Equal(pki.OIDAIC) {
		return value, nil
	}
	var aic pki.AIC
	if _, err := asn1.Unmarshal(value, &aic); err != nil {
		return value, nil
	}
	if err := SelfAuthorizeDA(key, &aic); err != nil {
		return nil, err
	}
	return asn1.Marshal(aic)
}

// SHA256SPKI returns the SHA-256 hash of the key's SPKI DER, i.e. the value a
// self-authorized AIC carries in PrincipalUid.KeyHash.
func SHA256SPKI(key crypto.Signer) ([]byte, error) {
	spki, err := x509.MarshalPKIXPublicKey(key.Public())
	if err != nil {
		return nil, err
	}
	h := sha256.Sum256(spki)
	return h[:], nil
}
