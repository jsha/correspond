package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"strings"
	"testing"
	"time"
)

func TestConsistentGood(t *testing.T) {
	finalDER, err := derFromPEMFile("testdata/good/final.pem")
	if err != nil {
		t.Fatal(err)
	}

	issuerDER, err := derFromPEMFile("testdata/good/lets-encrypt-r3.pem")
	if err != nil {
		t.Fatal(err)
	}

	issuer, err := x509.ParseCertificate(issuerDER)
	if err != nil {
		t.Fatal(err)
	}

	err = Consistent(finalDER, issuer)
	if err != nil {
		t.Errorf("expected testdata/good/final.pem to be consistent, got %s", err)
	}
}

func TestCorrespondGood(t *testing.T) {
	pre, final, err := readPair("testdata/good/precert.pem", "testdata/good/final.pem")
	if err != nil {
		t.Fatal(err)
	}

	err = Correspond(pre, final)
	if err != nil {
		t.Errorf("expected testdata/good/ certs to correspond, got %s", err)
	}
}

func TestCorrespondBad(t *testing.T) {
	pre, final, err := readPair("testdata/bad/precert.pem", "testdata/bad/final.pem")
	if err != nil {
		t.Fatal(err)
	}

	err = Correspond(pre, final)
	if err == nil {
		t.Errorf("expected testdata/bad/ certs to not correspond, got nil error")
	}
	expected := "extensions differed at position 7: '0603551d20040c300a3008060667810c010201' (precert) vs '0603551d20044530433008060667810c0102013037060b2b0601040182df130101013028302606082b06010505070201161a687474703a2f2f6370732e6c657473656e63727970742e6f7267' (final)"
	if !strings.Contains(err.Error(), expected) {
		t.Errorf("expected error to contain %q, got %q", expected, err.Error())
	}
}

func TestCorrespondCompleteMismatch(t *testing.T) {
	pre, final, err := readPair("testdata/good/precert.pem", "testdata/bad/final.pem")
	if err != nil {
		t.Fatal(err)
	}

	err = Correspond(pre, final)
	if err == nil {
		t.Errorf("expected testdata/good and testdata/bad/ certs to not correspond, got nil error")
	}
	expected := "checking for identical field 1: elements differ: 021203d91c3d22b404f20df3c1631c22e1754b8d != 021203e2267b786b7e338317ddd62e764fcb3c71"
	if !strings.Contains(err.Error(), expected) {
		t.Errorf("expected error to contain %q, got %q", expected, err.Error())
	}
}

func readPair(a, b string) ([]byte, []byte, error) {
	aDER, err := derFromPEMFile(a)
	if err != nil {
		return nil, nil, err
	}
	bDER, err := derFromPEMFile(b)
	if err != nil {
		return nil, nil, err
	}
	return aDER, bDER, nil
}

func TestMismatches(t *testing.T) {
	issuerKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	// A separate issuer key, used for signing the final certificate, but
	// using the same simulated issuer certificate.
	untrustedIssuerKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	subscriberKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	// By reading the crypto/x509 code, we know that Subject is the only field
	// of the issuer certificate that we need to care about for the purposes
	// of signing below.
	issuer := x509.Certificate{
		Subject: pkix.Name{
			CommonName: "Some Issuer",
		},
	}

	precertTemplate := x509.Certificate{
		SerialNumber: big.NewInt(3141592653589793238),
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(24 * time.Hour),
		DNSNames:     []string{"example.com"},
		ExtraExtensions: []pkix.Extension{
			{
				Id:    poisonOID,
				Value: []byte{0x5, 0x0},
			},
		},
	}

	precertDER, err := x509.CreateCertificate(rand.Reader, &precertTemplate, &issuer, &subscriberKey.PublicKey, issuerKey)
	if err != nil {
		t.Fatal(err)
	}

	// Sign a final certificate with the untrustedIssuerKey, first applying the
	// given modify function to the default template. Return the DER encoded bytes.
	makeFinalCert := func(modify func(c *x509.Certificate)) []byte {
		t.Helper()
		finalCertTemplate := &x509.Certificate{
			SerialNumber: big.NewInt(3141592653589793238),
			NotBefore:    time.Now(),
			NotAfter:     time.Now().Add(24 * time.Hour),
			DNSNames:     []string{"example.com"},
			ExtraExtensions: []pkix.Extension{
				{
					Id:    sctListOID,
					Value: nil,
				},
			},
		}

		modify(finalCertTemplate)

		finalCertDER, err := x509.CreateCertificate(rand.Reader, finalCertTemplate,
			&issuer, &subscriberKey.PublicKey, untrustedIssuerKey)
		if err != nil {
			t.Fatal(err)
		}

		return finalCertDER
	}

	// Expect success with a matching precert and final cert
	finalCertDER := makeFinalCert(func(c *x509.Certificate) {})
	err = Correspond(precertDER, finalCertDER)
	if err != nil {
		t.Errorf("expected precert and final cert to correspond, got: %s", err)
	}

	// Set up a precert / final cert pair where the SCTList and poison extensions are
	// not in the same position
	precertTemplate2 := x509.Certificate{
		SerialNumber: big.NewInt(3141592653589793238),
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(24 * time.Hour),
		DNSNames:     []string{"example.com"},
		ExtraExtensions: []pkix.Extension{
			{
				Id:    poisonOID,
				Value: []byte{0x5, 0x0},
			},
			// Arbitrary extension to make poisonOID not be the last extension
			{
				Id:    []int{1, 2, 3, 4},
				Value: []byte{0x5, 0x0},
			},
		},
	}

	precertDER2, err := x509.CreateCertificate(rand.Reader, &precertTemplate2, &issuer, &subscriberKey.PublicKey, issuerKey)
	if err != nil {
		t.Fatal(err)
	}

	finalCertDER = makeFinalCert(func(c *x509.Certificate) {
		c.ExtraExtensions = []pkix.Extension{
			{
				Id:    []int{1, 2, 3, 4},
				Value: []byte{0x5, 0x0},
			},
			{
				Id:    sctListOID,
				Value: nil,
			},
		}
	})
	err = Correspond(precertDER2, finalCertDER)
	if err != nil {
		t.Errorf("expected precert and final cert to correspond with differently positioned extensions, got: %s", err)
	}

	// Expect failure with a mismatched Issuer
	issuer = x509.Certificate{
		Subject: pkix.Name{
			CommonName: "Some Other Issuer",
		},
	}

	finalCertDER = makeFinalCert(func(c *x509.Certificate) {})
	err = Correspond(precertDER, finalCertDER)
	if err == nil {
		t.Errorf("expected error for mismatched issuer, got nil error")
	}

	// Restore original issuer
	issuer = x509.Certificate{
		Subject: pkix.Name{
			CommonName: "Some Issuer",
		},
	}

	// Expect failure with a mismatched Serial
	finalCertDER = makeFinalCert(func(c *x509.Certificate) {
		c.SerialNumber = big.NewInt(2718281828459045)
	})
	err = Correspond(precertDER, finalCertDER)
	if err == nil {
		t.Errorf("expected error for mismatched serial, got nil error")
	}

	// Expect failure with mismatched names
	finalCertDER = makeFinalCert(func(c *x509.Certificate) {
		c.DNSNames = []string{"example.com", "www.example.com"}
	})

	err = Correspond(precertDER, finalCertDER)
	if err == nil {
		t.Errorf("expected error for mismatched names, got nil error")
	}

	// Expect failure with mismatched NotBefore
	finalCertDER = makeFinalCert(func(c *x509.Certificate) {
		c.NotBefore = time.Now().Add(24 * time.Hour)
	})

	err = Correspond(precertDER, finalCertDER)
	if err == nil {
		t.Errorf("expected error for mismatched NotBefore, got nil error")
	}

	// Expect failure with mismatched NotAfter
	finalCertDER = makeFinalCert(func(c *x509.Certificate) {
		c.NotAfter = time.Now().Add(48 * time.Hour)
	})
	err = Correspond(precertDER, finalCertDER)
	if err == nil {
		t.Errorf("expected error for mismatched NotAfter, got nil error")
	}

	// Expect failure for mismatched extensions
	finalCertDER = makeFinalCert(func(c *x509.Certificate) {
		c.ExtraExtensions = append(c.ExtraExtensions, pkix.Extension{
			Critical: true,
			Id:       []int{1, 2, 3},
			Value:    []byte("hello"),
		})
	})

	err = Correspond(precertDER, finalCertDER)
	if err == nil {
		t.Errorf("expected error for mismatched extensions, got nil error")
	}
	expectedError := "extensions differed at position 2: '' (precert) vs '06022a030101ff040568656c6c6f' (final)"
	if err.Error() != expectedError {
		t.Errorf("expected error %q, got %q", expectedError, err)
	}
}
