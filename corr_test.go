package main

import (
	"strings"
	"testing"
)

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
	expected := "extensions differed: 0603551d20040c300a3008060667810c010201 vs 0603551d20044530433008060667810c0102013037060b2b0601040182df130101013028302606082b06010505070201161a687474703a2f2f6370732e6c657473656e63727970742e6f7267"
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
