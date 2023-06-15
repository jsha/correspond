package main

import (
	"bytes"
	encoding_asn1 "encoding/asn1"
	"encoding/pem"
	"errors"
	"fmt"
	"log"
	"os"

	"golang.org/x/crypto/cryptobyte"
	"golang.org/x/crypto/cryptobyte/asn1"
)

func main() {
	if len(os.Args) != 3 {
		log.Fatalf("Usage: %s precert.pem final.pem", os.Args[0])
	}
	err := main2(os.Args[1], os.Args[2])
	if err != nil {
		log.Fatal(err)
	}
}

func main2(precertFile, finalFile string) error {
	precertDER, err := derFromPEMFile(precertFile)
	if err != nil {
		return fmt.Errorf("parsing precert: %w", err)
	}

	finalDER, err := derFromPEMFile(finalFile)
	if err != nil {
		return fmt.Errorf("parsing final cert: %w", err)
	}

	return Correspond(precertDER, finalDER)
}

// Correspond returns nil if the two certificates are a valid precertificate/final certificate pair.
// Order of the arguments matters: the precertificate is first and the final certificate is second.
func Correspond(precertDER, finalDER []byte) error {
	preTBS, err := tbsDERFromCertDER(precertDER)
	if err != nil {
		return fmt.Errorf("parsing precert: %w", err)
	}

	finalTBS, err := tbsDERFromCertDER(finalDER)
	if err != nil {
		return fmt.Errorf("parsing final cert: %w", err)
	}

	// The first 7 fields of TBSCertificate must be byte-for-byte identical.
	// The next 2 fields (issuerUniqueID and subjectUniqueID) are forbidden
	// by the Baseline Requirements so we assume they are not present (if they
	// are, they will fail the next check, for extensions).
	// https://datatracker.ietf.org/doc/html/rfc5280#page-117
	// TBSCertificate  ::=  SEQUENCE  {
	//      version         [0]  Version DEFAULT v1,
	//      serialNumber         CertificateSerialNumber,
	//      signature            AlgorithmIdentifier,
	//      issuer               Name,
	//      validity             Validity,
	//      subject              Name,
	//      subjectPublicKeyInfo SubjectPublicKeyInfo,
	//      issuerUniqueID  [1]  IMPLICIT UniqueIdentifier OPTIONAL,
	//      					 -- If present, version MUST be v2 or v3
	//      subjectUniqueID [2]  IMPLICIT UniqueIdentifier OPTIONAL,
	//      					 -- If present, version MUST be v2 or v3
	//      extensions      [3]  Extensions OPTIONAL
	//      					 -- If present, version MUST be v3 --  }
	for i := 0; i < 7; i++ {
		if err := readIdenticalElement(&preTBS, &finalTBS); err != nil {
			return fmt.Errorf("checking for identical field %d: %w", i, err)
		}
	}

	// The extensions should be mostly the same, with these two exceptions:
	//  - The precertificate should have exactly one precertificate poison extension
	//    not present in the final certificate.
	//  - The final certificate should have exactly one SCTList extension not present
	//    in the precertificate.
	precertExtensionBytes, err := unwrapExtensions(preTBS)
	if err != nil {
		return fmt.Errorf("parsing precert extensions: %w", err)
	}

	finalCertExtensionBytes, err := unwrapExtensions(finalTBS)
	if err != nil {
		return fmt.Errorf("parsing final cert extensions: %w", err)
	}

	var foundPoison, foundSCTList bool
	for !precertExtensionBytes.Empty() {
		if finalCertExtensionBytes.Empty() {
			return fmt.Errorf("excess extensions in precert")
		}

		var precertExtn cryptobyte.String
		if !precertExtensionBytes.ReadASN1(&precertExtn, asn1.SEQUENCE) {
			return fmt.Errorf("failed to parse precert extension")
		}

		// When we hit the poison extension, skip past it and parse the next one for comparison.
		precertEOF := false
		if isPoisonExtension(precertExtn) {
			if foundPoison {
				return fmt.Errorf("duplicate poison extension")
			}
			foundPoison = true
			if precertExtensionBytes.Empty() {
				precertEOF = true
			} else if !precertExtensionBytes.ReadASN1(&precertExtn, asn1.SEQUENCE) {
				return fmt.Errorf("failed to parse precert extension")
			}
		}

		var finalCertExtn cryptobyte.String
		if !finalCertExtensionBytes.ReadASN1(&finalCertExtn, asn1.SEQUENCE) {
			return fmt.Errorf("failed to parse final cert extension")
		}

		// When we hit the SCTList extension, skip past it and parse the next one for comparison.
		finalCertEOF := false
		if isSCTLExtension(finalCertExtn) {
			if foundSCTList {
				return fmt.Errorf("duplicate SCTList extension")
			}
			foundSCTList = true
			if finalCertExtensionBytes.Empty() {
				finalCertEOF = true
			} else if !finalCertExtensionBytes.ReadASN1(&finalCertExtn, asn1.SEQUENCE) {
				return fmt.Errorf("failed to parse final cert extension after SCTList")
			}
		}

		// When the poison extension and the SCTList extension are both empty, we'll hit the end
		// of each extensions list in the same iteration and have nothing left to compare.
		if precertEOF && finalCertEOF {
			break
		}

		if !bytes.Equal(precertExtn, finalCertExtn) {
			return fmt.Errorf("extensions differed: %x vs %x", precertExtn, finalCertExtn)
		}
	}

	if !finalCertExtensionBytes.Empty() {
		return fmt.Errorf("excess extensions in final cert")
	}
	if !foundPoison {
		return fmt.Errorf("no poison extension found in precert")
	}
	if !foundSCTList {
		return fmt.Errorf("no SCTList extension found in final cert")
	}
	return nil
}

func isPoisonExtension(extn cryptobyte.String) bool {
	var oid encoding_asn1.ObjectIdentifier
	if !extn.ReadASN1ObjectIdentifier(&oid) {
		return false
	}
	return oid.Equal([]int{1, 3, 6, 1, 4, 1, 11129, 2, 4, 3})
}

func isSCTLExtension(extn cryptobyte.String) bool {
	var oid encoding_asn1.ObjectIdentifier
	if !extn.ReadASN1ObjectIdentifier(&oid) {
		return false
	}
	return oid.Equal([]int{1, 3, 6, 1, 4, 1, 11129, 2, 4, 2})
}

// given a sequence of bytes representing the `extensions` field of TBSCertificate, parse the field,
// then parse the SEQUENCE inside it, returning the inner bytes of that SEQUENCE.
func unwrapExtensions(field cryptobyte.String) (cryptobyte.String, error) {
	var extensions cryptobyte.String
	if !field.ReadASN1(&extensions, asn1.Tag(3).Constructed().ContextSpecific()) {
		return nil, errors.New("error reading extensions")
	}

	var extensionsInner cryptobyte.String
	if !extensions.ReadASN1(&extensionsInner, asn1.SEQUENCE) {
		return nil, errors.New("error reading extensions inner")
	}

	return extensionsInner, nil
}

// read a single ASN1 element, return error if their tags are different or their contents are different.
func readIdenticalElement(a, b *cryptobyte.String) error {
	var aInner, bInner cryptobyte.String
	var aTag, bTag asn1.Tag
	if !a.ReadAnyASN1Element(&aInner, &aTag) {
		return fmt.Errorf("failed to read element from first input")
	}
	if !b.ReadAnyASN1Element(&bInner, &bTag) {
		return fmt.Errorf("failed to read element from first input")
	}
	if aTag != bTag {
		return fmt.Errorf("tags differ: %d != %d", aTag, bTag)
	}
	if !bytes.Equal([]byte(aInner), []byte(bInner)) {
		return fmt.Errorf("elements differ: %x != %x", aInner, bInner)
	}
	return nil
}

func derFromPEMFile(filename string) ([]byte, error) {
	precertPEM, err := os.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", filename, err)
	}

	precertPEMBlock, _ := pem.Decode(precertPEM)
	if precertPEMBlock == nil {
		return nil, fmt.Errorf("error PEM decoding %s", filename)
	}

	return precertPEMBlock.Bytes, nil
}

func tbsDERFromCertDER(certDER []byte) (cryptobyte.String, error) {
	var inner cryptobyte.String
	input := cryptobyte.String(certDER)

	if !input.ReadASN1(&inner, asn1.SEQUENCE) {
		return nil, fmt.Errorf("failed to read outer sequence")
	}

	var tbsCertificate cryptobyte.String
	if !inner.ReadASN1(&tbsCertificate, asn1.SEQUENCE) {
		return nil, fmt.Errorf("failed to read tbsCertificate")
	}

	return tbsCertificate, nil
}
