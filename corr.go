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

	// The extensions should be mostly the same, with these exceptions:
	//  - The precertificate should have exactly one precertificate poison extension
	//    not present in the final certificate.
	//  - The final certificate should have exactly one SCTList extension not present
	//    in the precertificate.
	//  - As a consequence, the byte lengths of the extensions fields will not be the
	//    same, so we ignore the lengths (so long as they parse)
	precertExtensionBytes, err := unwrapExtensions(preTBS)
	if err != nil {
		return fmt.Errorf("parsing precert extensions: %w", err)
	}

	finalCertExtensionBytes, err := unwrapExtensions(finalTBS)
	if err != nil {
		return fmt.Errorf("parsing final cert extensions: %w", err)
	}

	poisonsFound := 0
	// Predeclare these function variables so they can recurse
	var finalCertNext, precertNext func() (cryptobyte.String, error)
	// Read an extension from the precert, skipping (and counting) poison
	// extensions. Return nil, nil if we've reached the end.
	precertNext = func() (cryptobyte.String, error) {
		if precertExtensionBytes.Empty() {
			return nil, nil
		}

		var precertExtn cryptobyte.String
		if !precertExtensionBytes.ReadASN1(&precertExtn, asn1.SEQUENCE) {
			return nil, fmt.Errorf("failed to parse precert extension")
		}

		if isPoisonExtension(precertExtn) {
			poisonsFound++
			return precertNext()
		}

		return precertExtn, nil
	}

	sctListsFound := 0
	// Read an extension from the precert, skipping (and counting) SCTList
	// extensions. Return nil, nil if we've reached the end.
	finalCertNext = func() (cryptobyte.String, error) {
		if finalCertExtensionBytes.Empty() {
			return nil, nil
		}

		var finalCertExtn cryptobyte.String
		if !finalCertExtensionBytes.ReadASN1(&finalCertExtn, asn1.SEQUENCE) {
			return nil, fmt.Errorf("failed to parse final cert extension")
		}

		// Skip SCTList extension and try again
		if isSCTLExtension(finalCertExtn) {
			sctListsFound++
			return finalCertNext()
		}
		return finalCertExtn, nil
	}

	for {
		precertExtn, err := precertNext()
		if err != nil {
			return err
		}

		finalCertExtn, err := finalCertNext()
		if err != nil {
			return err
		}

		if !bytes.Equal(precertExtn, finalCertExtn) {
			return fmt.Errorf("extensions differed: '%x' vs '%x'", precertExtn, finalCertExtn)
		}

		if precertExtn == nil && finalCertExtn == nil {
			break
		}
	}

	if poisonsFound == 0 {
		return fmt.Errorf("no poison extension found in precert")
	}
	if poisonsFound > 1 {
		return fmt.Errorf("multiple poison extensions found in precert")
	}
	if sctListsFound == 0 {
		return fmt.Errorf("no SCTList extension found in final cert")
	}
	if sctListsFound > 1 {
		return fmt.Errorf("multiple SCTList extensions found in final cert")
	}
	return nil
}

var poisonOID = []int{1, 3, 6, 1, 4, 1, 11129, 2, 4, 3}

// isPoisonExtension returns true if the given bytes start with the OID for the
// CT poison extension.
func isPoisonExtension(extn cryptobyte.String) bool {
	var oid encoding_asn1.ObjectIdentifier
	if !extn.ReadASN1ObjectIdentifier(&oid) {
		return false
	}
	return oid.Equal(poisonOID)
}

var sctListOID = []int{1, 3, 6, 1, 4, 1, 11129, 2, 4, 2}

// isSCTLExtension returns true if the given bytes start with the OID for the
// CT SCTList extension.
func isSCTLExtension(extn cryptobyte.String) bool {
	var oid encoding_asn1.ObjectIdentifier
	if !extn.ReadASN1ObjectIdentifier(&oid) {
		return false
	}
	return oid.Equal(sctListOID)
}

// unwrapExtensions taks a given a sequence of bytes representing the `extensions` field
// of a TBSCertificate and parses away the outermost two layers, returning the inner bytes
// of a SEQUENCE, which can then be parsed as a list of extensions.
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

// readIdenticalElement parses a single ASN1 element and returns an error if
// their tags are different or their contents are different.
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

// derFromPEMFile reads a PEM file and returns the DER-encoded bytes.
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

// tbsDERFromCertDER takes a Certficate object encoded as DER, and parses
// away the outermost two SEQUENCEs to get the TBSCertificate.
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
