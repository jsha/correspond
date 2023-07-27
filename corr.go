package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	encoding_asn1 "encoding/asn1"
	"encoding/base64"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log"
	"math"
	"math/big"
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

// Consistent returns nil if the certificate has one or more SCT, and that SCT
// is consistent with the TBSCertificate according to RFC 6962.
func Consistent(finalDER []byte, issuer *x509.Certificate) error {
	finalTBS, err := tbsDERFromCertDER(finalDER)
	if err != nil {
		return fmt.Errorf("parsing final cert: %w", err)
	}

	// In urTBS we will construct a TBSCertificate that has all of the fields
	// of the finalTBS, with the exception that the extensions omit the SCTList.
	urTBS := cryptobyte.NewBuilder(nil)

	// Read the first 7 fields and copy them into the jrTBS.
	//
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
		var field cryptobyte.String
		var tag asn1.Tag
		if !finalTBS.ReadAnyASN1Element(&field, &tag) {
			return fmt.Errorf("failed to read element from TBSCertificate")
		}
		urTBS.AddASN1(tag, func(child *cryptobyte.Builder) {
			child.AddBytes(field)
		})
	}

	finalCertExtensionBytes, err := unwrapExtensions(finalTBS)
	if err != nil {
		return fmt.Errorf("parsing final cert extensions: %w", err)
	}

	var scts []signedCertificateTimestamp
	urExtensions := cryptobyte.NewBuilder(nil)
	for i := 0; !finalCertExtensionBytes.Empty(); i++ {
		var extn cryptobyte.String
		if !finalCertExtensionBytes.ReadASN1(&extn, asn1.SEQUENCE) {
			return fmt.Errorf("failed to parse extension %x", finalCertExtensionBytes)
		}

		var oid encoding_asn1.ObjectIdentifier
		extnCopy := extn
		if !extnCopy.ReadASN1ObjectIdentifier(&oid) {
			return fmt.Errorf("failed to parse extension OID")
		}

		if oid.Equal(sctListOID) {
			// The SCTList extension should not be critical. Since the critical
			// bit of an Extension is DEFAULT FALSE, we expect not to see it; but
			// we check just in case.
			if extnCopy.PeekASN1Tag(asn1.BOOLEAN) {
				return fmt.Errorf("SCTList extension should not be critical")
			}
			var val cryptobyte.String
			if !extnCopy.ReadASN1(&val, asn1.OCTET_STRING) {
				return errors.New("malformed extension value field")
			}
			var sctList cryptobyte.String
			if !val.ReadASN1(&sctList, asn1.OCTET_STRING) {
				return errors.New("malformed extension value (inner)")
			}
			scts, err = parseSCTList(sctList)
			if err != nil {
				return fmt.Errorf("parsing SCTList: %w", err)
			}
			continue
		}

		urExtensions.AddASN1(asn1.SEQUENCE, func(child *cryptobyte.Builder) {
			child.AddBytes(extn)
		})
	}

	urExtensionsBytes, err := urExtensions.Bytes()
	if err != nil {
		return fmt.Errorf("serializing urExtensions: %w", err)
	}

	urTBS.AddASN1(asn1.Tag(3).Constructed().ContextSpecific(), func(child *cryptobyte.Builder) {
		child.AddASN1(asn1.SEQUENCE, func(child *cryptobyte.Builder) {
			child.AddBytes(urExtensionsBytes)
		})
	})

	urTBSBytes, err := urTBS.Bytes()
	if err != nil {
		return fmt.Errorf("serializing urTBS: %w", err)
	}

	urTBSOuter := cryptobyte.NewBuilder(nil)
	urTBSOuter.AddASN1(asn1.SEQUENCE, func(child *cryptobyte.Builder) {
		child.AddASN1(asn1.SEQUENCE, func(child *cryptobyte.Builder) {
			child.AddBytes(urTBSBytes)
		})
	})

	urTBSOuterBytes, err := urTBSOuter.Bytes()
	if err != nil {
		return fmt.Errorf("serializing urTBSOuter: %w", err)
	}

	for i, sct := range scts {
		err := sct.Verify(urTBSOuterBytes, issuer)
		if err != nil {
			return fmt.Errorf("verifying SCT %d: %w", i, err)
		}
	}

	return nil
}

type signedCertificateTimestamp struct {
	Version      uint8
	LogID        [32]byte
	Timestamp    uint64
	CTExtensions []byte
	// For implementation simplicity this is always a sha256/ecdsa signature
	Signature []byte
}

func (sct signedCertificateTimestamp) Verify(urTBS []byte, issuer *x509.Certificate) error {
	var signedData bytes.Buffer
	binary.Write(&signedData, binary.BigEndian, sct.Version)
	var certificateTimestampSignatureType uint8 = 0
	binary.Write(&signedData, binary.BigEndian, certificateTimestampSignatureType)
	// https://datatracker.ietf.org/doc/html/rfc6962#page-11
	//        enum { x509_entry(0), precert_entry(1), (65535) } LogEntryType;
	var precertEntryLogEntryType uint16 = 1
	binary.Write(&signedData, binary.BigEndian, precertEntryLogEntryType)
	// https://datatracker.ietf.org/doc/html/rfc6962#section-3.2
	// struct {
	//	opaque issuer_key_hash[32];
	//	TBSCertificate tbs_certificate;
	// } PreCert;
	//
	// "issuer_key_hash" is the SHA-256 hash of the certificate issuer's
	// public key, calculated over the DER encoding of the key represented
	// as SubjectPublicKeyInfo.
	issuerKeyHash := sha256.Sum256(issuer.RawSubjectPublicKeyInfo)
	io.Copy(&signedData, bytes.NewReader(issuerKeyHash[:]))
	io.Copy(&signedData, bytes.NewReader(urTBS))

	if len(sct.CTExtensions) > math.MaxUint16 {
		return errors.New("CTExtensions too long")
	}
	ctExtensionsLen := uint16(len(sct.CTExtensions))
	binary.Write(&signedData, binary.BigEndian, ctExtensionsLen)
	io.Copy(&signedData, bytes.NewReader(sct.CTExtensions))

	// Assumption: the SCT is always sha256/ecdsa
	digitallySignedHash := sha256.Sum256(signedData.Bytes())

	var r, s big.Int
	var signature cryptobyte.String = sct.Signature
	var signatureInner cryptobyte.String
	if !signature.ReadASN1(&signatureInner, asn1.SEQUENCE) {
		return errors.New("failed to parse signature SEQUENCE")
	}
	if !signatureInner.ReadASN1Integer(&r) {
		return errors.New("failed to lparse r")
	}
	if !signatureInner.ReadASN1Integer(&s) {
		return errors.New("failed to parse s")
	}
	logPubKey, err := findLogKey(sct.LogID)
	if err != nil {
		return err
	}
	ecdsa.Verify(logPubKey, digitallySignedHash[:], &r, &s)
	return nil
}

// findLogKey looks up a CT log by its logID and returns the public key.
// XXX: Right now we just hardcode a couple of logs from our testdata.
func findLogKey(logID [32]byte) (logPublicKey *ecdsa.PublicKey, err error) {
	logMap := map[string]string{
		// Cloudflare Nimbus2023
		"ejKMVNi3LbYg6jjgUh7phBZwMhOFTTvSK8E6V6NS61I=": "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEi/8tkhjLRp0SXrlZdTzNkTd6HqmcmXiDJz3fAdWLgOhjmv4mohvRhwXul9bgW0ODgRwC9UGAgH/vpGHPvIS1qA==",
		// Google Argon2023
		"6D7Q2j71BjUy51covIlryQPTy9ERa+zraeF3fW0GvW4=": "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE0JCPZFJOQqyEti5M8j13ALN3CAVHqkVM4yyOcKWCu2yye5yYeqDpEXYoALIgtM3TmHtNlifmt+4iatGwLpF3eA==",
	}

	logKeyBase64 := logMap[base64.StdEncoding.EncodeToString(logID[:])]
	if logKeyBase64 == "" {
		return nil, fmt.Errorf("unknown log ID: %s", base64.StdEncoding.EncodeToString(logID[:]))
	}
	logPubKeyBytes, err := base64.StdEncoding.DecodeString(logKeyBase64)
	if err != nil {
		return nil, err
	}
	logPubKey, err := x509.ParsePKIXPublicKey(logPubKeyBytes)
	if err != nil {
		return nil, err
	}
	return logPubKey.(*ecdsa.PublicKey), nil
}

// https://datatracker.ietf.org/doc/html/rfc5246#section-4.7
// A digitally-signed element is encoded as a struct DigitallySigned:
//
//	struct {
//		SignatureAndHashAlgorithm algorithm;
//		opaque signature<0..2^16-1>;
//	} DigitallySigned;
//
// https://datatracker.ietf.org/doc/html/rfc6962#section-3.2
//
// enum { certificate_timestamp(0), tree_hash(1), (255) }
//
//	 SignatureType;
//
//	enum { v1(0), (255) }
//	  Version;
//
//	struct {
//	   opaque key_id[32];
//	} LogID;
//
// opaque TBSCertificate<1..2^24-1>;
//
//	struct {
//	   opaque issuer_key_hash[32];
//	   TBSCertificate tbs_certificate;
//	} PreCert;
//
//	opaque CtExtensions<0..2^16-1>;
//
//	struct {
//			Version sct_version;
//			LogID id;
//			uint64 timestamp;
//			CtExtensions extensions;
//			digitally-signed struct {
//				Version sct_version;
//				SignatureType signature_type = certificate_timestamp;
//				uint64 timestamp;
//				LogEntryType entry_type;
//				select(entry_type) {
//					case x509_entry: ASN.1Cert;
//					case precert_entry: PreCert;
//				} signed_entry;
//			   CtExtensions extensions;
//			};
//		} SignedCertificateTimestamp;
//
// opaque SerializedSCT<1..2^16-1>;
//
//	struct {
//	   SerializedSCT sct_list <1..2^16-1>;
//	} SignedCertificateTimestampList;
func parseSCTList(extn cryptobyte.String) ([]signedCertificateTimestamp, error) {
	reader := bytes.NewReader(extn)

	// First comes the sctListLen, in bytes, of the SignedCertificateTimestampList.
	// The number of bytes encoding the sctListLen field is however many bytes it
	// would take to encode the max sctListLen. In this case that's 2 bytes, to encode
	// a sctListLen of 2^16-1.
	var sctListLen uint16
	err := binary.Read(reader, binary.BigEndian, &sctListLen)
	if err != nil {
		return nil, fmt.Errorf("reading SCTList length: %w", err)
	}

	if sctListLen != uint16(len(extn))-2 {
		return nil, fmt.Errorf("SCTList length %d does not match extension length %d", sctListLen, len(extn))
	}

	var scts []signedCertificateTimestamp
	for reader.Len() > 0 {
		var serializedSCTLen uint16
		err := binary.Read(reader, binary.BigEndian, &serializedSCTLen)
		if err != nil {
			return nil, fmt.Errorf("reading SerializedSCT length: %w", err)
		}

		reader := io.LimitReader(reader, int64(serializedSCTLen))

		var sct signedCertificateTimestamp
		err = binary.Read(reader, binary.BigEndian, &sct.Version)
		if err != nil {
			return nil, fmt.Errorf("reading SCT version: %w", err)
		}

		// Read the 32 bytes of the LogID.
		_, err = io.ReadFull(reader, sct.LogID[:])
		if err != nil {
			return nil, fmt.Errorf("reading SCT LogID: %w", err)
		}

		err = binary.Read(reader, binary.BigEndian, &sct.Timestamp)
		if err != nil {
			return nil, fmt.Errorf("reading SCT timestamp: %w", err)
		}

		// Like the SCTList length, the max length of CtExtensions is 2^16-1.
		var extensionsLength uint16
		err = binary.Read(reader, binary.BigEndian, &extensionsLength)
		if err != nil {
			return nil, fmt.Errorf("reading SCT timestamp: %w", err)
		}

		_, err = io.ReadFull(reader, sct.CTExtensions)
		if err != nil {
			return nil, fmt.Errorf("reading CT extensions: %w", err)
		}

		sct.Signature, err = parseDigitallySigned(reader)
		if err != nil {
			return nil, fmt.Errorf("parsing digitally-signed component: %w", err)
		}

		scts = append(scts, sct)
	}

	return scts, nil
}

// parseDigitallySigned parses a TLS `digitally-signed` element. For implementation
// simplicity, it requires that the parsed SignatureAndHashAlgorithm be sha256 and ecdsa.
//
// It returns the bytes of the signature.
//
// https://datatracker.ietf.org/doc/html/rfc5246#section-4.7
//
//	A digitally-signed element is encoded as a struct DigitallySigned:
//
//	struct {
//		SignatureAndHashAlgorithm algorithm;
//		opaque signature<0..2^16-1>;
//	} DigitallySigned;
//
//	enum {
//			none(0), md5(1), sha1(2), sha224(3), sha256(4), sha384(5),
//			sha512(6), (255)
//	} HashAlgorithm;
//
// enum { anonymous(0), rsa(1), dsa(2), ecdsa(3), (255) }
//
//	SignatureAlgorithm;
//
//	struct {
//		  HashAlgorithm hash;
//		  SignatureAlgorithm signature;
//	} SignatureAndHashAlgorithm;
func parseDigitallySigned(reader io.Reader) ([]byte, error) {
	var hashAlgorithm uint8
	var signatureAlgorithm uint8
	err := binary.Read(reader, binary.BigEndian, &hashAlgorithm)
	if err != nil {
		return nil, fmt.Errorf("reading hashAlgorithm: %w", err)
	}
	if hashAlgorithm != 4 {
		return nil, fmt.Errorf("hashAlgorithm %d not supported; only sha256 is supported in SCT", hashAlgorithm)
	}

	err = binary.Read(reader, binary.BigEndian, &signatureAlgorithm)
	if err != nil {
		return nil, fmt.Errorf("reading signatureAlgorithm: %w", err)
	}

	if signatureAlgorithm != 3 {
		return nil, fmt.Errorf("signatureAlgorithm %d not supported; only ecdsa is supported in SCT", signatureAlgorithm)
	}

	// uint16 because the max signature length is 2^16-1.
	var signatureLen uint16
	err = binary.Read(reader, binary.BigEndian, &signatureLen)
	if err != nil {
		return nil, fmt.Errorf("reading signatureLen: %w", err)
	}

	signature := make([]byte, signatureLen)
	_, err = io.ReadFull(reader, signature)
	if err != nil {
		return nil, fmt.Errorf("reading signature: %w", err)
	}

	return signature, nil
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

	precertParser := extensionParser{bytes: precertExtensionBytes, skippableOID: poisonOID}
	finalCertParser := extensionParser{bytes: finalCertExtensionBytes, skippableOID: sctListOID}

	for i := 0; ; i++ {
		precertExtn, err := precertParser.Next()
		if err != nil {
			return err
		}

		finalCertExtn, err := finalCertParser.Next()
		if err != nil {
			return err
		}

		if !bytes.Equal(precertExtn, finalCertExtn) {
			return fmt.Errorf("extensions differed at position %d: '%x' (precert) vs '%x' (final)",
				i+precertParser.skipped, precertExtn, finalCertExtn)
		}

		if precertExtn == nil && finalCertExtn == nil {
			break
		}
	}

	if precertParser.skipped == 0 {
		return fmt.Errorf("no poison extension found in precert")
	}
	if precertParser.skipped > 1 {
		return fmt.Errorf("multiple poison extensions found in precert")
	}
	if finalCertParser.skipped == 0 {
		return fmt.Errorf("no SCTList extension found in final cert")
	}
	if finalCertParser.skipped > 1 {
		return fmt.Errorf("multiple SCTList extensions found in final cert")
	}
	return nil
}

var poisonOID = []int{1, 3, 6, 1, 4, 1, 11129, 2, 4, 3}
var sctListOID = []int{1, 3, 6, 1, 4, 1, 11129, 2, 4, 2}

// extensionParser takes a sequence of bytes representing the inner bytes of the
// `extensions` field. Repeated calls to Next() will return all the extensions
// except those that match the skippableOID. The skipped extensions will be
// counted in `skipped`.
type extensionParser struct {
	skippableOID encoding_asn1.ObjectIdentifier
	bytes        cryptobyte.String
	skipped      int
}

// Next returns the next extension in the sequence, skipping (and counting)
// any extension that matches the skippableOID.
// Returns nil, nil when there are no more extensions.
func (e *extensionParser) Next() (cryptobyte.String, error) {
	if e.bytes.Empty() {
		return nil, nil
	}

	var next cryptobyte.String
	if !e.bytes.ReadASN1(&next, asn1.SEQUENCE) {
		return nil, fmt.Errorf("failed to parse extension")
	}

	var oid encoding_asn1.ObjectIdentifier
	nextCopy := next
	if !nextCopy.ReadASN1ObjectIdentifier(&oid) {
		return nil, fmt.Errorf("failed to parse extension OID")
	}

	if oid.Equal(e.skippableOID) {
		e.skipped++
		return e.Next()
	}

	return next, nil
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
