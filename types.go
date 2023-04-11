package xmlsig

import (
	"encoding/xml"
	"math/big"
)

/*
Data structures to represent some of the types defined in
Schema for XML Signatures, http://www.w3.org/2000/09/xmldsig.
*/

// Signature element is the root element of an XML Signature.
type Signature struct {
	XMLName            xml.Name `xml:"http://www.w3.org/2000/09/xmldsig# Signature"`
	Xmlns              string   `xml:"xmlns,attr"`
	SignedInfo         SignedInfo
	SignatureValue     string `xml:"http://www.w3.org/2000/09/xmldsig# SignatureValue"`
	KeyInfo            KeyInfo
	CanonicalizedInput string `xml:"-"`
}

// Algorithm describes the digest or signature used when digest or signature.
type Algorithm struct {
	Algorithm string `xml:",attr"`
	// InclusiveNamespace InclusiveNamespace `xml:",omitempty"`
}

// type InclusiveNamespace struct {}

// SignedInfo includes a canonicalization algorithm, a signature algorithm, and a reference.
type SignedInfo struct {
	XMLName                xml.Name  `xml:"http://www.w3.org/2000/09/xmldsig# SignedInfo"`
	CanonicalizationMethod Algorithm `xml:"http://www.w3.org/2000/09/xmldsig# CanonicalizationMethod"`
	SignatureMethod        Algorithm `xml:"http://www.w3.org/2000/09/xmldsig# SignatureMethod"`
	Reference              Reference
}

// Reference specifies a digest algorithm and digest value, and optionally an identifier of the object being signed, the type of the object, and/or a list of transforms to be applied prior to digesting.
type Reference struct {
	XMLName      xml.Name `xml:"http://www.w3.org/2000/09/xmldsig# Reference"`
	URI          string   `xml:",attr,omitempty"`
	Transforms   Transforms
	DigestMethod Algorithm `xml:"http://www.w3.org/2000/09/xmldsig# DigestMethod"`
	DigestValue  string    `xml:"http://www.w3.org/2000/09/xmldsig# DigestValue"`
}

// Transforms is an optional ordered list of processing steps that were applied to the resource's content before it was digested.
type Transforms struct {
	XMLName   xml.Name    `xml:"http://www.w3.org/2000/09/xmldsig# Transforms"`
	Transform []Algorithm `xml:"http://www.w3.org/2000/09/xmldsig# Transform"`
}

// KeyInfo is an optional element that enables the recipient(s) to obtain the key needed to validate the signature.
type KeyInfo struct {
	XMLName  xml.Name `xml:"http://www.w3.org/2000/09/xmldsig# KeyInfo"`
	X509Data *X509Data
	// KeyValue KeyValue
	Children []interface{}
}

// KeyValue holds the RSAKeyValue modulus & exponent
type KeyValue struct {
	XMLName     xml.Name `xml:"http://www.w3.org/2000/09/xmldsig# KeyValue"`
	RSAKeyValue RSAKeyValue
}

// RSAKeyValue element within KeyValue holds rsa keyvalue
type RSAKeyValue struct {
	XMLName  xml.Name `xml:"http://www.w3.org/2000/09/xmldsig# RSAKeyValue"`
	Modulus  string   `xml:"Modulus"`
	Exponent string   `xml:"Exponent"`
}

// X509Data element within KeyInfo contains an X509 certificate
type X509Data struct {
	XMLName          xml.Name `xml:"http://www.w3.org/2000/09/xmldsig# X509Data"`
	X509Certificate  string   `xml:"http://www.w3.org/2000/09/xmldsig# X509Certificate"`
	X509IssuerSerial X509IssuerSerial
}

// X509IssuerSerial element within X509Data contains the issername and the serialnumber
type X509IssuerSerial struct {
	XMLName      xml.Name `xml:"http://www.w3.org/2000/09/xmldsig# X509IssuerSerial"`
	IssuerName   string   `xml:"X509IssuerName,omitempty"`
	SerialNumber *big.Int `xml:"X509SerialNumber,omitempty"`
}

// BinarySecurityToken contains the binary security token for X509 certificates
type BinarySecurityToken struct {
	ValueType    string `xml:"ValueType,attr"`
	EncodingType string `xml:"EncodingType,attr"`
	ID           string `xml:"wsu:Id,attr"`
	Value        string `xml:",chardata"`
}
