package xmlsig

import (
	"encoding/xml"
	"testing"
)

type Root struct {
	XMLName xml.Name `xml:"tns root"`
	B       string   `xml:"b,attr"`
	A       string   `xml:"http://someotherns/for/attr a,attr"`
	C       string   `xml:"anotherns/be a,attr"`
	Child   Child
}

type Child struct {
	XMLName xml.Name `xml:"tns child"`
	Data    string   `xml:",chardata"`
}

type Body struct {
	XMLName      xml.Name `xml:"soap:Body"`
	XMLNamespace string   `xml:"xmlns:wsu,attr"`
	// XMLNamespace2 string   `xml:"xmlns:soap,attr"`
	SignatureID string `xml:"wsu:Id,attr"`
}

func TestCanonicalization2(t *testing.T) {
	body := &Body{
		XMLNamespace: "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd",
		SignatureID:  "SoapBody-445940dd-f66d-4076-8671-9945b6a754df",
		// XMLNamespace2: "http://www.w3.org/2003/05/soap-envelope",
	}

	data, _, err := canonicalize(body)
	if err != nil {
		t.Fatal(err)
	}

	actual := string(data)
	expected := `<soap:Body xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd" wsu:Id="SoapBody-445940dd-f66d-4076-8671-9945b6a754df"></soap:Body>`

	if actual != expected {
		t.Log("Expected: ", expected)
		t.Log("Actual: ", actual)
		t.Fatal("Expected and Actual result doesn't match!")
	}
}

func TestCanonicalization(t *testing.T) {
	element := &Root{B: "1", A: "2", C: "3", Child: Child{Data: "data"}}
	// Go's default encoder would produce the following
	// <root xmlns="tns" b="1" xmlns:attr="http://someotherns/for/attr" attr:a="2" xmlns:be="anotherns/be" be:a="3"><child xmlns="tns">data</child></root>
	// It should produce
	// <root xmlns="tns" xmlns:attr="http://someotherns/for/attr" xmlns:be="anotherns/be" b="1" be:a="3"  attr:a="2"><child>data</child></root>
	data, _, err := canonicalize(element)
	if err != nil {
		t.Fatal(err)
	}
	actual := string(data)
	expected := `<root xmlns="tns" xmlns:attr="http://someotherns/for/attr" xmlns:be="anotherns/be" b="1" be:a="3" attr:a="2"><child>data</child></root>`
	if actual != expected {
		t.Fatalf("expected output of %s but got %s", expected, actual)
	}
}
