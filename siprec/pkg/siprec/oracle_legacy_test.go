package siprec

import (
	"bytes"
	"encoding/xml"
	"os"
	"testing"
)

func TestOracleSCZ930LegacyNamespace(t *testing.T) {
	data, err := os.ReadFile("testdata/oracle_scz930_metadata.xml")
	if err != nil {
		t.Fatal(err)
	}
	for _, namespace := range []string{"urn:ietf:params:xml:ns:recording", "urn:ietf:params:xml:ns:recording:1"} {
		t.Run(namespace, func(t *testing.T) {
			input := bytes.Replace(data, []byte("urn:ietf:params:xml:ns:recording'"), []byte(namespace+"'"), 1)
			var metadata RSMetadata
			if err := xml.Unmarshal(input, &metadata); err != nil {
				t.Fatal(err)
			}
			if validation := ValidateSiprecMessage(&metadata); len(validation.Errors) > 0 {
				t.Fatal(validation.Errors)
			}
			if metadata.SessionID != "nyXkuxUFTy1iUhgQ9RiDUQ==" {
				t.Fatalf("session ID not preserved: %s", metadata.SessionID)
			}
			if len(metadata.Participants) != 2 || len(metadata.Streams) != 1 {
				t.Fatal("participants/streams lost")
			}
			if metadata.Participants[0].Aor[0].Value != "sip:1001@oracle.com" {
				t.Fatal("participant contact lost")
			}
			if metadata.Streams[0].Label != "16777221" || metadata.Streams[0].Mode != "separate" {
				t.Fatal("stream mapping lost")
			}
			if metadata.ResolveStreamParticipant("16777221") == nil {
				t.Fatal("stream participant association lost")
			}
			if _, err := xml.Marshal(&metadata); err != nil {
				t.Fatal("canonical metadata cannot be serialized:", err)
			}
		})
	}
}

func TestOracleCompatibilityStillRejectsInvalidXML(t *testing.T) {
	for _, data := range []string{
		`<recording xmlns="urn:unexpected"/>`,
		`<invalid xmlns="urn:ietf:params:xml:ns:recording"/>`,
		`<recording xmlns="urn:ietf:params:xml:ns:recording"><session></recording>`,
		`<!DOCTYPE recording [<!ENTITY injected SYSTEM "file:///etc/passwd">]><recording xmlns="urn:ietf:params:xml:ns:recording">&injected;</recording>`,
	} {
		var metadata RSMetadata
		if err := xml.Unmarshal([]byte(data), &metadata); err == nil {
			t.Fatal("invalid XML was accepted")
		}
	}
}
