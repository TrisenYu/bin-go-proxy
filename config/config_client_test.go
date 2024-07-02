package config

import (
	"log"
	"testing"
)

func TestParseClient(t *testing.T) {
	now := ParseClientYAML(".\\test_client.yaml")
	if now == nil {
		t.Error(`unable to parse`)
		return
	}
	log.Println(now.Local.InterceptorPort)
	log.Println(now.Local.AsymmetricCipher)
	log.Println(now.Local.HashCipher)
	log.Println(now.Local.StreamCipher)
}
