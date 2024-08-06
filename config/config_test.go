package config

import (
	"log"
	"testing"
)

func TestParser(t *testing.T) {
	// client
	{
		now := ParseClientYAML("./example_client.yaml")
		if now == nil {
			t.Error(`unable to parse client yaml.`)
			return
		}
		log.Println(now.Local.InterceptorPort)
		log.Println(now.Local.AsymmetricCipher)
		log.Println(now.Local.HashCipher)
		log.Println(now.Local.StreamCipher)
	}
	// proxy
	{
		now := ParseProxyYAML("./example_proxy.yaml")
		if now == nil {
			t.Error(`unable to parse proxy yaml.`)
			return
		}
		log.Println(now.Local.PathToAccessToken)
		log.Println(now.Local.ListeningPort)
	}
}
