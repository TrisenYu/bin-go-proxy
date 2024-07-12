package config

import (
	"log"
	"os"
	"sync"

	"gopkg.in/yaml.v3"
)

type (
	ProxyConfig struct {
		PathToAccessToken string `yaml:"PathToAccessToken"`
		ListeningPort     uint16 `yaml:"ListeningPort"`
	}
	ProxyCommunicationConfig struct {
		Local ProxyConfig `yaml:"ProxyConfig"`
	}
)

var safe_read_proxy sync.RWMutex

func ParseProxyYAML(path string) *ProxyCommunicationConfig {
	safe_read_proxy.RLock()
	cfg_data, err := os.ReadFile(path)
	safe_read_proxy.RUnlock()
	if err != nil {
		log.Println(err.Error())
		return nil
	}
	var res ProxyCommunicationConfig
	err = yaml.Unmarshal(cfg_data, &res)
	if err != nil {
		log.Println(err.Error())
		return nil
	}
	return &res
}
