package config

import (
	"log"
	"os"
	"sync"

	"bingoproxy/utils"

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

var (
	safe_read_proxy          sync.RWMutex
	GlobalProxyConfiguration *ProxyCommunicationConfig
	default_proxy_path       string = "./example_proxy.yaml"
)

func ParseProxyYAML(path string) *ProxyCommunicationConfig {
	safe_read_proxy.RLock()
	cfg_data, err := os.ReadFile(path)
	safe_read_proxy.RUnlock()
	if err != nil {
		log.Println(err.Error())
		return nil
	}
	safe_read_proxy.Lock()
	defer safe_read_proxy.Unlock()
	GlobalProxyConfiguration = &ProxyCommunicationConfig{}
	err = yaml.Unmarshal(cfg_data, GlobalProxyConfiguration)
	if err != nil {
		log.Println(err.Error())
		GlobalProxyConfiguration = nil
		return nil
	}
	return GlobalProxyConfiguration
}

func init() {
	grandpa_dir, err := utils.GetFilePath(default_client_path)
	if err != nil {
		return // keep nil.
	}
	// we provide a default configuration, user can reset the configuratoin after initiation.
	ParseProxyYAML(grandpa_dir + `/config/` + default_proxy_path)
}
