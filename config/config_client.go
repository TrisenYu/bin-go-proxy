// SPDX-LICENSE-IDENTIFIER: GPL-2.0-ONLY
// (C) 2024 Author: <kisfg@hotmail.com>

package config

import (
	"log"
	"os"
	"sync"

	"bingoproxy/utils"

	"gopkg.in/yaml.v3"
)

type (
	local struct {
		InterceptorPort     uint16 `yaml:"InterceptorPort"`
		ProxySocket         string `yaml:"ProxySocket"`
		AsymmetricCipher    string `yaml:"AsymmetricCipher"`
		StreamCipher        string `yaml:"StreamCipher"`
		HashCipher          string `yaml:"HashCipher"`
		CompressedAlgorithm string `yaml:"CompressedAlgorithm"`
		AccessToken         string `yaml:"AccessToken"`
	}
	ClientCommunicationConfig struct {
		Local local `yaml:"local"`
	}
)

var (
	safe_read_client          sync.RWMutex
	GlobalClientConfiguration *ClientCommunicationConfig
	default_client_path       string = "./example_client.yaml"
)

func ParseClientYAML(path string) *ClientCommunicationConfig {
	safe_read_client.RLock()
	cfg_data, err := os.ReadFile(path)
	safe_read_client.RUnlock()
	if err != nil {
		log.Println(err.Error())
		return nil
	}
	safe_read_client.Lock()
	defer safe_read_client.Unlock()
	GlobalClientConfiguration = &ClientCommunicationConfig{}
	err = yaml.Unmarshal(cfg_data, GlobalClientConfiguration)
	if err != nil {
		log.Println(err.Error())
		GlobalClientConfiguration = nil
		return nil
	}
	return GlobalClientConfiguration
}

func init() {
	// we provide a default configuration, user can reset the configuratoin after initiation.'
	grandfa_dir, err := utils.GetFilePath(default_client_path)
	if err != nil {
		return // keep nil.
	}
	ParseClientYAML(grandfa_dir + `/config/` + default_client_path)
}
