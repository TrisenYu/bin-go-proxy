// SPDX-LICENSE-IDENTIFIER: GPL-2.0-ONLY
// (C) 2024 Author: <kisfg@hotmail.com>

package config

import (
	"log"
	"os"
	"sync"

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

var safe_read sync.RWMutex

func ParseClientYAML(path string) *ClientCommunicationConfig {
	safe_read.RLock()
	cfg_data, err := os.ReadFile(path)
	safe_read.RUnlock()
	if err != nil {
		log.Println(err.Error())
		return nil
	}
	var res ClientCommunicationConfig
	err = yaml.Unmarshal(cfg_data, &res)
	if err != nil {
		log.Println(err.Error())
		return nil
	}
	return &res
}
