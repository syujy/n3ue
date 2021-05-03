/*
 * N3UE Configuration Factory
 */

package config

import (
	"io/ioutil"

	"gopkg.in/yaml.v2"
)

const (
	N3UE_EXPECTED_CONFIG_VERSION = "1.0.0"
)

type Config struct {
	Info          *Info          `yaml:"Info"`
	Configuration *Configuration `yaml:"Configuration"`
	Log           *Log           `yaml:"Log"`
}

type Info struct {
	Version     string `yaml:"Version,omitempty"`
	Description string `yaml:"Description,omitempty"`
}

type Configuration struct {
	IKEBindAddress string `yaml:"IKEServiceIP"`
	N3IWFAddress   L4Addr `yaml:"N3IWFAddress"`
}

type Log struct {
	LogPath      string `yaml:"LogPath"`
	DebugLevel   string `yaml:"DebugLevel"`
	ReportCaller bool   `yaml:"ReportCaller"`
}

type L4Addr struct {
	IP   string `yaml:"IP"`
	Port int    `yaml:"Port"`
}

func (c *Config) ReadConfigFile(path string) error {
	if content, err := ioutil.ReadFile(path); err != nil {
		return err
	} else {
		if err = yaml.Unmarshal(content, c); err != nil {
			return err
		}
	}
	return nil
}

func (c *Config) CheckConfigVersion() bool {
	return c.getVersion() == N3UE_EXPECTED_CONFIG_VERSION
}

func (c *Config) getVersion() string {
	if c.Info != nil && c.Info.Version != "" {
		return c.Info.Version
	}
	return ""
}
