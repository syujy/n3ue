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
	IKEBindAddress string         `yaml:"IKEServiceBindIP"`
	N3IWFAddress   L4Addr         `yaml:"N3IWFAddress"`
	IPsecIf        IPSecInterface `yaml:"IPSecInterface"`
	SUPI           string         `yaml:"SUPI"`
	Nssai          *NSSAI         `yaml:"NSSAI"`
	UeAmbr         *UEAMBR        `yaml:"UEAMBR"`
	Auth           AuthData       `yaml:"Auth"`
	ServingPLMNID  string         `yaml:"ServingPLMN"`
	CipheringAlgo  string         `yaml:"CipherAlgo"`
	IntegrityAlgo  string         `yaml:"IntegrityAlgo"`
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

type IPSecInterface struct {
	Name string  `yaml:"Name"`
	Mark *uint32 `yaml:"Mark"`
}

type NSSAI struct {
	DefaultSNSSAIs []*SNSSAI `yaml:"DefaultSNSSAIs"`
	SNSSAIs        []*SNSSAI `yaml:"SNSSAIs"`
}

type SNSSAI struct {
	SST int    `yaml:"SST"`
	SD  string `yaml:"SD"`
}

type UEAMBR struct {
	Uplink   string `yaml:"Uplink"`
	Downlink string `yaml:"Downlink"`
}

type AuthData struct {
	AuthMethod string `yaml:"AuthMethod"`
	K          string `yaml:"K"`
	OPC        string `yaml:"OPC"`
	OP         string `yaml:"OP"`
	AMF        string `yaml:"AMF"`
	SQNFile    string `yaml:"SQNFile"` // 48-bit integer in hex format
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
