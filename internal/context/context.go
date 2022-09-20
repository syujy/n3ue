package context

import (
	"errors"
	"fmt"
	"io/ioutil"
	"github.com/syujy/n3ue/internal/config"
	"github.com/syujy/n3ue/internal/projenv"
	"net"
	"strconv"

	"github.com/sirupsen/logrus"
)

func errMsg(fields ...string) error {
	err := "Config "
	for _, s := range fields {
		err += "\"" + s + "\" "
	}
	err += "is not valid"
	return errors.New(err)
}

func (c *N3UEContext) Init(conf *config.Config) error {
	if conf.Log != nil {
		c.Log = new(Log)
		// Log path
		if len(conf.Log.LogPath) != 0 {
			c.Log.LogPath = conf.Log.LogPath
		} else {
			c.Log.LogPath = projenv.DefaultLogFile
		}
		// Debug level
		if l, err := logrus.ParseLevel(conf.Log.DebugLevel); err != nil {
			c.Log.DebugLevel = logrus.InfoLevel
		} else {
			c.Log.DebugLevel = l
		}
		// Report caller
		c.Log.ReportCaller = conf.Log.ReportCaller
	} else {
		c.Log = &Log{
			LogPath:      projenv.DefaultLogFile,
			DebugLevel:   logrus.InfoLevel,
			ReportCaller: false,
		}
	}

	if conf.Configuration != nil {
		// IKE service bind IP
		if addr := net.ParseIP(conf.Configuration.IKEBindAddress); addr == nil {
			return errMsg("IKEServiceBindIP")
		} else {
			c.IKEBindAddress = conf.Configuration.IKEBindAddress
		}

		// N3IWF address
		if addr := net.ParseIP(conf.Configuration.N3IWFAddress.IP); addr == nil {
			return errMsg("N3IWFAddress", "IP")
		} else {
			c.N3IWFAddress.IP = conf.Configuration.N3IWFAddress.IP
		}
		if port := conf.Configuration.N3IWFAddress.Port; port < 0 || port > 65535 {
			return errMsg("N3IWFAddress", "Port")
		} else if port == 0 {
			c.N3IWFAddress.Port = 500
		} else {
			c.N3IWFAddress.Port = uint16(port)
		}

		// IPsec interface
		if name := conf.Configuration.IPsecIf.Name; len(name) == 0 {
			c.IPSecIf.Name = "ipsec0"
		} else {
			c.IPSecIf.Name = name
		}
		if mark := conf.Configuration.IPsecIf.Mark; mark != nil {
			c.IPSecIf.Mark = new(uint32)
			*c.IPSecIf.Mark = *mark
		}

		// SUPI
		if supi := conf.Configuration.SUPI; len(supi) == 0 {
			return errMsg("SUPI")
		} else {
			c.Supi = supi
		}

		// NSSAI
		if nssai := conf.Configuration.Nssai; nssai != nil {
			c.Nssai = new(NSSAI)
			for _, snssai := range nssai.DefaultSNSSAIs {
				s := new(SNSSAI)
				s.SST = uint8(snssai.SST)
				if len(snssai.SD) != 6 && len(snssai.SD) != 0 {
					return errMsg("NSSAI", "DefaultSNSSAIs", "SD")
				}
				s.SD = snssai.SD
				c.Nssai.DefaultSNSSAIs = append(c.Nssai.DefaultSNSSAIs, s)
			}
			for _, snssai := range nssai.SNSSAIs {
				s := new(SNSSAI)
				s.SST = uint8(snssai.SST)
				if len(snssai.SD) != 6 && len(snssai.SD) != 0 {
					return errMsg("NSSAI", "SNSSAIs", "SD")
				}
				s.SD = snssai.SD
				c.Nssai.SNSSAIs = append(c.Nssai.SNSSAIs, s)
			}
		}

		// UE AMBR
		if ueAmbr := conf.Configuration.UeAmbr; ueAmbr != nil {
			c.UeAmbr = new(UEAMBR)
			c.UeAmbr.Uplink = ueAmbr.Uplink
			c.UeAmbr.Downlink = ueAmbr.Downlink
		}

		// Auth Data
		if am := conf.Configuration.Auth.AuthMethod; len(am) == 0 {
			return errMsg("Auth", "AuthMethod")
		} else {
			c.Auth.AuthMethod = am
		}
		if k := conf.Configuration.Auth.K; len(k) != 32 {
			return errMsg("Auth", "K")
		} else {
			c.Auth.K = k
		}
		if opc := conf.Configuration.Auth.OPC; len(opc) == 0 {
			if op := conf.Configuration.Auth.OP; len(op) == 0 {
				return errMsg("Auth", "OPC", "OP")
			} else if len(op) != 32 {
				return errMsg("Auth", "OP")
			} else {
				c.Auth.OP = op
			}
		} else if len(opc) != 32 {
			if op := conf.Configuration.Auth.OP; len(op) == 0 {
				return errMsg("Auth", "OPC")
			} else if len(op) != 32 {
				return errMsg("Auth", "OPC", "OP")
			} else {
				c.Auth.OP = op
			}
		} else {
			c.Auth.OPC = opc
		}
		if amf := conf.Configuration.Auth.AMF; len(amf) != 4 {
			return errMsg("Auth", "AMF")
		} else {
			c.Auth.AMF = amf
		}
		if sqnFile := conf.Configuration.Auth.SQNFile; len(sqnFile) != 0 {
			c.Auth.sqnFile = sqnFile
		} else {
			c.Auth.sqnFile = projenv.NASSQNFile
		}
		if content, err := ioutil.ReadFile(c.Auth.sqnFile); err != nil {
			return fmt.Errorf("%s. Read file failed: %s", errMsg("Auth", "SQNFile"), err)
		} else {
			if len(content) < 12 {
				return errMsg("Auth", "SQN")
			} else {
				content = content[:12]
			}
			c.Auth.SQN = string(content)
		}

		// Serving PLMN ID
		if plmn := conf.Configuration.ServingPLMNID; len(plmn) != 5 && len(plmn) != 6 {
			return errMsg("ServingPLMN")
		} else {
			c.PlmnID = plmn
		}

		// Algorithm
		if algo := conf.Configuration.CipheringAlgo; len(algo) == 0 {
			return errMsg("CipherAlgo")
		} else {
			c.CipheringAlgo = algo
		}
		if algo := conf.Configuration.IntegrityAlgo; len(algo) == 0 {
			return errMsg("IntegrityAlgo")
		} else {
			c.IntegrityAlgo = algo
		}
	}

	return nil
}

func (a *AuthData) AuthDataSQNAddOne() {
	num, _ := strconv.ParseInt(a.SQN, 16, 48)
	_ = ioutil.WriteFile(a.sqnFile, []byte(fmt.Sprintf("%x", num+1)), 0o644)
}
