package context

import (
	"errors"
	"n3ue/internal/config"
	"n3ue/internal/projenv"
	"net"

	"github.com/sirupsen/logrus"
)

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
		if addr := net.ParseIP(conf.Configuration.IKEBindAddress); addr == nil {
			return errors.New("Config \"IKEServiceIP\" is not valid")
		} else {
			c.IKEBindAddress = conf.Configuration.IKEBindAddress
		}

		if addr := net.ParseIP(conf.Configuration.N3IWFAddress.IP); addr == nil {
			return errors.New("Config \"N3IWFAddress\" IP is not valid")
		} else {
			c.N3IWFAddress.IP = conf.Configuration.N3IWFAddress.IP
		}

		if port := conf.Configuration.N3IWFAddress.Port; port < 0 || port > 65535 {
			return errors.New("Config \"N3IWFAddress\" Port is not valid")
		} else if port == 0 {
			c.N3IWFAddress.Port = 500
		} else {
			c.N3IWFAddress.Port = uint16(port)
		}
	}

	return nil
}
