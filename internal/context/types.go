package context

import (
	"sync"

	"github.com/sirupsen/logrus"
)

type N3UEContext struct {
	// Configs
	Log            *Log
	IKEBindAddress string
	N3IWFAddress   L4Addr
	// Data
	// Mapping
	SPI_IKESA sync.Map // map[uint64]IKESA
}

type Log struct {
	LogPath      string
	DebugLevel   logrus.Level
	ReportCaller bool
}

type L4Addr struct {
	IP   string
	Port uint16
}
