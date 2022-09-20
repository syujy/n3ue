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
	IPSecIf        IPSecInterface
	Supi           string
	Nssai          *NSSAI
	UeAmbr         *UEAMBR
	Auth           AuthData
	PlmnID         string
	CipheringAlgo  string
	IntegrityAlgo  string

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

type IPSecInterface struct {
	Name string
	Mark *uint32
}

type NSSAI struct {
	DefaultSNSSAIs []*SNSSAI
	SNSSAIs        []*SNSSAI
}

type SNSSAI struct {
	SST uint8
	SD  string
}

type UEAMBR struct {
	Uplink   string
	Downlink string
}

type AuthData struct {
	AuthMethod string
	K          string
	OPC        string
	OP         string
	AMF        string
	sqnFile    string
	SQN        string
}
