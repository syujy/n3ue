package sessInterface

import (
	"net"

	"github.com/vishvananda/netlink"
)

type CommType string

const (
	REG          = "REG"
	PDUSessEstab = "PDUSessEstab"
)

// REG
// Used in registration procedure
type Param_REG struct {
	// EAPSignalling - NAS
	ANParameter []byte
	NASPDUtoIKE chan []byte
	NASPDUtoNAS chan []byte
	// N3IWF Key
	Kn3iwf []byte
	// NAS TCP Address
	Addr *net.TCPAddr
}

// PDUSessEstab
// Used in PDU session establishment procedure
type Param_PDUSessEstab struct {
	// link
	Link *netlink.Gretun
}

type SessInt struct {
	// Communication Types
	Comm CommType

	// Parameter or some context
	Value interface{}
}
