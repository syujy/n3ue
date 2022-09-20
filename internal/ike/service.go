package ike

import (
	"encoding/binary"
	"fmt"
	"github.com/syujy/n3ue/internal/n3ue_exclusive"
	"net"
	"sync"

	"github.com/syujy/ikev2/types"
	"github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"
)

type IKEService struct {
	n3ue_exclusive.N3UECommon
	log *logrus.Entry
	// Socket handler
	socketHandler500  *socketHandler
	socketHandler4500 *socketHandler
	// Dispatcher
	packetDispatcher *dispatcher
}

func (s *IKEService) Init(c n3ue_exclusive.N3UECommon) {
	// Set n3ue common
	s.N3UECommon = c
	// Init logger
	s.log = s.Log.WithFields(logrus.Fields{"component": "N3UE", "category": "IKEService"})
}

func (s *IKEService) Run() error {
	ip := s.Ctx.IKEBindAddress
	// Conn
	udpAddrPort500, err := net.ResolveUDPAddr("udp", ip+":500")
	if err != nil {
		return fmt.Errorf("Resolve UDP address port 500 failed: %+v", err)
	}
	udpConnPort500, err := net.ListenUDP("udp", udpAddrPort500)
	if err != nil {
		return fmt.Errorf("Listen UDP port 500 failed: %+v", err)
	}
	udpAddrPort4500, err := net.ResolveUDPAddr("udp", ip+":4500")
	if err != nil {
		return fmt.Errorf("Resolve UDP address port 4500 failed: %+v", err)
	}
	udpConnPort4500, err := net.ListenUDP("udp", udpAddrPort4500)
	if err != nil {
		return fmt.Errorf("Listen UDP port 4500 failed: %+v", err)
	}
	// UDP encap for xfrm
	if file, err := udpConnPort4500.File(); err != nil {
		return fmt.Errorf("Setting UDP encap flag failed: %+v", err)
	} else {
		if err = unix.SetsockoptInt(int(file.Fd()), unix.IPPROTO_UDP, types.OPT_UDP_ENCAP, types.OPTVAL_UDP_ENCAP_ESPINUDP); err != nil {
			return fmt.Errorf("Set socket options failed: %+v", err)
		}
		if err = file.Close(); err != nil {
			return fmt.Errorf("Close socket file failed: %+v", err)
		}
	}

	// Chan
	shPacketIn := make(chan *packet, 10000)
	shPacketOut500 := make(chan *packet, 10000)
	shPacketOut4500 := make(chan *packet, 10000)
	saPacketOut := make(chan *packet, 10000)
	// Socket handler
	s.socketHandler500 = &socketHandler{
		log:       s.log,
		conn:      udpConnPort500,
		port:      500,
		packetIn:  shPacketIn,
		packetOut: shPacketOut500,
	}
	s.socketHandler500.run()
	s.socketHandler4500 = &socketHandler{
		log:       s.log,
		conn:      udpConnPort4500,
		port:      4500,
		packetIn:  shPacketIn,
		packetOut: shPacketOut4500,
	}
	s.socketHandler4500.run()
	// Dispatcher
	s.packetDispatcher = &dispatcher{
		log:             s.log,
		shPacketIn:      shPacketIn,
		shPacketOut500:  shPacketOut500,
		shPacketOut4500: shPacketOut4500,
		saPacketOut:     saPacketOut,
	}
	s.packetDispatcher.run()

	return nil
}

type packet struct {
	LocalPort  uint16
	RemoteAddr *net.UDPAddr
	Payload    []byte
}

type socketHandler struct {
	log       *logrus.Entry
	conn      *net.UDPConn
	port      uint16
	packetIn  chan *packet
	packetOut chan *packet
}

func (sh *socketHandler) run() {
	go sh.reader()
	go sh.writer()
}

func (sh *socketHandler) reader() {
	data := make([]byte, 65536)

	for {
		n, remoteAddr, err := sh.conn.ReadFromUDP(data)
		if err != nil {
			sh.log.Errorf("ReadFromUDP failed: %+v", err)
			continue
		}

		p := new(packet)

		p.LocalPort = sh.port
		p.RemoteAddr = remoteAddr
		p.Payload = make([]byte, n)
		copy(p.Payload, data[:n])

		sh.packetIn <- p
	}
}

func (sh *socketHandler) writer() {
	for {
		p := <-sh.packetOut
		n, err := sh.conn.WriteToUDP(p.Payload, p.RemoteAddr)
		if err != nil {
			sh.log.Errorf("WriteToUDP failed: %+v", err)
			return
		}
		if n != len(p.Payload) {
			sh.log.Errorf("Not all of the data is sent. Total length: %d. Sent: %d.", len(p.Payload), n)
			return
		}
	}
}

type dispatcher struct {
	log *logrus.Entry
	// Socket handler
	shPacketIn      chan *packet
	shPacketOut500  chan *packet
	shPacketOut4500 chan *packet
	// IKESA
	saReqPacketIn sync.Map // map[uint64]chan *packet
	saResPacketIn sync.Map // map[uint64]chan *packet
	saPacketOut   chan *packet
}

func (d *dispatcher) run() {
	go d.inputDispatcher()
	go d.outputDispatcher()
}

func (d *dispatcher) inputDispatcher() {
	for {
		p := <-d.shPacketIn
		if p.LocalPort == 4500 {
			if !isAllZero(p.Payload[0:4]) {
				d.log.Warn(
					"Received an IKE packet that does not prepend 4 bytes zero from UDP port 4500," +
						" this packet may be the UDP encapsulated ESP. The packet will not be handled.")
				continue
			}
			p.Payload = p.Payload[4:]
		}
		// Get flag
		if len(p.Payload) < 28 {
			d.log.Warn("Received UDP packet that doesn't follow IKE format. Drop.")
			continue
		}
		flagI := p.Payload[19] & types.InitiatorBitCheck
		var spi uint64
		if flagI == 0 {
			spi = binary.BigEndian.Uint64(p.Payload[0:8])
		} else {
			spi = binary.BigEndian.Uint64(p.Payload[8:16])
		}
		flagR := p.Payload[19] & types.ResponseBitCheck
		var iChan chan *packet
		if flagR == 0 {
			if ch, ok := d.saReqPacketIn.Load(spi); ok {
				iChan = ch.(chan *packet)
			} else {
				if ch, ok := d.saReqPacketIn.Load(0); ok {
					iChan = ch.(chan *packet)
				}
			}
		} else {
			if ch, ok := d.saResPacketIn.Load(spi); ok {
				iChan = ch.(chan *packet)
			}
		}
		// Packet in
		if iChan != nil { // if nil, drop
			iChan <- p
		}
	}
}

func (d *dispatcher) outputDispatcher() {
	for {
		p := <-d.saPacketOut
		if p.LocalPort == 4500 {
			// Prepend 4 bytes zero
			prependZero := make([]byte, 4)
			p.Payload = append(prependZero, p.Payload...)
			d.shPacketOut4500 <- p
		} else {
			d.shPacketOut500 <- p
		}
	}
}

func (d *dispatcher) registerReqReadChan(localSPI uint64, iChan chan *packet) {
	d.saReqPacketIn.Store(localSPI, iChan)
}

func (d *dispatcher) deregisterReqReadChan(localSPI uint64) {
	d.saReqPacketIn.Delete(localSPI)
}

func (d *dispatcher) registerResReadChan(localSPI uint64, iChan chan *packet) {
	d.saResPacketIn.Store(localSPI, iChan)
}

func (d *dispatcher) deregisterResReadChan(localSPI uint64) {
	d.saResPacketIn.Delete(localSPI)
}

func (d *dispatcher) send(p *packet) {
	d.saPacketOut <- p
}

func isAllZero(b []byte) bool {
	for _, value := range b {
		if value != 0 {
			return false
		}
	}
	return true
}
