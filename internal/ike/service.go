package ike

import (
	"encoding/binary"
	"fmt"
	"n3ue/internal/n3ue_exclusive"
	"net"
	"sync"

	"bitbucket.org/_syujy/ike/types"
	"github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"
)

type IKEService struct {
	n3ue_exclusive.N3UECommon
	log *logrus.Entry
	// socket handler
	socketHandler500  *socketHandler
	socketHandler4500 *socketHandler
	// dispatcher
	packetDispatcher *dispatcher
}

func (s *IKEService) Init(c n3ue_exclusive.N3UECommon) {
	// set n3ue common
	s.N3UECommon = c
	// init logger
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
		err = unix.SetsockoptInt(int(file.Fd()), unix.IPPROTO_UDP, types.OPT_UDP_ENCAP, types.OPTVAL_UDP_ENCAP_ESPINUDP)
		if err != nil {
			return fmt.Errorf("Set socket options failed: %+v", err)
		}
		err = file.Close()
		if err != nil {
			return fmt.Errorf("Close socket file failed: %+v", err)
		}
	}

	// Chan
	shInputChan := make(chan *packet, 10000)
	shOutputChan500 := make(chan *packet, 10000)
	shOutputChan4500 := make(chan *packet, 10000)
	saOutputChan := make(chan *packet, 10000)
	// socket handler
	s.socketHandler500 = &socketHandler{
		log:        s.log,
		conn:       udpConnPort500,
		port:       500,
		inputChan:  shInputChan,
		outputChan: shOutputChan500,
	}
	s.socketHandler500.run()
	s.socketHandler4500 = &socketHandler{
		log:        s.log,
		conn:       udpConnPort4500,
		port:       4500,
		inputChan:  shInputChan,
		outputChan: shOutputChan4500,
	}
	s.socketHandler4500.run()
	// dispatcher
	s.packetDispatcher = &dispatcher{
		log:              s.log,
		shInputChan:      shInputChan,
		shOutputChan500:  shOutputChan500,
		shOutputChan4500: shOutputChan4500,
		saOutputChan:     saOutputChan,
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
	log        *logrus.Entry
	conn       *net.UDPConn
	port       uint16
	inputChan  chan *packet
	outputChan chan *packet
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

		sh.inputChan <- p
	}
}

func (sh *socketHandler) writer() {
	for {
		p := <-sh.outputChan
		n, err := sh.conn.WriteToUDP(p.Payload, p.RemoteAddr)
		if err != nil {
			sh.log.Error(err)
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
	// socket handler
	shInputChan      chan *packet
	shOutputChan500  chan *packet
	shOutputChan4500 chan *packet
	// IKESA
	saInputChan  sync.Map // map[uint64]chan *packet
	saOutputChan chan *packet
}

func (d *dispatcher) run() {
	go d.inputDispatcher()
	go d.outputDispatcher()
}

func (d *dispatcher) inputDispatcher() {
	for {
		p := <-d.shInputChan
		if p.LocalPort == 4500 {
			if !isAllZero(p.Payload[0:4]) {
				d.log.Warn(
					"Received an IKE packet that does not prepend 4 bytes zero from UDP port 4500," +
						" this packet may be the UDP encapsulated ESP. The packet will not be handled.")
				continue
			}
			p.Payload = p.Payload[4:]
		}
		// get flag
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

		iChan, ok := d.saInputChan.Load(spi)
		if !ok {
			iChan, _ = d.saInputChan.Load(0)
		}
		if iChan.(chan *packet) != nil { // if nil, drop
			iChan.(chan *packet) <- p
		}
	}
}

func (d *dispatcher) outputDispatcher() {
	for {
		p := <-d.saOutputChan
		if p.LocalPort == 4500 {
			// prepend 4 bytes zero
			prependZero := make([]byte, 4)
			p.Payload = append(prependZero, p.Payload...)
			d.shOutputChan4500 <- p
		} else {
			d.shOutputChan500 <- p
		}
	}
}

func (d *dispatcher) registerSAInputChan(localSPI uint64, iChan chan *packet) {
	d.saInputChan.Store(localSPI, iChan)
}

func (d *dispatcher) deregisterSAInputChan(localSPI uint64) {
	d.saInputChan.Delete(localSPI)
}

func (d *dispatcher) send(p *packet) {
	d.saOutputChan <- p
}

func isAllZero(b []byte) bool {
	for _, value := range b {
		if value != 0 {
			return false
		}
	}
	return true
}
