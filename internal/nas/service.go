package nas

import (
	"n3ue/internal/n3ue_exclusive"
	"net"

	"github.com/sirupsen/logrus"
)

type NASTCPService struct {
	n3ue_exclusive.N3UECommon
	log *logrus.Entry
	// Connection
	conn *net.TCPConn
	// Channels
	packetIn  chan []byte
	packetOut chan []byte
}

func (s *NASTCPService) Init(c n3ue_exclusive.N3UECommon, conn *net.TCPConn, packetIn, packetOut chan []byte) {
	// Set n3ue common
	s.N3UECommon = c
	// Init logger
	s.log = s.Log.WithFields(logrus.Fields{"component": "N3UE", "category": "NASTCPService"})
	// Connection
	s.conn = conn
	// Channels
	s.packetIn = packetIn
	s.packetOut = packetOut
}

func (s *NASTCPService) Run() {
	go s.reader()
	go s.writer()
}

func (s *NASTCPService) reader() {
	data := make([]byte, 65536)

	for {
		n, err := s.conn.Read(data)
		if err != nil {
			s.log.Errorf("Read failed: %+v", err)
			return
		}

		naspdu := make([]byte, len(data))
		copy(naspdu, data[:n])

		s.packetIn <- naspdu
	}
}

func (s *NASTCPService) writer() {
	for {
		data := <-s.packetOut
		n, err := s.conn.Write(data)
		if err != nil {
			s.log.Errorf("Write failed: %+v", err)
			return
		}
		if n != len(data) {
			s.log.Errorf("Not all of the data is sent. Total length: %d. Sent: %d.", len(data), n)
			return
		}
	}
}
