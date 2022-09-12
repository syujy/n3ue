package ike

import (
	"context"
	"fmt"
	"n3ue/internal/n3ue_exclusive"
	"n3ue/internal/sessInterface"
	"net"

	"bitbucket.org/_syujy/ike/security"
	"github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"
)

type Session struct {
	n3ue_exclusive.N3UECommon
	// Log
	log *logrus.Entry
	// Security association
	ikesa   *security.IKESA
	childsa []*security.ChildSA
	// Services
	ikeService *IKEService
	// Channels
	ikeReqReadChan chan *packet
	ikeResReadChan chan *packet
	// Packets
	packetTemplate packet
	// Communication with NAS task
	nasSessIntRead  chan *sessInterface.SessInt
	nasSessIntWrite chan *sessInterface.SessInt
	// Virtual tunnel interface
	link *netlink.Vti
	addr *netlink.Addr
	// Golang context cancel function, for controlling tasks
	handlerCancel   context.CancelFunc
	keepaliveCancel context.CancelFunc
}

func (s *Session) Init(c n3ue_exclusive.N3UECommon, ikeService *IKEService, sir, siw chan *sessInterface.SessInt) {
	// Set n3ue common
	s.N3UECommon = c
	// Init logger
	s.log = s.Log.WithFields(logrus.Fields{"component": "N3UE", "category": "IKE"})
	// IKE service
	s.ikeService = ikeService
	// Channels
	s.ikeReqReadChan = make(chan *packet, 100)
	s.ikeResReadChan = make(chan *packet, 100)
	s.nasSessIntRead = sir
	s.nasSessIntWrite = siw
	// Virtual tunnel interface
	s.link = new(netlink.Vti)
	s.link.LinkAttrs = netlink.NewLinkAttrs()
	s.link.Name = s.Ctx.IPSecIf.Name
	if s.Ctx.IPSecIf.Mark != nil {
		s.link.IKey = *s.Ctx.IPSecIf.Mark
		s.link.OKey = *s.Ctx.IPSecIf.Mark
	}
	s.link.Local = net.ParseIP(s.Ctx.IKEBindAddress)
	s.link.Remote = net.ParseIP(s.Ctx.N3IWFAddress.IP)
	s.addr = new(netlink.Addr)
	s.addr.IPNet = new(net.IPNet)
	// Create task for handle IKE request
	newTask := NewTask()
	newTask.ctx, s.handlerCancel = context.WithCancel(context.Background())
	newTask.PushFunc(s.handle)
	s.TM.NewTask(newTask)
}

func (s *Session) SessionStopHard() error {
	// Stop IKE requests handler
	s.handlerCancel()
	s.keepaliveCancel()
	// Flush XFRM rules
	if err := netlink.XfrmStateFlush(netlink.Proto(0)); err != nil {
		return fmt.Errorf("Flush XFRM state failed: %+v", err)
	}
	if err := netlink.XfrmPolicyFlush(); err != nil {
		return fmt.Errorf("Flush XFRM policy failed: %+v", err)
	}
	// Remove the kernel resources
	if s.link != nil {
		if err := netlink.LinkDel(s.link); err != nil {
			return fmt.Errorf("Delete ue addr failed[%s]", err.Error())
		}
		s.link = nil
		s.addr = nil
	}
	return nil
}

func (s *Session) checkMsgError(err error, msg string) {
	if err != nil {
		s.log.Errorf("Handle %s Error: %s", msg, err.Error())
	}
}
