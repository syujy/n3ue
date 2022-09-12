package nas

import (
	"context"
	"encoding/binary"
	"fmt"
	"n3ue/internal/n3ue_exclusive"
	"n3ue/internal/sessInterface"
	"regexp"
	"sync"

	"bitbucket.org/free5gc-team/UeauCommon"
	"bitbucket.org/free5gc-team/fsm"
	"bitbucket.org/free5gc-team/nas/nasType"
	"bitbucket.org/free5gc-team/nas/security"
	"bitbucket.org/free5gc-team/ngap/ngapType"
	"bitbucket.org/free5gc-team/openapi/models"
	"github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"
)

const (
	RmStateRegistered  = "REGISTERED"
	RmStateRegistering = "REGISTERING"
	RmStateDeregitered = "DEREGISTERED"
)

const (
	CmStateConnected = "CONNECTED"
	CmStateIdle      = "IDLE"
)

const (
	MsgRegisterSuccess       = "Registration success"
	MsgRegisterFail          = "Registration fail"
	MsgServiceRequestSuccess = "ServiceRequest success"
	MsgServiceRequestFail    = "ServiceRequest fail"
	MsgDeregisterSuccess     = "Deregistration success"
	MsgDeregisterFail        = "Deregistration fail"
)

type Session struct {
	n3ue_exclusive.N3UECommon
	// Log
	log *logrus.Entry
	// NAS context
	c *NAS
	// NAS TCP service
	nasTCPService *NASTCPService
	// Channels
	readChan  chan []byte
	writeChan chan []byte
	// Communication with IKE task
	ikeSessIntRead  chan *sessInterface.SessInt
	ikeSessIntWrite chan *sessInterface.SessInt
	// Golang context cancel function, for controlling tasks
	cancel context.CancelFunc
}

func (s *Session) Init(c n3ue_exclusive.N3UECommon, sir, siw chan *sessInterface.SessInt) {
	// Set n3ue common
	s.N3UECommon = c
	// Init logger
	s.log = s.Log.WithFields(logrus.Fields{"component": "N3UE", "category": "NAS"})
	// NAS context
	s.c = NewUeContext()
	s.c.Supi = s.Ctx.Supi
	s.c.ServingPlmnId = s.Ctx.PlmnID
	switch s.Ctx.IntegrityAlgo {
	case "NIA0":
		s.c.IntegrityAlg = security.AlgIntegrity128NIA0
	case "NIA1":
		s.c.IntegrityAlg = security.AlgIntegrity128NIA1
	case "NIA2":
		s.c.IntegrityAlg = security.AlgIntegrity128NIA2
	case "NIA3":
		s.c.IntegrityAlg = security.AlgIntegrity128NIA3
	}

	switch s.Ctx.CipheringAlgo {
	case "NEA0":
		s.c.CipheringAlg = security.AlgCiphering128NEA0
	case "NEA1":
		s.c.CipheringAlg = security.AlgCiphering128NEA1
	case "NEA2":
		s.c.CipheringAlg = security.AlgCiphering128NEA2
	case "NEA3":
		s.c.CipheringAlg = security.AlgCiphering128NEA3
	}
	// Channels
	s.readChan = make(chan []byte, 10)
	s.writeChan = make(chan []byte, 10)
	s.ikeSessIntRead = sir
	s.ikeSessIntWrite = siw
}

func (s *Session) SessionStopHard() error {
	// Stop NAS TCP service
	s.cancel()
	// Remove the kernel resources
	if err := s.c.DelAllPduSession(); err != nil {
		return fmt.Errorf("Delete all PDU session failed: %+v", err)
	}
	return nil
}

func (s *Session) checkMsgError(err error, msg string) {
	if err != nil {
		s.log.Errorf("Handle %s Error: %s", msg, err.Error())
	}
}

type NAS struct {
	// registration related
	FollowOnRequest bool
	Supi            string // init
	Guti            *nasType.GUTI5G
	ServingPlmnId   string // init
	// security
	ULCount      security.Count
	DLCount      security.Count
	CipheringAlg uint8
	IntegrityAlg uint8
	KnasEnc      [16]uint8
	KnasInt      [16]uint8
	Kamf         []uint8
	Kn3iwf       []uint8
	NgKsi        uint8
	// PduSession
	PduSession map[int64]*SessionContext
	// related Context
	RmState *fsm.State
	CmState *fsm.State
}

type SessionContext struct {
	Mtx sync.Mutex
	// GtpHdr       []byte
	// GtpHdrLen    uint16
	PduSessionId int64
	Dnn          string
	Snssai       models.Snssai
	Link         *netlink.Gretun
	Addr         *netlink.Addr
	//QosFlows     map[int64]*QosFlow // QosFlowIdentifier as key
	// Sess Channel To Tcp Client
	//SessTcpChannelMsg chan string
}

type QosFlow struct {
	Identifier int64
	Parameters ngapType.QosFlowLevelQosParameters
}

func NewUeContext() *NAS {
	return &NAS{
		PduSession: make(map[int64]*SessionContext),
		RmState:    fsm.NewState(RmStateDeregitered),
		CmState:    fsm.NewState(CmStateIdle),
	}
}

func (n *NAS) AddPduSession(pduSessionId uint8, dnn string, snssai models.Snssai) *SessionContext {
	sess := &SessionContext{
		PduSessionId: int64(pduSessionId),
		Dnn:          dnn,
		Snssai:       snssai,
	}
	n.PduSession[sess.PduSessionId] = sess
	return sess
}

func (n *NAS) DelPduSession(pduSessionID int64) error {
	sess := n.PduSession[pduSessionID]
	sess.Mtx.Lock()
	if sess.Link != nil {
		if err := netlink.LinkDel(sess.Link); err != nil {
			return fmt.Errorf("Delete ue addr failed[%s]", err.Error())
		}
		sess.Link = nil
		sess.Addr = nil
	}
	sess.Mtx.Unlock()
	delete(n.PduSession, pduSessionID)
	return nil
}

func (n *NAS) DelAllPduSession() error {
	for _, sess := range n.PduSession {
		sess.Mtx.Lock()
		if sess.Link != nil {
			if err := netlink.LinkDel(sess.Link); err != nil {
				return fmt.Errorf("Delete ue addr failed[%s]", err.Error())
			}
			sess.Link = nil
			sess.Addr = nil
		}
		sess.Mtx.Unlock()
		delete(n.PduSession, sess.PduSessionId)
	}
	return nil
}

/*
func (s *SessionContext) SendMsg(msg string) {
	if s.SessTcpChannelMsg != nil {
		select {
		case s.SessTcpChannelMsg <- msg:
		default:
			logger.ContextLog.Warnf("Can't send Msg to Tcp client")
		}
	}
}
*/

// func (s *SessionContext) GetGtpConn() (*net.UDPConn, error) {
// 	key := fmt.Sprintf("%s,%s", s.DLAddr, s.ULAddr)
// 	if conn := Simulator_Self().GtpConnPool[key]; conn != nil {
// 		return conn, nil
// 	} else {
// 		return nil, fmt.Errorf("gtp conn is empty, map key [%s]", key)
// 	}
// }

// func (s *SessionContext) NewGtpHeader(extHdrFlag, sqnFlag, numFlag byte) {
// 	extHdrFlag &= 0x1
// 	sqnFlag &= 0x1
// 	numFlag &= 0x1
// 	if extHdrFlag == 0 && sqnFlag == 0 && numFlag == 0 {
// 		s.GtpHdrLen = 8
// 	} else {
// 		s.GtpHdrLen = 12
// 	}
// 	s.GtpHdr = make([]byte, s.GtpHdrLen)
// 	// Version: 3-bit, gtpv1=1
// 	// Protocol type: 1-bit, GTP=1, GTP'=0
// 	// Reserved: 1-bit 0
// 	// E: 1-bit
// 	// S: 1-bit
// 	// PN: 1-bit
// 	s.GtpHdr[0] = 0x01<<5 | 0x01<<4 | extHdrFlag<<2 | sqnFlag<<1 | numFlag
// 	// Message Type: 8-bit reference to 3GPP TS 29.060 subclause 7.1
// 	s.GtpHdr[1] = 0xff
// 	// Total Length: 16-bit not include first 8 bits
// 	// Wait for realData
// 	// TEID: 32-bit
// 	binary.BigEndian.PutUint32(s.GtpHdr[4:8], s.ULTEID)
// 	// Sequence number: 32-bit (optinal, if D is true)
// 	// N-PDU number: 16-bit (optinal, if PN is true)
// 	// Next extension header type: 16-bit (optinal, if E is true)
// }

/*
func (n *NAS) SendAPINotification(status api.StatusCode, msg string) {
	n.ApiNotifyChan <- ApiNotification{
		Status:           status,
		Message:          msg,
		RestartCount:     n.RestartCount,
		RestartTimeStamp: n.RestartTimeStamp,
	}
}
*/

func (n *NAS) GetServingNetworkName() string {
	mcc := n.ServingPlmnId[:3]
	mnc := n.ServingPlmnId[3:]
	if len(mnc) == 2 {
		mnc = "0" + mnc
	}
	return fmt.Sprintf("5G:mnc%s.mcc%s.3gppnetwork.org", mnc, mcc)
}

// TS 33.501 Annex A.4
func (n *NAS) DeriveRESstar(ck []byte, ik []byte, servingNetworkName string, rand []byte, res []byte) []byte {
	inputKey := append(ck, ik...)
	FC := UeauCommon.FC_FOR_RES_STAR_XRES_STAR_DERIVATION
	P0 := []byte(servingNetworkName)
	L0 := UeauCommon.KDFLen(P0)
	P1 := rand
	L1 := UeauCommon.KDFLen(P1)
	P2 := res
	L2 := UeauCommon.KDFLen(P2)
	kdfVal_for_resStar := UeauCommon.GetKDFValue(inputKey, FC, P0, L0, P1, L1, P2, L2)
	return kdfVal_for_resStar[len(kdfVal_for_resStar)/2:]
}

// TS 33.501 Annex A.2
func DerivateKausf(ck []byte, ik []byte, servingNetworkName string, sqnXorAK []byte) []byte {
	inputKey := append(ck, ik...)
	P0 := []byte(servingNetworkName)
	L0 := UeauCommon.KDFLen(P0)
	P1 := sqnXorAK
	L1 := UeauCommon.KDFLen(P1)
	return UeauCommon.GetKDFValue(inputKey, UeauCommon.FC_FOR_KAUSF_DERIVATION, P0, L0, P1, L1)
}

func DerivateKseaf(kausf []byte, servingNetworkName string) []byte {
	P0 := []byte(servingNetworkName)
	L0 := UeauCommon.KDFLen(P0)
	return UeauCommon.GetKDFValue(kausf, UeauCommon.FC_FOR_KSEAF_DERIVATION, P0, L0)
}

func (n *NAS) DerivateKamf(kseaf []byte, abba []byte) {
	supiRegexp, _ := regexp.Compile("(?:imsi|supi)-([0-9]{5,15})")
	groups := supiRegexp.FindStringSubmatch(n.Supi)
	if groups == nil {
		return
	}
	P0 := []byte(groups[1])
	L0 := UeauCommon.KDFLen(P0)
	P1 := abba
	L1 := UeauCommon.KDFLen(P1)

	n.Kamf = UeauCommon.GetKDFValue(kseaf, UeauCommon.FC_FOR_KAMF_DERIVATION, P0, L0, P1, L1)
}

// Algorithm key Derivation function defined in TS 33.501 Annex A.9
func (n *NAS) DerivateAlgKey() {
	// Security Key
	P0 := []byte{security.NNASEncAlg}
	L0 := UeauCommon.KDFLen(P0)
	P1 := []byte{n.CipheringAlg}
	L1 := UeauCommon.KDFLen(P1)

	kenc := UeauCommon.GetKDFValue(n.Kamf, UeauCommon.FC_FOR_ALGORITHM_KEY_DERIVATION, P0, L0, P1, L1)
	copy(n.KnasEnc[:], kenc[16:32])

	// Integrity Key
	P0 = []byte{security.NNASIntAlg}
	L0 = UeauCommon.KDFLen(P0)
	P1 = []byte{n.IntegrityAlg}
	L1 = UeauCommon.KDFLen(P1)

	kint := UeauCommon.GetKDFValue(n.Kamf, UeauCommon.FC_FOR_ALGORITHM_KEY_DERIVATION, P0, L0, P1, L1)
	copy(n.KnasInt[:], kint[16:32])
}

// Access Network key Derivation function defined in TS 33.501 Annex A.9
func (n *NAS) DerivateAnKey(accessType uint8) {
	P0 := make([]byte, 4)
	binary.BigEndian.PutUint32(P0, n.ULCount.Get())
	L0 := UeauCommon.KDFLen(P0)
	P1 := []byte{accessType}
	L1 := UeauCommon.KDFLen(P1)

	n.Kn3iwf = UeauCommon.GetKDFValue(n.Kamf, UeauCommon.FC_FOR_KGNB_KN3IWF_DERIVATION, P0, L0, P1, L1)
}
