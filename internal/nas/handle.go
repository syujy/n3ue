package nas

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"github.com/syujy/n3ue/internal/task_manager"
	"net"

	"github.com/free5gc/milenage"
	"github.com/free5gc/nas"
	"github.com/free5gc/nas/nasConvert"
	"github.com/free5gc/nas/nasMessage"
	"github.com/free5gc/nas/security"
	"github.com/vishvananda/netlink"
)

func (s *Session) handle(t *task) int {
	for {
		select {
		case <-t.ctx.Done():
			return task_manager.Success
		case naspdu := <-s.readChan:
			s.handleGmmMessage(naspdu)
		}
	}
}

func (s *Session) handleGmmMessage(nasPdu []byte) {
	// GMM Message
	msg, err := s.NASDecode(nas.GetSecurityHeaderType(nasPdu)&0x0f, nasPdu)
	if err != nil {
		s.log.Error(err.Error())
		return
	}

	switch msg.GmmMessage.GetMessageType() {
	case nas.MsgTypeAuthenticationRequest:
		s.checkMsgError(s.handleAuthenticationRequest(msg.GmmMessage.AuthenticationRequest), "AuthenticationRequest")
	case nas.MsgTypeAuthenticationReject:
		s.checkMsgError(s.handleAuthenticationReject(msg.GmmMessage.AuthenticationReject), "AuthenticationReject")
	case nas.MsgTypeRegistrationReject:
		s.checkMsgError(s.handleRegistrationReject(msg.GmmMessage.RegistrationReject), "RegistrationReject")
	case nas.MsgTypeSecurityModeCommand:
		s.checkMsgError(s.handleSecurityModeCommand(msg.GmmMessage.SecurityModeCommand), "SecurityModeCommand")
	case nas.MsgTypeServiceAccept:
		s.checkMsgError(s.handleServiceAccept(msg.GmmMessage.ServiceAccept), "ServiceAccept")
	case nas.MsgTypeServiceReject:
		s.checkMsgError(s.handleServiceReject(msg.GmmMessage.ServiceReject), "ServiceReject")
	case nas.MsgTypeRegistrationAccept:
		s.checkMsgError(s.handleRegistrationAccept(msg.GmmMessage.RegistrationAccept), "RegistrationAccept")
	case nas.MsgTypeDeregistrationAcceptUEOriginatingDeregistration:
		s.checkMsgError(s.handleDeregistrationAccept(msg.GmmMessage.DeregistrationAcceptUEOriginatingDeregistration), "DeregistraionAccept")
	case nas.MsgTypeDLNASTransport:
		s.checkMsgError(s.handleDLNASTransport(msg.GmmMessage.DLNASTransport), "DLNASTransport")
	default:
		s.log.Errorf("Unknown GmmMessage[%d]\n", msg.GmmMessage.GetMessageType())
	}
}

func (s *Session) handleGsmMessage(nasPdu []byte) {
	msg := new(nas.Message)
	err := msg.PlainNasDecode(&nasPdu)
	if err != nil {
		s.log.Error(err.Error())
		return
	}
	switch msg.GsmMessage.GetMessageType() {
	case nas.MsgTypePDUSessionEstablishmentAccept:
		s.checkMsgError(s.handlePduSessionEstblishmentAccept(msg.GsmMessage.PDUSessionEstablishmentAccept), "PduSessionEstblishmentAccept")
	case nas.MsgTypePDUSessionReleaseCommand:
		s.checkMsgError(s.handlePduSessionReleaseCommand(msg.GsmMessage.PDUSessionReleaseCommand), "PduSessionReleaseCommand")
	default:
		s.log.Errorf("Unknown GsmMessage[%d]\n", msg.GsmMessage.GetMessageType())
	}
}

func (s *Session) handleAuthenticationRequest(request *nasMessage.AuthenticationRequest) error {
	s.log.Info("Handle Authentication Request", "supi", s.c.Supi)

	s.c.NgKsi = request.GetNasKeySetIdentifiler()

	// Get RAND & AUTN from Authentication request
	RAND := request.GetRANDValue()
	AUTN := request.GetAUTN()
	SQNxorAK := AUTN[0:6]
	AMF := AUTN[6:8]
	MAC := AUTN[8:]

	authData := s.Ctx.Auth
	servingNetworkName := s.c.GetServingNetworkName()
	SQNms, _ := hex.DecodeString(authData.SQN)

	// Run milenage
	XMAC, MAC_S := make([]byte, 8), make([]byte, 8)
	CK, IK := make([]byte, 16), make([]byte, 16)
	RES := make([]byte, 8)
	SQN := make([]byte, 6)
	AK, AKstar := make([]byte, 6), make([]byte, 6)
	OPC, _ := hex.DecodeString(authData.OPC)
	K, _ := hex.DecodeString(authData.K)

	// Generate RES, CK, IK, AK
	if err := milenage.F2345(OPC, K, RAND[:], RES, CK, IK, AK, nil); err != nil {
		s.log.Error(err)
		return nil
	}

	// Derive SQN
	for i := 0; i < 6; i++ {
		SQN[i] = SQNxorAK[i] ^ AK[i]
	}

	// Generate XMAC
	if err := milenage.F1(OPC, K, RAND[:], SQN, AMF, XMAC, nil); err != nil {
		s.log.Error(err)
		return nil
	}

	// Verify MAC == XMAC
	if !bytes.Equal(MAC, XMAC) {
		s.log.Errorf("Authentication Failed: MAC (0x%0x) != XMAC (0x%0x)", MAC, XMAC)
		s.SendAuthenticationFailure(nasMessage.Cause5GMMMACFailure, nil)
		return nil
	}

	// Verify that SQN is in the current range TS 33.102
	// sqn is out of sync -> synchronisation failure -> trigger resync procedure
	if !bytes.Equal(SQN, SQNms) {
		s.log.Errorf("Authentication Synchronisation Failure: SQN (0x%0x) != SQNms (0x%0x)", SQN, SQNms)
		SQNmsXorAK := make([]byte, 6)

		// TS 33.102 6.3.3: The AMF used to calculate MAC S assumes a dummy value of all zeros so that it does not
		// need to be transmitted in the clear in the re-synch message.
		if err := milenage.F1(OPC, K, RAND[:], SQNms, []byte{0x00, 0x00}, nil, MAC_S); err != nil {
			s.log.Error(err)
			return nil
		}
		if err := milenage.F2345(OPC, K, RAND[:], nil, nil, nil, nil, AKstar); err != nil {
			s.log.Error(err)
			return nil
		}
		for i := 0; i < 6; i++ {
			SQNmsXorAK[i] = SQNms[i] ^ AKstar[i]
		}
		AUTS := append(SQNmsXorAK, MAC_S...)
		s.SendAuthenticationFailure(nasMessage.Cause5GMMSynchFailure, AUTS)
		return nil
	}

	// derive RES* and send response
	resStar := s.c.DeriveRESstar(CK, IK, servingNetworkName, RAND[:], RES)
	s.SendAuthenticationResponse(resStar)

	// generate keys
	kausf := DerivateKausf(CK, IK, servingNetworkName, SQNxorAK)
	s.log.Debugf("Kausf: 0x%0x", kausf)
	kseaf := DerivateKseaf(kausf, servingNetworkName)
	s.log.Debugf("Kseaf: 0x%0x", kseaf)
	s.c.DerivateKamf(kseaf, []byte{0x00, 0x00})
	s.c.DerivateAnKey(security.AccessTypeNon3GPP)
	s.Ctx.Auth.AuthDataSQNAddOne()
	return nil
}

func (s *Session) handleAuthenticationReject(message *nasMessage.AuthenticationReject) error {
	s.log.Error("Receive Authentication Reject", "supi", s.c.Supi)
	return nil
}

func (s *Session) handleRegistrationReject(message *nasMessage.RegistrationReject) error {
	s.log.Warn("Handle Registration Reject", "supi", s.c.Supi)
	if message.Cause5GMM.GetCauseValue() == nasMessage.Cause5GMMCongestion {
		s.log.Warn("Restart Initial Registration", "supi", s.c.Supi)
	}
	return nil
}

func (s *Session) handleSecurityModeCommand(request *nasMessage.SecurityModeCommand) error {

	s.log.Infof("UE[%s] Handle Security Mode Command", s.c.Supi)

	nasContent, err := s.GetRegistrationRequestWith5GMM(nasMessage.RegistrationType5GSInitialRegistration, nil, nil)
	if err != nil {
		return err
	}
	s.SendSecurityModeCommand(nasContent)
	return nil
}

func (s *Session) handleRegistrationAccept(request *nasMessage.RegistrationAccept) error {
	s.log.Infof("UE[%s] Handle Registration Accept", s.c.Supi)

	s.c.Guti = request.GUTI5G

	nasPdu, err := s.GetRegistrationComplete(nil)
	if err != nil {
		return err
	}
	s.log.Info("Send Registration Complete")
	s.writeChan <- nasPdu
	s.c.RmState.Set(RmStateRegistered)
	return nil
}

func (s *Session) handleServiceAccept(message *nasMessage.ServiceAccept) error {
	s.log.Info("Handle Service Accept", "supi", s.c.Supi)
	s.c.CmState.Set(CmStateConnected)
	return nil
}

func (s *Session) handleServiceReject(message *nasMessage.ServiceReject) error {
	s.log.Info("Handle Service Reject", "supi", s.c.Supi)
	return nil
}

func (s *Session) handleDeregistrationAccept(request *nasMessage.DeregistrationAcceptUEOriginatingDeregistration) error {

	s.log.Infof("UE[%s] Handle Deregistration Accept", s.c.Supi)

	s.c.RmState.Set(RmStateDeregitered)
	return nil
}

func (s *Session) handleDLNASTransport(request *nasMessage.DLNASTransport) error {
	s.log.Infof("UE[%s] Handle DL NAS Transport", s.c.Supi)

	switch request.GetPayloadContainerType() {
	case nasMessage.PayloadContainerTypeN1SMInfo:
		s.handleGsmMessage(request.GetPayloadContainerContents())
	case nasMessage.PayloadContainerTypeSMS:
		return fmt.Errorf("PayloadContainerTypeSMS has not been implemented yet in DL NAS TRANSPORT")
	case nasMessage.PayloadContainerTypeLPP:
		return fmt.Errorf("PayloadContainerTypeLPP has not been implemented yet in DL NAS TRANSPORT")
	case nasMessage.PayloadContainerTypeSOR:
		return fmt.Errorf("PayloadContainerTypeSOR has not been implemented yet in DL NAS TRANSPORT")
	case nasMessage.PayloadContainerTypeUEPolicy:
		return fmt.Errorf("PayloadContainerTypeUEPolicy has not been implemented yet in DL NAS TRANSPORT")
	case nasMessage.PayloadContainerTypeUEParameterUpdate:
		return fmt.Errorf("PayloadContainerTypeUEParameterUpdate has not been implemented yet in DL NAS TRANSPORT")
	case nasMessage.PayloadContainerTypeMultiplePayload:
		return fmt.Errorf("PayloadContainerTypeMultiplePayload has not been implemented yet in DL NAS TRANSPORT")
	}
	return nil
}

func (s *Session) handlePduSessionEstblishmentAccept(request *nasMessage.PDUSessionEstablishmentAccept) error {

	s.log.Infof("UE[%s] Handle PDU Session Establishment Accept", s.c.Supi)

	pduSessionId := int64(request.GetPDUSessionID())
	sess, exist := s.c.PduSession[pduSessionId]
	if !exist {
		return fmt.Errorf("pduSessionId[%d] is not exist in UE", pduSessionId)
	}
	sess.Mtx.Lock()
	if request.DNN != nil {
		sess.Dnn = string(request.GetDNN())
	}
	if request.SNSSAI != nil {
		sess.Snssai = nasConvert.SnssaiToModels(request.SNSSAI)
	}
	if request.PDUAddress != nil {
		ipBytes := request.PDUAddress.GetPDUAddressInformation()
		switch request.PDUAddress.GetPDUSessionTypeValue() {
		case nasMessage.PDUSessionTypeIPv4:
			sess.Addr = new(netlink.Addr)
			sess.Addr.IPNet = new(net.IPNet)
			sess.Addr.IP = net.IP(ipBytes[:4])
			sess.Addr.Mask = []byte{255, 255, 255, 255}
			if err := netlink.AddrAdd(sess.Link, sess.Addr); err != nil {
				return fmt.Errorf("Create ue addr failed[%s]", err.Error())
			}
		case nasMessage.PDUSessionTypeIPv6, nasMessage.PDUSessionTypeIPv4IPv6:
			return fmt.Errorf("Ipv6 is not support yet")
		}
	}
	sess.Mtx.Unlock()
	return nil
}

func (s *Session) handlePduSessionReleaseCommand(request *nasMessage.PDUSessionReleaseCommand) error {

	s.log.Infof("UE[%s] Handle PDU Session Release Command", s.c.Supi)

	pduSessionId := request.GetPDUSessionID()
	if err := s.c.DelPduSession(int64(pduSessionId)); err != nil {
		return fmt.Errorf("Delete PDU session failed: %+v", err)
	}
	// Send Pdu Session Release Complete to SMF
	nasPdu, err := s.GetUlNasTransport_PduSessionCommonData(pduSessionId, PDUSesRelCmp)
	if err != nil {
		return err
	}
	s.log.Info("Send PDU Session Release Complete")
	s.writeChan <- nasPdu
	return nil
}

func (s *Session) SendAuthenticationResponse(resStar []byte) {
	s.log.Info("Send Authentication Response", "supi", s.c.Supi)
	nasPdu := s.BuildAuthenticationResponse(resStar, "")
	s.writeChan <- nasPdu
}

func (s *Session) SendAuthenticationFailure(cause uint8, authFailParams []byte) {
	s.log.Info("Send Authentication Failure", "supi", s.c.Supi)
	nasPdu := s.BuildAuthenticationFailure(cause, authFailParams)
	s.writeChan <- nasPdu
}

func (s *Session) SendSecurityModeCommand(nasMsg []byte) {
	s.log.Info("Send Security Mode Complete", "supi", s.c.Supi)
	nasPdu, err := s.GetSecurityModeComplete(nasMsg)
	if err != nil {
		s.log.Errorf("Build Security Mode Complete error: %+v", err)
		return
	}
	s.writeChan <- nasPdu
}
