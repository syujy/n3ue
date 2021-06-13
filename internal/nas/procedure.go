package nas

import (
	"context"
	"n3ue/internal/eap5g"
	"n3ue/internal/sessInterface"
	"n3ue/internal/task_manager"
	"net"
	"time"

	"bitbucket.org/free5gc-team/nas/nasMessage"
	"bitbucket.org/free5gc-team/openapi/models"
)

func (s *Session) RegistrationRequest(t *task) int {
	// Provide data for IKE task
	paramREG := new(sessInterface.Param_REG)
	// AN Parameters
	// GUAMI
	guami := &eap5g.GUAMI{
		PLMNID: "20893",
		AMFID:  "cafe00",
	}
	if guamiByte, err := guami.Decode(); err != nil {
		s.log.Errorf("Build AN parameter GUAMI decode failed: %+v", err)
		return task_manager.Failed
	} else {
		param := make([]byte, 2+len(guamiByte))
		param[0] = byte(eap5g.TypeGUAMI)
		param[1] = byte(len(guamiByte))
		copy(param[2:], guamiByte)
		paramREG.ANParameter = append(paramREG.ANParameter, param...)
	}
	// PLMNID
	plmnid := eap5g.PLMNID(s.Ctx.PlmnID)
	if plmnidByte, err := plmnid.Decode(); err != nil {
		s.log.Errorf("Build AN parameter PLMNID decode failed: %+v", err)
		return task_manager.Failed
	} else {
		param := make([]byte, 2+len(plmnidByte))
		param[0] = byte(eap5g.TypePLMNID)
		param[1] = byte(len(plmnidByte))
		copy(param[2:], plmnidByte)
		paramREG.ANParameter = append(paramREG.ANParameter, param...)
	}
	// NSSAI
	if s.Ctx.Nssai != nil && len(s.Ctx.Nssai.DefaultSNSSAIs) != 0 {
		nssai := &eap5g.NSSAI{
			&eap5g.SNSSAI{
				SST: s.Ctx.Nssai.DefaultSNSSAIs[0].SST,
				SD:  s.Ctx.Nssai.DefaultSNSSAIs[0].SD,
			},
		}
		if nssaiByte, err := nssai.Decode(); err != nil {
			s.log.Errorf("Build AN parameter NSSAI decode failed: %+v", err)
			return task_manager.Failed
		} else {
			param := make([]byte, 2+len(nssaiByte))
			param[0] = byte(eap5g.TypeNSSAI)
			param[1] = byte(len(nssaiByte))
			copy(param[2:], nssaiByte)
			paramREG.ANParameter = append(paramREG.ANParameter, param...)
		}
	}
	// Establishment Cause
	paramREG.ANParameter = append(paramREG.ANParameter, []byte{byte(eap5g.TypeEstabCause), 1, eap5g.Mo_Data}...)

	// NASPDU channels
	paramREG.NASPDUtoIKE = s.writeChan
	paramREG.NASPDUtoNAS = s.readChan

	// Send to IKE task
	s.ikeSessIntWrite <- &sessInterface.SessInt{
		Comm:  sessInterface.CommType(sessInterface.REG),
		Value: paramREG,
	}

	// Set follow on request
	s.c.FollowOnRequest = true

	// Send NASPDU (Registration Request)
	if naspdu, err := s.GetRegistrationRequestWith5GMM(nasMessage.RegistrationType5GSInitialRegistration, nil, nil); err != nil {
		s.log.Errorf("Build registration request with 5GMM failed: %+v", err)
		return task_manager.Failed
	} else {
		s.writeChan <- naspdu
	}

	// Recv NASPDU (Authentication Request)
	s.handleGmmMessage(<-s.readChan)

	// Recv NASPDU (NAS Security Mode Command)
	s.handleGmmMessage(<-s.readChan)

	// Provide data for IKE task
	paramREG = new(sessInterface.Param_REG)
	// Kn3iwf
	paramREG.Kn3iwf = append(paramREG.Kn3iwf, s.c.Kn3iwf...)

	// Send to IKE task
	s.ikeSessIntWrite <- &sessInterface.SessInt{
		Comm:  sessInterface.CommType(sessInterface.REG),
		Value: paramREG,
	}

	// Recv NAS TCP address
	if info := <-s.ikeSessIntRead; info.Comm != sessInterface.REG {
		s.log.Error("Received communication type that is not REG")
		return task_manager.Failed
	} else {
		paramREG := info.Value.(*sessInterface.Param_REG)
		if tcpConn, err := net.DialTCP("tcp", nil, paramREG.Addr); err != nil {
			s.log.Errorf("DialTCP failed: %+v", err)
			return task_manager.Failed
		} else {
			nasTCPService := new(NASTCPService)
			nasTCPService.Init(s.N3UECommon, tcpConn, s.readChan, s.writeChan)
			nasTCPService.Run()
			s.nasTCPService = nasTCPService
		}
	}

	// Create task for handle input naspdu from TCP
	newTask := NewTask()
	newTask.ctx, s.cancel = context.WithCancel(context.Background())
	newTask.PushFunc(s.handle)
	s.TM.NewTask(newTask)

	for {
		if s.c.RmState.Is(RmStateRegistered) {
			break
		}
	}

	time.Sleep(2 * time.Second)

	return task_manager.Success
}

func (s *Session) PDUSessionEstablishmentRequest(t *task) int {
	s.log.Info("PDU session establishment request")
	pduSessionId := uint8(1)
	dnn := "internet" // default
	snssai := &models.Snssai{
		Sst: int32(s.Ctx.Nssai.DefaultSNSSAIs[0].SST),
		Sd:  s.Ctx.Nssai.DefaultSNSSAIs[0].SD,
	}
	// Send Pdu Session Estblishment
	if gsmPdu, err := s.GetPduSessionEstablishmentRequest(pduSessionId, nasMessage.PDUSessionTypeIPv4); err != nil {
		s.log.Error(err)
		return task_manager.Failed
	} else {
		if naspdu, err := s.GetUlNasTransport_PduSessionEstablishmentRequest(pduSessionId,
			nasMessage.ULNASTransportRequestTypeInitialRequest, dnn, snssai, gsmPdu); err != nil {
			s.log.Error(err)
			return task_manager.Failed
		} else {
			s.writeChan <- naspdu
		}
	}

	// Add PDU session
	sess := s.c.AddPduSession(pduSessionId, dnn, *snssai)
	// Lock session for modification
	sess.Mtx.Lock()

	// Recv gretun info
	if info := <-s.ikeSessIntRead; info.Comm != sessInterface.PDUSessEstab {
		s.log.Error("Received communication type that is not PDUSessEstab")
		return task_manager.Failed
	} else {
		paramPDUSessEstab := info.Value.(*sessInterface.Param_PDUSessEstab)
		sess.Link = paramPDUSessEstab.Link
	}

	// Send ACK to IKE
	s.ikeSessIntWrite <- &sessInterface.SessInt{
		Comm: sessInterface.PDUSessEstab,
	}

	// Unlock session
	sess.Mtx.Unlock()

	return task_manager.Success
}
