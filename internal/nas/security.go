package nas

import (
	"fmt"
	"reflect"

	"github.com/free5gc/nas"
	"github.com/free5gc/nas/security"
)

func (s *Session) NASEncode(msg *nas.Message, securityContextAvailable bool, newSecurityContext bool) ([]byte, error) {
	if s.c == nil {
		return nil, fmt.Errorf("NAS context is nil")
	}
	if msg == nil {
		return nil, fmt.Errorf("Nas Message is empty")
	}
	if !securityContextAvailable {
		return msg.PlainNasEncode()
	} else {
		if newSecurityContext {
			s.c.ULCount.Set(0, 0)
			s.c.DLCount.Set(0, 0)
		}

		sequenceNumber := s.c.ULCount.SQN()
		payload, err := msg.PlainNasEncode()
		if err != nil {
			return nil, err
		}

		// TODO: Support for ue has nas connection in both accessType
		s.log.Debugf("Encrypt NAS message (algorithm: %+v, ULCount: 0x%0x)", s.c.CipheringAlg, s.c.ULCount.Get())
		s.log.Debugf("NAS ciphering key: %0x", s.c.KnasEnc)
		if err = security.NASEncrypt(s.c.CipheringAlg, s.c.KnasEnc, s.c.ULCount.Get(), security.Bearer3GPP,
			security.DirectionUplink, payload); err != nil {
			return nil, err
		}
		// add sequece number
		payload = append([]byte{sequenceNumber}, payload[:]...)

		mac32, err := security.NASMacCalculate(s.c.IntegrityAlg, s.c.KnasInt, s.c.ULCount.Get(), security.Bearer3GPP, security.DirectionUplink, payload)
		if err != nil {
			return nil, err
		}

		// Add mac value
		payload = append(mac32, payload[:]...)
		// Add EPD and Security Type
		msgSecurityHeader := []byte{msg.SecurityHeader.ProtocolDiscriminator, msg.SecurityHeader.SecurityHeaderType}
		payload = append(msgSecurityHeader, payload[:]...)

		// Increase UL Count
		s.c.ULCount.AddOne()
		return payload, nil
	}
}

func (s *Session) NASDecode(securityHeaderType uint8, payload []byte) (msg *nas.Message, err error) {
	if s.c == nil {
		err = fmt.Errorf("NAS context is nil")
		return
	}
	if payload == nil {
		err = fmt.Errorf("Nas payload is empty")
		return
	}

	msg = new(nas.Message)

	if securityHeaderType == nas.SecurityHeaderTypePlainNas {
		err = msg.PlainNasDecode(&payload)
		return
	} else if s.c.IntegrityAlg == security.AlgIntegrity128NIA0 {
		// remove header
		payload = payload[3:]

		if err = security.NASEncrypt(s.c.CipheringAlg, s.c.KnasEnc, s.c.DLCount.Get(), security.Bearer3GPP,
			security.DirectionDownlink, payload); err != nil {
			return nil, err
		}

		err = msg.PlainNasDecode(&payload)
		return
	} else {
		// security mode command
		if securityHeaderType == nas.SecurityHeaderTypeIntegrityProtectedWithNew5gNasSecurityContext {
			s.c.DLCount.Set(0, 0)

			plainNas := payload[7:]
			if err := msg.PlainNasDecode(&plainNas); err != nil {
				return nil, err
			}
			if command := msg.GmmMessage.SecurityModeCommand; command != nil {
				s.c.CipheringAlg = command.SelectedNASSecurityAlgorithms.GetTypeOfCipheringAlgorithm()
				s.c.IntegrityAlg = command.SelectedNASSecurityAlgorithms.GetTypeOfIntegrityProtectionAlgorithm()
				s.c.DerivateAlgKey()
			} else {
				return nil, fmt.Errorf("Integrity Protected With New 5G Nas Security is not Security command")
			}
		}

		securityHeader := payload[0:6]
		sequenceNumber := payload[6]
		receivedMac32 := securityHeader[2:]
		// remove security Header except for sequece Number
		payload = payload[6:]

		// Caculate dl count
		if s.c.DLCount.SQN() > sequenceNumber {
			s.c.DLCount.SetOverflow(s.c.DLCount.Overflow() + 1)
		}
		s.c.DLCount.SetSQN(sequenceNumber)

		s.log.Debugf("Calculate NAS MAC (algorithm: %+v, DLCount: 0x%0x)", s.c.IntegrityAlg, s.c.DLCount.Get())
		s.log.Debugf("NAS integrity key: %0x", s.c.KnasInt)
		mac32, err := security.NASMacCalculate(s.c.IntegrityAlg, s.c.KnasInt, s.c.DLCount.Get(), security.Bearer3GPP,
			security.DirectionDownlink, payload)
		if err != nil {
			return nil, err
		}
		if !reflect.DeepEqual(mac32, receivedMac32) {
			s.log.Warnf("NAS MAC verification failed(0x%x != 0x%x)", mac32, receivedMac32)
		} else {
			s.log.Debugf("cmac value: 0x%x\n", mac32)
		}

		// remove sequece Number
		payload = payload[1:]

		// TODO: Support for ue has nas connection in both accessType
		if securityHeaderType != nas.SecurityHeaderTypeIntegrityProtectedWithNew5gNasSecurityContext &&
			securityHeaderType != nas.SecurityHeaderTypeIntegrityProtected {
			s.log.Debugf("Decrypt NAS message (algorithm: %+v, DLCount: 0x%0x)", s.c.CipheringAlg, s.c.DLCount.Get())
			s.log.Debugf("NAS ciphering key: %0x", s.c.KnasEnc)
			if err = security.NASEncrypt(s.c.CipheringAlg, s.c.KnasEnc, s.c.DLCount.Get(), security.Bearer3GPP,
				security.DirectionDownlink, payload); err != nil {
				return nil, err
			}
		}
	}
	err = msg.PlainNasDecode(&payload)
	return
}
