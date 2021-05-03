package ike

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/binary"
	"fmt"
	"math/big"
	"math/rand"
	"n3ue/internal/n3ue_exclusive"
	"n3ue/internal/task_manager"
	"net"

	"bitbucket.org/_syujy/ike/dh"
	"bitbucket.org/_syujy/ike/encr"
	"bitbucket.org/_syujy/ike/integ"
	"bitbucket.org/_syujy/ike/message"
	"bitbucket.org/_syujy/ike/prf"
	"bitbucket.org/_syujy/ike/security"
	"bitbucket.org/_syujy/ike/types"
	"github.com/sirupsen/logrus"
)

type Session struct {
	n3ue_exclusive.N3UECommon
	// log
	log *logrus.Entry
	// security association
	ikesa *security.IKESA
	//childsa []*security.ChildSA
	// services
	ikeService *IKEService
	// channels
	ikeResReadChan chan *packet
	ikeReqReadChan chan *packet
	// connection
	packetTemplate packet
}

func (s *Session) Init(c n3ue_exclusive.N3UECommon, ikeService *IKEService) {
	// set n3ue common
	s.N3UECommon = c
	// init logger
	s.log = s.Log.WithFields(logrus.Fields{"component": "N3UE", "category": "SA"})
	// IKE service
	s.ikeService = ikeService
	// channels
	s.ikeResReadChan = make(chan *packet, 100)
	s.ikeReqReadChan = make(chan *packet, 100)
}

func (s *Session) IKE_SA_INIT(t *task) int {
	// IKESA
	if s.ikesa != nil {
		s.log.Errorln("IKESA not nil.")
		return task_manager.Failed
	}

	s.ikesa = new(security.IKESA)
	for {
		spi := rand.Uint64()
		if _, loaded := s.Ctx.SPI_IKESA.LoadOrStore(spi, s.ikesa); !loaded {
			s.ikesa.LocalSPI = spi
			break
		}
	}

	// connection
	if addr, err := net.ResolveUDPAddr("udp", fmt.Sprintf("%s:%d",
		s.Ctx.N3IWFAddress.IP, s.Ctx.N3IWFAddress.Port)); err != nil {
		s.log.Errorf("Cannot set IKE connection: %+v", err)
		return task_manager.Failed
	} else {
		s.packetTemplate.LocalPort = 500
		s.packetTemplate.RemoteAddr = addr
	}
	// register read channel
	s.ikeService.packetDispatcher.registerSAInputChan(s.ikesa.LocalSPI, s.ikeResReadChan)

	// build IKE message
	reqIKEMsg := new(message.IKEMessage)
	reqIKEMsg.BuildIKEHeader(s.ikesa.LocalSPI, 0, types.IKE_SA_INIT, types.InitiatorBitCheck, 0)

	// SAi
	sai := reqIKEMsg.Payloads.BuildSecurityAssociation()
	proposal1 := sai.Proposals.BuildProposal(1, types.TypeIKE, nil)

	// DH
	proposal1.DiffieHellmanGroup = append(proposal1.DiffieHellmanGroup,
		dh.StrToTransform(dh.String_DH_1024_BIT_MODP))
	proposal1.DiffieHellmanGroup = append(proposal1.DiffieHellmanGroup,
		dh.StrToTransform(dh.String_DH_2048_BIT_MODP))
	// ENCR
	proposal1.EncryptionAlgorithm = append(proposal1.EncryptionAlgorithm,
		encr.StrToTransform(encr.String_ENCR_AES_CBC_128))
	proposal1.EncryptionAlgorithm = append(proposal1.EncryptionAlgorithm,
		encr.StrToTransform(encr.String_ENCR_AES_CBC_192))
	proposal1.EncryptionAlgorithm = append(proposal1.EncryptionAlgorithm,
		encr.StrToTransform(encr.String_ENCR_AES_CBC_256))
	// INTEG
	proposal1.IntegrityAlgorithm = append(proposal1.IntegrityAlgorithm,
		integ.StrToTransform(integ.String_AUTH_HMAC_MD5_96))
	proposal1.IntegrityAlgorithm = append(proposal1.IntegrityAlgorithm,
		integ.StrToTransform(integ.String_AUTH_HMAC_SHA1_96))
	// PRF
	proposal1.PseudorandomFunction = append(proposal1.PseudorandomFunction,
		prf.StrToTransform(prf.String_PRF_HMAC_MD5))
	proposal1.PseudorandomFunction = append(proposal1.PseudorandomFunction,
		prf.StrToTransform(prf.String_PRF_HMAC_SHA1))

	// KE - 2048 bits MODP
	dhType := dh.StrToType(dh.String_DH_2048_BIT_MODP)
	var dhSecret *big.Int
	if bign, err := security.GenerateRandomNumber(); err != nil {
		s.log.Errorf("Build KE payload failed: GenerateRandomNumber() failed: %+v", err)
		return task_manager.Failed
	} else {
		reqIKEMsg.Payloads.BUildKeyExchange(types.DH_2048_BIT_MODP,
			dhType.GetPublicValue(bign))
		dhSecret = bign
	}

	// Ni
	var ni *big.Int
	if bign, err := security.GenerateRandomNumber(); err != nil {
		s.log.Errorf("Build Ni payload failed: GenerateRandomNumber() failed: %+v", err)
		return task_manager.Failed
	} else {
		reqIKEMsg.Payloads.BuildNonce(bign.Bytes())
		ni = bign
	}

	// Build NAT-T Notify payloads
	// Calculate NAT_DETECTION_SOURCE_IP hash
	// : sha1(ispi | rspi | sourceip | sourceport)
	sha1Hash := sha1.New()

	localDetectionData := make([]byte, 22)
	binary.BigEndian.PutUint64(localDetectionData[0:8], s.ikesa.LocalSPI)
	binary.BigEndian.PutUint64(localDetectionData[8:16], s.ikesa.RemoteSPI)
	ip := net.ParseIP(s.Ctx.IKEBindAddress)
	copy(localDetectionData[16:20], ip.To4())
	binary.BigEndian.PutUint16(localDetectionData[20:22], 500)
	if _, err := sha1Hash.Write(localDetectionData); err != nil {
		s.log.Errorf("Hash function write error: %+v", err)
		return task_manager.Failed
	}

	// N(NAT_DETECTION_SOURCE_IP)
	natDetectionSourceIP := sha1Hash.Sum(nil)
	reqIKEMsg.Payloads.BuildNotification(types.TypeNone, types.NAT_DETECTION_SOURCE_IP, nil, natDetectionSourceIP)

	// Calculate local NAT_DETECTION_DESTINATION_IP hash
	// : sha1(ispi | rspi | destip | destport)
	sha1Hash.Reset()

	localDetectionData = make([]byte, 22)
	binary.BigEndian.PutUint64(localDetectionData[0:8], s.ikesa.LocalSPI)
	binary.BigEndian.PutUint64(localDetectionData[8:16], s.ikesa.RemoteSPI)
	ip = net.ParseIP(s.Ctx.N3IWFAddress.IP)
	copy(localDetectionData[16:20], ip.To4())
	binary.BigEndian.PutUint16(localDetectionData[20:22], s.Ctx.N3IWFAddress.Port)
	if _, err := sha1Hash.Write(localDetectionData); err != nil {
		s.log.Errorf("Hash function write error: %+v", err)
		return task_manager.Failed
	}

	// N(NAT_DETECTION_DESTINATION_IP)
	natDetectionDestinationIP := sha1Hash.Sum(nil)
	reqIKEMsg.Payloads.BuildNotification(types.TypeNone, types.NAT_DETECTION_DESTINATION_IP, nil, natDetectionDestinationIP)

sendIKE_SA_INIT:
	// Encode and send
	var p *packet
	if data, err := reqIKEMsg.Encode(); err != nil {
		s.log.Errorf("IKE message encode failed: %+v", err)
		return task_manager.Failed
	} else {
		p = new(packet)
		*p = s.packetTemplate
		p.Payload = data
	}
	s.ikeService.packetDispatcher.send(p)

	// Response
	p = <-s.ikeResReadChan

	// Decode
	resIKEMsg := new(message.IKEMessage)
	if err := resIKEMsg.Decode(p.Payload); err != nil {
		s.log.Errorf("IKE_SA_INIT response decode failed: %+v", err)
		return task_manager.Failed
	}

	s.ikesa.RemoteSPI = resIKEMsg.ResponderSPI

	// get payloads
	var resSA *message.SecurityAssociation
	var resKE *message.KeyExchange
	var resNr *message.Nonce
	var notify []*message.Notification

	for _, p := range resIKEMsg.Payloads {
		switch p.Type() {
		case types.TypeSA:
			resSA = p.(*message.SecurityAssociation)
		case types.TypeKE:
			resKE = p.(*message.KeyExchange)
		case types.TypeNiNr:
			resNr = p.(*message.Nonce)
		case types.TypeN:
			notify = append(notify, p.(*message.Notification))
		default:
			s.log.Warnf("Receive %d type IKE payload when process IKE_SA_INIT response. Skip.", p.Type())
		}
	}

	// check if INVALID_KE_PAYLOAD
	for _, n := range notify {
		if n.NotifyMessageType == types.INVALID_KE_PAYLOAD {
			s.log.Trace("Receive INVALID_KE_PAYLOAD from responder")
			requestGroup := binary.BigEndian.Uint16(n.NotificationData)
			dhType = dh.GetType(requestGroup)
			if dhType == nil {
				s.log.Errorln("INVALID_KE_PAYLOAD contains unsupported Diffie-Hellman group")
				return task_manager.Failed
			}
			for _, p := range reqIKEMsg.Payloads {
				if p.Type() == types.TypeKE {
					kep := p.(*message.KeyExchange)
					kep.DiffieHellmanGroup = requestGroup
					kep.KeyExchangeData = dhType.GetPublicValue(dhSecret)
					break
				}
			}
			goto sendIKE_SA_INIT
		}
	}

	// handle SA
	if resSA != nil {
		if len(resSA.Proposals) == 1 {
			if !s.ikesa.SetProposal(resSA.Proposals[0]) {
				s.log.Error("Set proposal failed")
				return task_manager.Failed
			}
		}
	} else {
		s.log.Error("Responder doesn't send SA")
		return task_manager.Failed
	}

	// handle KE
	var dhSharedKey []byte
	if resKE != nil {
		if resKE.DiffieHellmanGroup == dhType.TransformID() {
			dhSharedKey = dhType.GetSharedKey(dhSecret, new(big.Int).SetBytes(resKE.KeyExchangeData))
		} else {
			s.log.Error("Response Diffie-Hellman group mismatched")
			return task_manager.Failed
		}
	} else {
		s.log.Error("Responder doesn't send KE")
		return task_manager.Failed
	}

	// handle Nonce
	var ninr []byte
	if resNr != nil {
		ninr = append(ni.Bytes(), resNr.NonceData...)
	} else {
		s.log.Error("Responder doesn't send Nr")
		return task_manager.Failed
	}

	for _, n := range notify {
		if n.NotifyMessageType == types.NAT_DETECTION_SOURCE_IP {
			if !hmac.Equal(natDetectionDestinationIP, n.NotificationData) {
				s.ikesa.NATT = true
				s.packetTemplate.LocalPort = 4500
			}
		}
		if n.NotifyMessageType == types.NAT_DETECTION_DESTINATION_IP {
			if !hmac.Equal(natDetectionSourceIP, n.NotificationData) {
				s.ikesa.NATT = true
				s.packetTemplate.LocalPort = 4500
			}
		}
	}

	// generate key for IKESA
	if err := s.ikesa.GenerateKey(ninr, dhSharedKey); err != nil {
		s.log.Errorf("Generate key for IKESA failed: %+v", err)
		return task_manager.Failed
	}

	// deregister read channel
	s.ikeService.packetDispatcher.deregisterSAInputChan(s.ikesa.LocalSPI)

	return task_manager.Success
}
