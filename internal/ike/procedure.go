package ike

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha1"
	"crypto/x509"
	"encoding/binary"
	"fmt"
	"math"
	"math/big"
	"math/bits"
	"math/rand"
	"github.com/syujy/n3ue/internal/sessInterface"
	"github.com/syujy/n3ue/internal/task_manager"
	"net"

	"github.com/syujy/ikev2/dh"
	"github.com/syujy/ikev2/encr"
	"github.com/syujy/ikev2/esn"
	"github.com/syujy/ikev2/integ"
	"github.com/syujy/ikev2/message"
	"github.com/syujy/ikev2/prf"
	"github.com/syujy/ikev2/security"
	"github.com/syujy/ikev2/types"
	"github.com/vishvananda/netlink"
)

func (s *Session) IKE_SA_INIT(t *task) int {
	// IKESA
	if s.ikesa != nil {
		s.log.Errorln("IKESA not nil")
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
	s.ikesa.Role = types.Role_Initiator

	// Connection
	if addr, err := net.ResolveUDPAddr("udp", fmt.Sprintf("%s:%d",
		s.Ctx.N3IWFAddress.IP, s.Ctx.N3IWFAddress.Port)); err != nil {
		s.log.Errorf("Cannot set IKE connection: %+v", err)
		return task_manager.Failed
	} else {
		s.packetTemplate.LocalPort = 500
		s.packetTemplate.RemoteAddr = addr
	}
	// Register read channel
	s.ikeService.packetDispatcher.registerReqReadChan(s.ikesa.LocalSPI, s.ikeReqReadChan)
	s.ikeService.packetDispatcher.registerResReadChan(s.ikesa.LocalSPI, s.ikeResReadChan)

	// Build IKE message
	reqIKEMsg := new(message.IKEMessage)
	reqIKEMsg.BuildIKEHeader(s.ikesa.LocalSPI, 0, types.IKE_SA_INIT, types.InitiatorBitCheck, s.ikesa.MessageID)

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
		reqIKEMsg.Payloads.BUildKeyExchange(types.DH_2048_BIT_MODP, dhType.GetPublicValue(bign))
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
	_, _ = sha1Hash.Write(localDetectionData) // hash.Hash.Write() never return an error

	// N(NAT_DETECTION_SOURCE_IP)
	reqIKEMsg.Payloads.BuildNotification(types.TypeNone, types.NAT_DETECTION_SOURCE_IP, nil, sha1Hash.Sum(nil))

	// Calculate local NAT_DETECTION_DESTINATION_IP hash
	// : sha1(ispi | rspi | destip | destport)
	sha1Hash.Reset()

	localDetectionData = make([]byte, 22)
	binary.BigEndian.PutUint64(localDetectionData[0:8], s.ikesa.LocalSPI)
	binary.BigEndian.PutUint64(localDetectionData[8:16], s.ikesa.RemoteSPI)
	ip = net.ParseIP(s.Ctx.N3IWFAddress.IP)
	copy(localDetectionData[16:20], ip.To4())
	binary.BigEndian.PutUint16(localDetectionData[20:22], s.Ctx.N3IWFAddress.Port)
	_, _ = sha1Hash.Write(localDetectionData) // hash.Hash.Write() never return an error

	// N(NAT_DETECTION_DESTINATION_IP)
	reqIKEMsg.Payloads.BuildNotification(types.TypeNone, types.NAT_DETECTION_DESTINATION_IP, nil, sha1Hash.Sum(nil))

encode:
	// Encode and send
	sendp := new(packet)
	if data, err := reqIKEMsg.Encode(); err != nil {
		s.log.Errorf("IKE message encode failed: %+v", err)
		return task_manager.Failed
	} else {
		*sendp = s.packetTemplate
		sendp.Payload = data
	}
	//send:
	s.ikeService.packetDispatcher.send(sendp)

recv:
	// Response
	// This part can be used with tag send: to implement retransmission
	recvp := <-s.ikeResReadChan

	// Decode
	resIKEMsg := new(message.IKEMessage)
	if err := resIKEMsg.Decode(recvp.Payload); err != nil {
		s.log.Errorf("IKE_SA_INIT response decode failed: %+v", err)
		return task_manager.Failed
	}

	// Check
	if !s.ikesa.CheckMessageID(resIKEMsg.MessageID) { // message ID not matched
		s.log.Warn("Received IKE message that its message ID not matched. Drop")
		goto recv
	}
	if resIKEMsg.Flags&types.ResponseBitCheck == 0 { // not response
		s.log.Warn("Received IKE message that is not a response message. Drop")
		goto recv
	}

	s.ikesa.RemoteSPI = resIKEMsg.ResponderSPI

	// Get payloads
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
			s.log.Warnf("Receive type %d IKE payload when process IKE_SA_INIT response. Skip", p.Type())
		}
	}

	// Check if INVALID_KE_PAYLOAD
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
			s.ikesa.MessageID = 0
			goto encode
		}
	}

	// Handle SA
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

	// Handle KE
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

	// Handle Nonce
	if resNr != nil {
		t.ninr = append(ni.Bytes(), resNr.NonceData...)
	} else {
		s.log.Error("Responder doesn't send Nr")
		return task_manager.Failed
	}

	for _, n := range notify {
		if n.NotifyMessageType == types.NAT_DETECTION_SOURCE_IP {
			sha1Hash.Reset()
			localDetectionData = make([]byte, 22)
			copy(localDetectionData, recvp.Payload[0:16])
			copy(localDetectionData[16:20], recvp.RemoteAddr.IP.To4())
			binary.BigEndian.PutUint16(localDetectionData[20:22], uint16(recvp.RemoteAddr.Port))
			_, _ = sha1Hash.Write(localDetectionData) // hash.Hash.Write() never return an error
			if !hmac.Equal(sha1Hash.Sum(nil), n.NotificationData) {
				s.ikesa.NATT = true
				s.packetTemplate.LocalPort = 4500
				s.packetTemplate.RemoteAddr.Port = 4500
			}
		}
		if n.NotifyMessageType == types.NAT_DETECTION_DESTINATION_IP {
			sha1Hash.Reset()
			localDetectionData := make([]byte, 22)
			copy(localDetectionData, recvp.Payload[0:16])
			ip := net.ParseIP(s.Ctx.IKEBindAddress)
			copy(localDetectionData[16:20], ip.To4())
			binary.BigEndian.PutUint16(localDetectionData[20:22], 500)
			_, _ = sha1Hash.Write(localDetectionData) // hash.Hash.Write() never return an error
			if !hmac.Equal(sha1Hash.Sum(nil), n.NotificationData) {
				s.ikesa.NATT = true
				s.packetTemplate.LocalPort = 4500
				s.packetTemplate.RemoteAddr.Port = 4500
				// Create task for sending keepalive
				newTask := NewTask()
				newTask.ctx, s.keepaliveCancel = context.WithCancel(context.Background())
				newTask.timerInterval = 25
				newTask.PushFunc(s.udpKeepAlive)
				s.TM.NewTask(newTask)
			}
		}
	}

	// Generate key for IKESA
	if err := s.ikesa.GenerateKey(t.ninr, dhSharedKey, recvp.Payload[0:16]); err != nil {
		s.log.Errorf("Generate key for IKESA failed: %+v", err)
		return task_manager.Failed
	}

	// Deregister read channel
	s.ikeService.packetDispatcher.deregisterResReadChan(s.ikesa.LocalSPI)

	// Store data for authtication
	t.initiatorSignedOctets = append(sendp.Payload, resNr.NonceData...)
	t.responderSignedOctets = append(recvp.Payload, ni.Bytes()...)

	return task_manager.Success
}

func (s *Session) IKE_AUTH(t *task) int {
	// ChildSA
	if len(s.childsa) != 0 {
		s.log.Errorln("Not the first child SA")
		return task_manager.Failed
	}

	childSA := new(security.ChildSA)
	childSA.Mark = s.Ctx.IPSecIf.Mark
	childSA.LocalPublicIPAddr = net.ParseIP(s.Ctx.IKEBindAddress)
	childSA.RemotePublicIPAddr = s.packetTemplate.RemoteAddr.IP
	if s.ikesa.NATT {
		childSA.EnableEncap = true
		childSA.LocalPort = int(s.packetTemplate.LocalPort)
		childSA.RemotePort = s.packetTemplate.RemoteAddr.Port
	}
	if err := childSA.GenerateXFRMState(s.ikesa.Role, true); err != nil {
		s.log.Errorf("Generate XFRM states failed: %+v", err)
		return task_manager.Failed
	}

	// Register read channel
	s.ikeService.packetDispatcher.registerResReadChan(s.ikesa.LocalSPI, s.ikeResReadChan)

	// Build reqPayloads
	var reqPayloads message.IKEPayloadContainer
	var fCKS bool // flag

	// IDi
	idi := &message.IdentificationInitiator{
		IDType: types.ID_FQDN,
		IDData: []byte("N3UE"),
	}
	reqPayloads = append(reqPayloads, idi)
	if data, err := idi.Marshal(); err != nil {
		s.log.Errorf("Marshal IDi for authentication failed: %+v", err)
	} else {
		s.ikesa.Prf_i.Reset()
		_, _ = s.ikesa.Prf_i.Write(data) // hash.Hash.Write() never return an error
		t.initiatorSignedOctets = append(t.initiatorSignedOctets, s.ikesa.Prf_i.Sum(nil)...)
	}

	// SAi
	sai := reqPayloads.BuildSecurityAssociation()
	childsaSPI := make([]byte, 4)
	binary.BigEndian.PutUint32(childsaSPI, childSA.SPI)
	proposal1 := sai.Proposals.BuildProposal(1, types.TypeESP, childsaSPI)

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
	// ESN
	proposal1.ExtendedSequenceNumbers = append(proposal1.ExtendedSequenceNumbers,
		esn.StrToTransform(esn.String_ESN_DISABLE))

	// Traffic Selector
	tsi := reqPayloads.BuildTrafficSelectorInitiator()
	tsi.TrafficSelectors.BuildIndividualTrafficSelector(types.TS_IPV4_ADDR_RANGE, 0, 0, 65535, []byte{0, 0, 0, 0}, []byte{255, 255, 255, 255})
	tsr := reqPayloads.BuildTrafficSelectorResponder()
	tsr.TrafficSelectors.BuildIndividualTrafficSelector(types.TS_IPV4_ADDR_RANGE, 0, 0, 65535, []byte{0, 0, 0, 0}, []byte{255, 255, 255, 255})

	// CP request
	cp := reqPayloads.BuildConfiguration(types.CFG_REQUEST)
	cp.ConfigurationAttribute.BuildConfigurationAttribute(types.INTERNAL_IP4_ADDRESS, nil)
	cp.ConfigurationAttribute.BuildConfigurationAttribute(types.INTERNAL_IP4_NETMASK, nil)

	// Build IKE message
	reqIKEMsg := new(message.IKEMessage)
	reqIKEMsg.BuildIKEHeader(s.ikesa.LocalSPI, s.ikesa.RemoteSPI, types.IKE_AUTH, types.InitiatorBitCheck, s.ikesa.MessageID)

	// SK
	if nextPyload, payloadData, err := reqPayloads.Encode(); err != nil {
		s.log.Errorf("Encode payload failed: %+v", err)
		return task_manager.Failed
	} else {
		if encryptedData, err := s.ikesa.EncryptToSKPayload(payloadData); err != nil {
			s.log.Errorf("Encrypt pyaload data failed: %+v", err)
			return task_manager.Failed
		} else {
			reqIKEMsg.Payloads.BuildEncrypted(types.IKEPayloadType(nextPyload), encryptedData)
			fCKS = true
		}
	}

	//encodePreSig:
	// Encode, add cks, and send
	sendp := new(packet)
	if data, err := reqIKEMsg.Encode(); err != nil {
		s.log.Errorf("IKE message encode failed: %+v", err)
		return task_manager.Failed
	} else {
		*sendp = s.packetTemplate
		sendp.Payload = data
	}

	// Checksum
	if fCKS {
		if err := s.ikesa.CalcIKEChecksum(sendp.Payload); err != nil {
			s.log.Errorf("Calculate checksum failed: %+v", err)
			return task_manager.Failed
		}
		// Reset CKS flag
		fCKS = false
	}

	//sendPreSig:
	s.ikeService.packetDispatcher.send(sendp)

recvPreSig:
	// Response
	// This part can be used with tag send: to implement retransmission
	recvp := <-s.ikeResReadChan

	// Decode
	resIKEMsg := new(message.IKEMessage)
	if err := resIKEMsg.Decode(recvp.Payload); err != nil {
		s.log.Errorf("IKE_AUTH response decode failed: %+v", err)
		return task_manager.Failed
	}

	// Check
	if !s.ikesa.CheckMessageID(resIKEMsg.MessageID) { // message ID not matched
		s.log.Warn("Received IKE message that its message ID not matched. Drop")
		goto recvPreSig
	}
	if resIKEMsg.Flags&types.ResponseBitCheck == 0 { // not response
		s.log.Warn("Received IKE message that is not a response message. Drop")
		goto recvPreSig
	}

	// Get payloads
	var sk *message.Encrypted
	var notify []*message.Notification

	for _, p := range resIKEMsg.Payloads {
		switch p.Type() {
		case types.TypeSK:
			sk = p.(*message.Encrypted)
			fCKS = true
		case types.TypeN:
			notify = append(notify, p.(*message.Notification))
		default:
			s.log.Warnf("Receive type %d IKE payload when process IKE_AUTH response. Skip", p.Type())
		}
	}

	// Check if NO_PROPOSAL_CHOSEN
	for _, n := range notify {
		if n.NotifyMessageType == types.NO_PROPOSAL_CHOSEN {
			s.log.Error("Receive NO_PROPOSAL_CHOSEN from responder")
			return task_manager.Failed
		}
	}

	// Checksum
	if fCKS {
		if !s.ikesa.VerifyIKEChecksum(recvp.Payload) {
			s.log.Error("Checksum failed")
			return task_manager.Failed
		}
		// Reset CKS flag
		fCKS = false
	}

	var resPayloads message.IKEPayloadContainer

	// Handle SK
	if sk != nil {
		if payloadData, err := s.ikesa.DecryptSKPayload(sk.EncryptedData); err != nil {
			s.log.Errorf("Decrypt IKE SK failed: %+v", err)
			return task_manager.Failed
		} else {
			if err := resPayloads.Decode(sk.NextPayload, payloadData); err != nil {
				s.log.Errorf("IKE_AUTH response encrypted raw data decode failed: %+v", err)
				return task_manager.Failed
			}
		}
	}

	// Get payloads
	notify = make([]*message.Notification, 0)
	var idr *message.IdentificationResponder
	var cert *message.Certificate
	var auth *message.Authentication
	var eap *message.EAP

	for _, p := range resPayloads {
		switch p.Type() {
		case types.TypeIDr:
			idr = p.(*message.IdentificationResponder)
		case types.TypeCERT:
			cert = p.(*message.Certificate)
		case types.TypeAUTH:
			auth = p.(*message.Authentication)
		case types.TypeEAP:
			eap = p.(*message.EAP)
		case types.TypeN:
			notify = append(notify, p.(*message.Notification))
		default:
			s.log.Warnf("Receive type %d IKE payload when process IKE_AUTH encrypted response. Skip", p.Type())
		}
	}

	// Handle IDr
	if idr != nil {
		// Store data for authentication
		data, _ := idr.Marshal() // No need to check error
		s.ikesa.Prf_r.Reset()
		_, _ = s.ikesa.Prf_r.Write(data) // hash.Hash.Write() never return an error
		t.responderSignedOctets = append(t.responderSignedOctets, s.ikesa.Prf_r.Sum(nil)...)
	} else {
		s.log.Error("Responder doesn't send IDr")
		return task_manager.Failed
	}

	// Handle CERT
	var x509Cert *x509.Certificate
	if cert != nil {
		switch cert.CertificateEncoding {
		case types.X509CertificateSignature:
			if c, err := x509.ParseCertificate(cert.CertificateData); err != nil {
				s.log.Errorf("Parse certificate failed: %+v", err)
				return task_manager.Failed
			} else {
				x509Cert = c
			}
		default:
			s.log.Errorf("Received certificate encoding that doesn't support: %d", cert.CertificateEncoding)
			return task_manager.Failed
		}
	} else {
		s.log.Error("Responder doesn't send CERT")
		return task_manager.Failed
	}

	// Handle AUTH
	if auth != nil {
		switch auth.AuthenticationMethod {
		case types.RSADigitalSignature:
			if err := x509Cert.CheckSignature(x509.SHA1WithRSA, t.responderSignedOctets, auth.AuthenticationData); err != nil {
				s.log.Errorf("Authentication failed: %+v", err)
				return task_manager.Failed
			}
		default:
			s.log.Errorf("Received authentication method that doesn't support: %d", auth.AuthenticationMethod)
			return task_manager.Failed
		}
	} else {
		s.log.Error("Responder doesn't send AUTH")
		return task_manager.Failed
	}

	// Handle EAP
	var kn3iwf []byte
	if eap != nil {
		// Check if EAP5G start
		if eap.Code != types.EAPCodeRequest {
			s.log.Error("Received first EAP payload that is not an EAP request")
			return task_manager.Failed
		}
		if len(eap.EAPTypeData) == 0 {
			s.log.Error("No EAP type payload found")
			return task_manager.Failed
		}
		if eap5g := eap.EAPTypeData[0].(*message.EAPExpanded); eap5g.VendorID != types.VendorID3GPP ||
			eap5g.VendorType != types.VendorTypeEAP5G {
			s.log.Errorf("Can only handle EAP5G. Received: Vendor: %d, Vendor Type: %d", eap5g.VendorID, eap5g.VendorType)
			return task_manager.Failed
		} else {
			if eap5g.VendorData[0] != types.EAP5GType5GStart {
				s.log.Error("Received EAP5G payload but it is not EAP5G start")
				return task_manager.Failed
			}
		}

		// EAP signalling
		var anParam []byte
		var nasReadChan, nasWriteChan chan []byte
		if info := <-s.nasSessIntRead; info.Comm != sessInterface.REG {
			s.log.Error("Received communication type that is not REG")
			return task_manager.Failed
		} else {
			paramREG := info.Value.(*sessInterface.Param_REG)
			anParam = paramREG.ANParameter
			nasReadChan = paramREG.NASPDUtoIKE
			nasWriteChan = paramREG.NASPDUtoNAS
		}

		for {
			// Build reqPayloads
			reqPayloads.Reset()
			reqPayloads.BuildEAP5GNASRes(eap.Identifier, anParam, <-nasReadChan)
			anParam = nil

			// Build IKE message
			reqIKEMsg = new(message.IKEMessage)
			reqIKEMsg.BuildIKEHeader(s.ikesa.LocalSPI, s.ikesa.RemoteSPI, types.IKE_AUTH, types.InitiatorBitCheck, s.ikesa.MessageID)

			// SK
			if nextPyload, payloadData, err := reqPayloads.Encode(); err != nil {
				s.log.Errorf("Encode payload failed: %+v", err)
				return task_manager.Failed
			} else {
				if encryptedData, err := s.ikesa.EncryptToSKPayload(payloadData); err != nil {
					s.log.Errorf("Encrypt pyaload data failed: %+v", err)
					return task_manager.Failed
				} else {
					reqIKEMsg.Payloads.BuildEncrypted(types.IKEPayloadType(nextPyload), encryptedData)
					fCKS = true
				}
			}

			//encodeSig:
			// Encode, add cks, and send
			sendp = new(packet)
			if data, err := reqIKEMsg.Encode(); err != nil {
				s.log.Errorf("IKE message encode failed: %+v", err)
				return task_manager.Failed
			} else {
				*sendp = s.packetTemplate
				sendp.Payload = data
			}

			// Checksum
			if fCKS {
				if err := s.ikesa.CalcIKEChecksum(sendp.Payload); err != nil {
					s.log.Errorf("Calculate checksum failed: %+v", err)
					return task_manager.Failed
				}
				// Reset CKS flag
				fCKS = false
			}

			//sendSig:
			s.ikeService.packetDispatcher.send(sendp)

		recvSig:
			// Response
			// This part can be used with tag send: to implement retransmission
			recvp = <-s.ikeResReadChan

			// Decode
			resIKEMsg = new(message.IKEMessage)
			if err := resIKEMsg.Decode(recvp.Payload); err != nil {
				s.log.Errorf("IKE_AUTH response decode failed: %+v", err)
				return task_manager.Failed
			}

			// Check
			if !s.ikesa.CheckMessageID(resIKEMsg.MessageID) { // message ID not matched
				s.log.Warn("Received IKE message that its message ID not matched. Drop")
				goto recvSig
			}
			if resIKEMsg.Flags&types.ResponseBitCheck == 0 { // not response
				s.log.Warn("Received IKE message that is not a response message. Drop")
				goto recvSig
			}

			// Get payloads
			sk = nil
			for _, p := range resIKEMsg.Payloads {
				switch p.Type() {
				case types.TypeSK:
					sk = p.(*message.Encrypted)
					fCKS = true
				default:
					s.log.Warnf("Receive type %d IKE payload when process IKE_AUTH response. Skip", p.Type())
				}
			}

			// Checksum
			if fCKS {
				if !s.ikesa.VerifyIKEChecksum(recvp.Payload) {
					s.log.Error("Checksum failed")
					return task_manager.Failed
				}
				// Reset CKS flag
				fCKS = false
			}

			resPayloads.Reset()

			// Handle SK
			if sk != nil {
				if payloadData, err := s.ikesa.DecryptSKPayload(sk.EncryptedData); err != nil {
					s.log.Errorf("Decrypt IKE SK failed: %+v", err)
					return task_manager.Failed
				} else {
					if err := resPayloads.Decode(sk.NextPayload, payloadData); err != nil {
						s.log.Errorf("IKE_AUTH response encrypted raw data decode failed: %+v", err)
						return task_manager.Failed
					}
				}
			}

			// Get payloads
			eap = nil
			for _, p := range resPayloads {
				switch p.Type() {
				case types.TypeEAP:
					eap = p.(*message.EAP)
				default:
					s.log.Warnf("Receive type %d IKE payload when process IKE_AUTH response. Skip", p.Type())
				}
			}

			// Handle EAP
			if eap != nil {
				if eap.Code == types.EAPCodeSuccess {
					break
				} else if eap.Code == types.EAPCodeRequest {
					if len(eap.EAPTypeData) == 0 {
						s.log.Error("No EAP type payload found")
						return task_manager.Failed
					}

					if eap5g := eap.EAPTypeData[0].(*message.EAPExpanded); eap5g.VendorID != types.VendorID3GPP ||
						eap5g.VendorType != types.VendorTypeEAP5G {
						s.log.Errorf("Can only handle EAP5G. Received: Vendor: %d, Vendor Type: %d", eap5g.VendorID, eap5g.VendorType)
						return task_manager.Failed
					} else {
						if eap5g.VendorData[0] != types.EAP5GType5GNAS {
							s.log.Error("Received EAP5G payload but it is not 5GNAS")
							return task_manager.Failed
						}
						if nasPDULen := binary.BigEndian.Uint16(eap5g.VendorData[2:4]); nasPDULen != 0 {
							nasWriteChan <- eap5g.VendorData[4 : 4+nasPDULen]
						}
					}
				} else if eap.Code == types.EAPCodeFailure {
					s.log.Error("Received EAP failure. EAP signalling procedure failed")
					return task_manager.Failed
				}
			} else {
				s.log.Error("Responder doesn't send EAP")
				return task_manager.Failed
			}
		}
		// Get Kn3iwf from NAS
		if info := <-s.nasSessIntRead; info.Comm != sessInterface.REG {
			s.log.Error("Received communication type that is not REG")
			return task_manager.Failed
		} else {
			paramREG := info.Value.(*sessInterface.Param_REG)
			kn3iwf = paramREG.Kn3iwf
		}
	} else {
		s.log.Error("Responder doesn't send EAP")
		return task_manager.Failed
	}

	// Build reqPayloads
	reqPayloads.Reset()

	// Auth
	reqPayloads.BuildAuthentication(types.SharedKeyMesageIntegrityCode, s.ikesa.GetAuth(kn3iwf, t.initiatorSignedOctets))

	// Build IKE message
	reqIKEMsg = new(message.IKEMessage)
	reqIKEMsg.BuildIKEHeader(s.ikesa.LocalSPI, s.ikesa.RemoteSPI, types.IKE_AUTH, types.InitiatorBitCheck, s.ikesa.MessageID)

	// SK
	if nextPyload, payloadData, err := reqPayloads.Encode(); err != nil {
		s.log.Errorf("Encode payload failed: %+v", err)
		return task_manager.Failed
	} else {
		if encryptedData, err := s.ikesa.EncryptToSKPayload(payloadData); err != nil {
			s.log.Errorf("Encrypt pyaload data failed: %+v", err)
			return task_manager.Failed
		} else {
			reqIKEMsg.Payloads.BuildEncrypted(types.IKEPayloadType(nextPyload), encryptedData)
			fCKS = true
		}
	}

	//encodePostSig:
	// Encode, add cks, and send
	sendp = new(packet)
	if data, err := reqIKEMsg.Encode(); err != nil {
		s.log.Errorf("IKE message encode failed: %+v", err)
		return task_manager.Failed
	} else {
		*sendp = s.packetTemplate
		sendp.Payload = data
	}

	// Checksum
	if fCKS {
		if err := s.ikesa.CalcIKEChecksum(sendp.Payload); err != nil {
			s.log.Errorf("Calculate checksum failed: %+v", err)
			return task_manager.Failed
		}
		// Reset CKS flag
		fCKS = false
	}

	//sendPostSig:
	s.ikeService.packetDispatcher.send(sendp)

recvPostSig:
	// Response
	// This part can be used with tag send: to implement retransmission
	recvp = <-s.ikeResReadChan

	// Decode
	resIKEMsg = new(message.IKEMessage)
	if err := resIKEMsg.Decode(recvp.Payload); err != nil {
		s.log.Errorf("IKE_AUTH response decode failed: %+v", err)
		return task_manager.Failed
	}

	// Check
	if !s.ikesa.CheckMessageID(resIKEMsg.MessageID) { // message ID not matched
		s.log.Warn("Received IKE message that its message ID not matched. Drop")
		goto recvPostSig
	}
	if resIKEMsg.Flags&types.ResponseBitCheck == 0 { // not response
		s.log.Warn("Received IKE message that is not a response message. Drop")
		goto recvPostSig
	}

	// Get payloads
	sk = nil
	for _, p := range resIKEMsg.Payloads {
		switch p.Type() {
		case types.TypeSK:
			sk = p.(*message.Encrypted)
			fCKS = true
		default:
			s.log.Warnf("Receive type %d IKE payload when process IKE_AUTH response. Skip", p.Type())
		}
	}

	// Checksum
	if fCKS {
		if !s.ikesa.VerifyIKEChecksum(recvp.Payload) {
			s.log.Error("Checksum failed")
			return task_manager.Failed
		}
		// Reset CKS flag
		fCKS = false
	}

	resPayloads.Reset()

	// Handle SK
	if sk != nil {
		if payloadData, err := s.ikesa.DecryptSKPayload(sk.EncryptedData); err != nil {
			s.log.Errorf("Decrypt IKE SK failed: %+v", err)
			return task_manager.Failed
		} else {
			if err := resPayloads.Decode(sk.NextPayload, payloadData); err != nil {
				s.log.Errorf("IKE_AUTH response encrypted raw data decode failed: %+v", err)
				return task_manager.Failed
			}
		}
	}

	// Get payloads
	auth = nil
	var sar *message.SecurityAssociation
	tsi = nil
	tsr = nil
	cp = nil
	notify = make([]*message.Notification, 0)
	for _, p := range resPayloads {
		switch p.Type() {
		case types.TypeAUTH:
			auth = p.(*message.Authentication)
		case types.TypeSA:
			sar = p.(*message.SecurityAssociation)
		case types.TypeTSi:
			tsi = p.(*message.TrafficSelectorInitiator)
		case types.TypeTSr:
			tsr = p.(*message.TrafficSelectorResponder)
		case types.TypeCP:
			cp = p.(*message.Configuration)
		case types.TypeN:
			notify = append(notify, p.(*message.Notification))
		default:
			s.log.Warnf("Receive type %d IKE payload when process IKE_AUTH response. Skip", p.Type())
		}
	}

	// Handle AUTH
	if auth != nil {
		expectedAuth := s.ikesa.GetAuth(kn3iwf, t.responderSignedOctets)
		if !bytes.Equal(expectedAuth, auth.AuthenticationData) {
			s.log.Error("Authentication responder failed")
			return task_manager.Failed
		}
	} else {
		s.log.Error("Responder doesn't send AUTH")
		return task_manager.Failed
	}

	// Handle SA
	if sar != nil {
		if len(sar.Proposals) != 1 {
			s.log.Error("Proposal number in response is not correct")
			return task_manager.Failed
		}
		if !childSA.SetProposal(sar.Proposals[0]) {
			s.log.Error("Set proposal failed")
			return task_manager.Failed
		}
		if err := childSA.GenerateKey(s.ikesa.Prf_d, nil, t.ninr); err != nil {
			s.log.Errorf("Generate key for child SA failed: %+v", err)
			return task_manager.Failed
		}
	} else {
		s.log.Error("Responder doesn't send SA")
		return task_manager.Failed
	}

	// Handle TSi
	if tsi != nil {
		if len(tsi.TrafficSelectors) < 1 {
			s.log.Error("Traffic selector contains no single traffic selector")
			return task_manager.Failed
		} else if len(tsi.TrafficSelectors) > 1 {
			s.log.Error("Parsing more than one single traffic selector is currently not supported")
			return task_manager.Failed
		}
		sts := tsi.TrafficSelectors[0]
		childSA.IPProto = sts.IPProtocolID
		childSA.TSLocal = convertIPRange(sts.StartAddress, sts.EndAddress)
	} else {
		s.log.Error("Responder doesn't send TSi")
		return task_manager.Failed
	}

	// Handle TSr
	if tsr != nil {
		if len(tsr.TrafficSelectors) < 1 {
			s.log.Error("Traffic selector contains no single traffic selector")
			return task_manager.Failed
		} else if len(tsr.TrafficSelectors) > 1 {
			s.log.Error("Parsing more than one single traffic selector is currently not supported")
			return task_manager.Failed
		}
		sts := tsr.TrafficSelectors[0]
		childSA.IPProto = sts.IPProtocolID
		childSA.TSRemote = convertIPRange(sts.StartAddress, sts.EndAddress)
	} else {
		s.log.Error("Responder doesn't send TSr")
		return task_manager.Failed
	}

	// Handle CP
	if cp != nil {
		if cp.ConfigurationType != types.CFG_REPLY {
			s.log.Error("Receive configuration type isn't CFG_REPLY")
			return task_manager.Failed
		}

		// Create virtual interface
		if err := netlink.LinkAdd(s.link); err != nil {
			s.log.Errorf("Create virtual interface failed: %+v", err)
			return task_manager.Failed
		}

		// Parse configuration
		for _, confAttr := range cp.ConfigurationAttribute {
			if confAttr.Type == types.INTERNAL_IP4_ADDRESS {
				s.addr.IP = confAttr.Value
			}
			if confAttr.Type == types.INTERNAL_IP4_NETMASK {
				s.addr.Mask = confAttr.Value
			}
		}

		// Add address on link
		if err := netlink.AddrAdd(s.link, s.addr); err != nil {
			s.log.Errorf("Add address on vti failed: %+v", err)
			return task_manager.Failed
		}

		// Set link state up
		if err := netlink.LinkSetUp(s.link); err != nil {
			s.log.Errorf("Link set vti up failed: %+v", err)
			return task_manager.Failed
		}
	} else {
		s.log.Error("Responder doesn't send CP")
		return task_manager.Failed
	}

	// Setup xfrm
	if err := childSA.SetXFRMState(s.ikesa.Role); err != nil {
		s.log.Errorf("Set XFRM state failed: %+v", err)
		return task_manager.Failed
	}
	if err := childSA.GenerateXFRMPolicy(s.ikesa.Role); err != nil {
		s.log.Errorf("Generate XFRM policy failed: %+v", err)
		return task_manager.Failed
	}
	if err := childSA.XFRMRuleAdd(); err != nil {
		s.log.Errorf("Add XFRM rules failed: %+v", err)
		return task_manager.Failed
	}

	// Handle Notify N(NAS_IP_ADDRESS) and N(NAS_TCP_PORT)
	if len(notify) != 0 {
		nasTCPAddr := new(net.TCPAddr)
		for _, n := range notify {
			if n.NotifyMessageType == types.Vendor3GPPNotifyTypeNAS_IP4_ADDRESS {
				if len(n.NotificationData) != 4 {
					s.log.Error("NAS_IP4_ADDRESS is not valid")
					return task_manager.Failed
				}
				nasTCPAddr.IP = n.NotificationData[:4]
			}
			if n.NotifyMessageType == types.Vendor3GPPNotifyTypeNAS_TCP_PORT {
				if len(n.NotificationData) != 2 {
					s.log.Error("NAS_TCP_PORT is not valid")
					return task_manager.Failed
				}
				nasTCPAddr.Port = int(binary.BigEndian.Uint16(n.NotificationData[:2]))
			}
		}
		// Send NAS TCP address to NAS session
		s.nasSessIntWrite <- &sessInterface.SessInt{
			Comm: sessInterface.REG,
			Value: &sessInterface.Param_REG{
				Addr: nasTCPAddr,
			},
		}
	} else {
		s.log.Error("Responder doesn't send any Notify")
		return task_manager.Failed
	}

	// Deregister read channel
	s.ikeService.packetDispatcher.deregisterResReadChan(s.ikesa.LocalSPI)

	s.childsa = append(s.childsa, childSA)

	return task_manager.Success
}

func convertIPRange(startAddr []byte, endAddr []byte) *net.IPNet {
	sAddr := binary.BigEndian.Uint32(startAddr)
	eAddr := binary.BigEndian.Uint32(endAddr)
	mask := uint32(1<<bits.Len32(sAddr^eAddr)-1) ^ math.MaxUint32
	ipMask := make([]byte, 4)
	binary.BigEndian.PutUint32(ipMask, mask)
	return &net.IPNet{
		IP:   startAddr,
		Mask: ipMask,
	}
}
