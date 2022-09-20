package ike

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"github.com/syujy/n3ue/internal/sessInterface"
	"github.com/syujy/n3ue/internal/task_manager"
	"net"
	"time"

	"github.com/syujy/ikev2/message"
	"github.com/syujy/ikev2/security"
	"github.com/syujy/ikev2/types"
	"github.com/vishvananda/netlink"
)

func (s *Session) udpKeepAlive(t *task) int {
	ticker := time.NewTicker(time.Duration(t.timerInterval) * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-t.ctx.Done():
			return task_manager.Success
		case <-ticker.C:
			var p packet = s.packetTemplate
			p.Payload = []byte{0xff}
			s.ikeService.packetDispatcher.send(&p)
		}
	}
}

func (s *Session) handle(t *task) int {
	for {
		select {
		case <-t.ctx.Done():
			return task_manager.Success
		case p := <-s.ikeReqReadChan:
			s.handleIKEReq(p)
		}
	}
}

func (s *Session) handleIKEReq(p *packet) {
	switch p.Payload[18] {
	case types.CREATE_CHILD_SA:
		s.checkMsgError(s.handleCREATE_CHILD_SA(p), "CREATE_CHILD_SA")
	default:
		s.log.Errorf("Handler is not implemented or type is undefined for this IKE request. Type: %d", p.Payload[18])
	}
}

func (s *Session) handleCREATE_CHILD_SA(recvp *packet) error {
	// Decode
	reqIKEMsg := new(message.IKEMessage)
	if err := reqIKEMsg.Decode(recvp.Payload); err != nil {
		return fmt.Errorf("CREATE_CHILD_SA request decode failed: %+v", err)
	}

	// Check
	if !s.ikesa.CheckMessageID(reqIKEMsg.MessageID) { // message ID not matched
		return fmt.Errorf("Received IKE message that its message ID not matched. Drop")
	}
	if reqIKEMsg.Flags&types.ResponseBitCheck != 0 { // not request
		return fmt.Errorf("Received IKE message that is not a response message. Drop")
	}

	// Get payloads
	var sk *message.Encrypted
	var notify []*message.Notification
	var fCKS bool // flag

	for _, p := range reqIKEMsg.Payloads {
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

	// Checksum
	if fCKS {
		if !s.ikesa.VerifyIKEChecksum(recvp.Payload) {
			return errors.New("Checksum failed")
		}
		// Reset CKS flag
		fCKS = false
	}

	var reqPayloads message.IKEPayloadContainer

	// Handle SK
	if sk != nil {
		if payloadData, err := s.ikesa.DecryptSKPayload(sk.EncryptedData); err != nil {
			return fmt.Errorf("Decrypt IKE SK failed: %+v", err)
		} else {
			if err := reqPayloads.Decode(sk.NextPayload, payloadData); err != nil {
				return fmt.Errorf("IKE_AUTH response encrypted raw data decode failed: %+v", err)
			}
		}
	}

	// Get payloads
	var reqSA *message.SecurityAssociation
	var reqN *message.Nonce
	var reqKE *message.KeyExchange
	var reqTSi *message.TrafficSelectorInitiator
	var reqTSr *message.TrafficSelectorResponder
	notify = nil

	for _, p := range reqPayloads {
		switch p.Type() {
		case types.TypeSA:
			reqSA = p.(*message.SecurityAssociation)
		case types.TypeNiNr:
			reqN = p.(*message.Nonce)
		case types.TypeKE:
			reqKE = p.(*message.KeyExchange)
		case types.TypeTSi:
			reqTSi = p.(*message.TrafficSelectorInitiator)
		case types.TypeTSr:
			reqTSr = p.(*message.TrafficSelectorResponder)
		case types.TypeN:
			notify = append(notify, p.(*message.Notification))
		default:
			s.log.Warnf("Receive type %d IKE payload when process CREATE_CHILD_SA request. Skip", p.Type())
		}
	}

	// ChildSA
	childSA := new(security.ChildSA)
	childSA.Mark = s.Ctx.IPSecIf.Mark
	childSA.LocalPublicIPAddr = net.ParseIP(s.Ctx.IKEBindAddress)
	childSA.RemotePublicIPAddr = s.packetTemplate.RemoteAddr.IP
	if s.ikesa.NATT {
		childSA.EnableEncap = true
		childSA.LocalPort = int(s.packetTemplate.LocalPort)
		childSA.RemotePort = s.packetTemplate.RemoteAddr.Port
	}

	// Handle SA
	if reqSA != nil {
		for _, p := range reqSA.Proposals {
			if childSA.SelectProposal(p) {
				childSA.SPI = binary.BigEndian.Uint32(p.SPI)
				break
			}
		}
	} else {
		return errors.New("Initiator doesn't send SA")
	}

	// Handle Nonce
	if reqN == nil {
		return errors.New("Initiator doesn't send Nr")
	}

	// Handle KE
	var dhPubValue []byte
	var dhSharedKey []byte
	if reqKE != nil {
		if childSA.GetDHTransformID() != 0 {
			if reqKE.DiffieHellmanGroup != childSA.GetDHTransformID() {
				// Build resPayloads
				var resPayloads message.IKEPayloadContainer
				// Notify - INVALID_KE_PAYLOAD
				ndata := make([]byte, 2)
				binary.BigEndian.PutUint16(ndata, childSA.GetDHTransformID())
				resPayloads.BuildNotification(types.TypeESP, types.INVALID_KE_PAYLOAD, nil, ndata)
				// Build IKE message
				reqIKEMsg = new(message.IKEMessage)
				reqIKEMsg.BuildIKEHeader(s.ikesa.RemoteSPI, s.ikesa.LocalSPI, types.CREATE_CHILD_SA, types.ResponseBitCheck, reqIKEMsg.MessageID)
				// SK
				if nextPyload, payloadData, err := reqPayloads.Encode(); err != nil {
					return fmt.Errorf("Encode payload failed: %+v", err)
				} else {
					if encryptedData, err := s.ikesa.EncryptToSKPayload(payloadData); err != nil {
						return fmt.Errorf("Encrypt pyaload data failed: %+v", err)
					} else {
						reqIKEMsg.Payloads.BuildEncrypted(types.IKEPayloadType(nextPyload), encryptedData)
					}
				}
				// Encode, add cks, and send
				sendp := new(packet)
				if data, err := reqIKEMsg.Encode(); err != nil {
					return fmt.Errorf("IKE message encode failed: %+v", err)
				} else {
					*sendp = s.packetTemplate
					sendp.Payload = data
				}
				// Checksum
				if err := s.ikesa.CalcIKEChecksum(sendp.Payload); err != nil {
					return fmt.Errorf("Calculate checksum failed: %+v", err)
				}
				s.ikeService.packetDispatcher.send(sendp)
			} else {
				if pValue, sKey, err := childSA.CalcKEMaterial(reqKE.KeyExchangeData); err != nil {
					return fmt.Errorf("Calculate KE material failed: %+v", err)
				} else {
					dhPubValue = pValue
					dhSharedKey = sKey
				}
			}
		}
	}

	// Handle TSi
	if reqTSi != nil {
		if len(reqTSi.TrafficSelectors) < 1 {
			return errors.New("Traffic selector contains no single traffic selector")
		} else if len(reqTSi.TrafficSelectors) > 1 {
			return errors.New("Parsing more than one single traffic selector is currently not supported")
		}
		sts := reqTSi.TrafficSelectors[0]
		if bytes.Compare(s.addr.IP.To4(), sts.StartAddress) >= 0 && bytes.Compare(s.addr.IP.To4(), sts.EndAddress) <= 0 {
			childSA.IPProto = sts.IPProtocolID
			childSA.TSLocal = &net.IPNet{
				IP:   s.addr.IP,
				Mask: []byte{255, 255, 255, 255},
			}
		} else {
			return fmt.Errorf("Internal IP address is not in range of TSi sent from initiator. Local: %+v, Start: %+v, End: %+v", []byte(s.addr.IP.To4()), sts.StartAddress, sts.EndAddress)
		}
	} else {
		return errors.New("Responder doesn't send TSi")
	}

	// Handle TSr
	if reqTSr != nil {
		if len(reqTSr.TrafficSelectors) < 1 {
			return errors.New("Traffic selector contains no single traffic selector")
		} else if len(reqTSr.TrafficSelectors) > 1 {
			return errors.New("Parsing more than one single traffic selector is currently not supported")
		}
		sts := reqTSr.TrafficSelectors[0]
		childSA.IPProto = sts.IPProtocolID
		childSA.TSRemote = convertIPRange(sts.StartAddress, sts.EndAddress)
	} else {
		return errors.New("Responder doesn't send TSr")
	}

	// Handle Notify N(5G_QOS_INFO) and N(UP_IP4_ADDRESS)
	gretun := new(netlink.Gretun)
	gretun.LinkAttrs = netlink.NewLinkAttrs()
	gretun.Name = "gretun0"
	gretun.PMtuDisc = 1
	if len(notify) != 0 {
		for _, n := range notify {
			if n.NotifyMessageType == types.Vendor3GPPNotifyType5G_QOS_INFO {
				// Get QFI from 5G_QOS_INFO
				// TODO: Implement a complete decoder/encoder to handle 5G_QOS_INFO

				if len(n.NotificationData) < 5 {
					return errors.New("5G_QOS_INFO is not valid")
				}
				var qfi int = -1
				if n.NotificationData[2] != 0 {
					qfi = int(n.NotificationData[3])
				}
				if qfi != -1 {
					gretunkey := uint32(qfi << 24)
					gretun.IKey = gretunkey
					gretun.OKey = gretunkey
				}

			}
			if n.NotifyMessageType == types.Vendor3GPPNotifyTypeUP_IP4_ADDRESS {
				if len(n.NotificationData) != 4 {
					return errors.New("UP_IP4_ADDRESS is not valid")
				}
				gretun.Local = s.addr.IP
				gretun.Remote = n.NotificationData[:4]
			}
		}
	} else {
		return errors.New("Responder doesn't send any Notify")
	}

	// Build resPayloads
	var resPayloads message.IKEPayloadContainer

	// SAi
	sai := resPayloads.BuildSecurityAssociation()
	sai.Proposals = append(sai.Proposals, childSA.ToProposal())

	// Ni
	var ninr []byte
	if bign, err := security.GenerateRandomNumber(); err != nil {
		return fmt.Errorf("Build Ni payload failed: GenerateRandomNumber() failed: %+v", err)
	} else {
		b := bign.Bytes()
		resPayloads.BuildNonce(b)
		if s.ikesa.Role == types.Role_Initiator {
			ninr = append(b, reqN.NonceData...)
		} else {
			ninr = append(reqN.NonceData, b...)
		}
	}

	// KE (if present)
	if len(dhPubValue) != 0 {
		resPayloads.BUildKeyExchange(reqKE.DiffieHellmanGroup, dhPubValue)
	}

	// Traffic Selector
	tsi := resPayloads.BuildTrafficSelectorInitiator()
	tsr := resPayloads.BuildTrafficSelectorResponder()
	if s.ikesa.Role == types.Role_Initiator {
		tsi.TrafficSelectors.BuildIndividualTrafficSelector(types.TS_IPV4_ADDR_RANGE, types.IPProtocolGRE, 0, 65535, s.addr.IP.To4(), s.addr.IP.To4())
		tsr.TrafficSelectors = append(tsr.TrafficSelectors, reqTSr.TrafficSelectors[0])
	} else {
		tsi.TrafficSelectors = append(tsi.TrafficSelectors, reqTSi.TrafficSelectors[0])
		tsr.TrafficSelectors.BuildIndividualTrafficSelector(types.TS_IPV4_ADDR_RANGE, types.IPProtocolGRE, 0, 65535, s.addr.IP.To4(), s.addr.IP.To4())
	}

	// Build IKE message
	resIKEMsg := new(message.IKEMessage)
	if s.ikesa.Role == types.Role_Initiator {
		resIKEMsg.BuildIKEHeader(s.ikesa.LocalSPI, s.ikesa.RemoteSPI, types.CREATE_CHILD_SA, types.InitiatorBitCheck|types.ResponseBitCheck, reqIKEMsg.MessageID)
	} else {
		resIKEMsg.BuildIKEHeader(s.ikesa.RemoteSPI, s.ikesa.LocalSPI, types.CREATE_CHILD_SA, types.ResponseBitCheck, reqIKEMsg.MessageID)
	}

	// SK
	if nextPyload, payloadData, err := resPayloads.Encode(); err != nil {
		return fmt.Errorf("Encode payload failed: %+v", err)
	} else {
		if encryptedData, err := s.ikesa.EncryptToSKPayload(payloadData); err != nil {
			return fmt.Errorf("Encrypt pyaload data failed: %+v", err)
		} else {
			resIKEMsg.Payloads.BuildEncrypted(types.IKEPayloadType(nextPyload), encryptedData)
			fCKS = true
		}
	}

	// Encode, add cks, and send
	sendp := new(packet)
	if data, err := resIKEMsg.Encode(); err != nil {
		return fmt.Errorf("IKE message encode failed: %+v", err)
	} else {
		*sendp = s.packetTemplate
		sendp.Payload = data
	}

	// Checksum
	if fCKS {
		if err := s.ikesa.CalcIKEChecksum(sendp.Payload); err != nil {
			return fmt.Errorf("Calculate checksum failed: %+v", err)
		}
		// Reset CKS flag
		fCKS = false
	}

	// Set up XFRM
	// Generate states and policies
	if err := childSA.GenerateXFRMState(s.ikesa.Role, false); err != nil {
		return fmt.Errorf("Generate XFRM state failed: %+v", err)
	}
	if err := childSA.GenerateXFRMPolicy(s.ikesa.Role); err != nil {
		return fmt.Errorf("Generate XFRM policy failed: %+v", err)
	}
	// Generate keys
	if err := childSA.GenerateKey(s.ikesa.Prf_d, dhSharedKey, ninr); err != nil {
		return fmt.Errorf("Generate Key failed: %+v", err)
	}
	// Set security parameters of XFRM state
	if err := childSA.SetXFRMState(s.ikesa.Role); err != nil {
		return fmt.Errorf("Set XFRM state failed: %+v", err)
	}
	// Add rules
	if err := childSA.XFRMRuleAdd(); err != nil {
		return fmt.Errorf("Add XFRM rules failed: %+v", err)
	}

	// Add GRE tunnel interface
	if err := netlink.LinkAdd(gretun); err != nil {
		return fmt.Errorf("Add GRE tunnel link failed: %+v", err)
	}
	// Set link state up
	if err := netlink.LinkSetUp(gretun); err != nil {
		return fmt.Errorf("Link set GRE link up failed: %+v", err)
	}

	// Send link information to NAS session
	s.nasSessIntWrite <- &sessInterface.SessInt{
		Comm: sessInterface.PDUSessEstab,
		Value: &sessInterface.Param_PDUSessEstab{
			Link: gretun,
		},
	}

	// Recv ACK from NAS
	<-s.nasSessIntRead

	s.ikeService.packetDispatcher.send(sendp)

	return nil
}
