package nas

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"n3ue/internal/nas/lib"

	"bitbucket.org/free5gc-team/nas"
	"bitbucket.org/free5gc-team/nas/nasMessage"
	"bitbucket.org/free5gc-team/nas/nasType"
	"bitbucket.org/free5gc-team/openapi/models"
)

const (
	PDUSesModiReq    string = "PDU Session Modification Request"
	PDUSesModiCmp    string = "PDU Session Modification Complete"
	PDUSesModiCmdRej string = "PDU Session Modification Command Reject"
	PDUSesRelReq     string = "PDU Session Release Request"
	PDUSesRelCmp     string = "PDU Session Release Complete"
	PDUSesRelRej     string = "PDU Session Release Reject"
	PDUSesAuthCmp    string = "PDU Session Authentication Complete"
)

func (s *Session) GetRegistrationRequest(registrationType uint8, mobileIdentity nasType.MobileIdentity5GS, capBuffer []uint8, requestedNSSAI *nasType.RequestedNSSAI, uplinkDataStatus *nasType.UplinkDataStatus) (nasPdu []byte) {
	m := nas.NewMessage()
	m.GmmMessage = nas.NewGmmMessage()
	m.GmmHeader.SetMessageType(nas.MsgTypeRegistrationRequest)

	registrationRequest := nasMessage.NewRegistrationRequest(0)
	registrationRequest.SetExtendedProtocolDiscriminator(nasMessage.Epd5GSMobilityManagementMessage)
	registrationRequest.SpareHalfOctetAndSecurityHeaderType.SetSecurityHeaderType(nas.SecurityHeaderTypePlainNas)
	registrationRequest.SpareHalfOctetAndSecurityHeaderType.SetSpareHalfOctet(0x00)
	registrationRequest.RegistrationRequestMessageIdentity.SetMessageType(nas.MsgTypeRegistrationRequest)
	registrationRequest.NgksiAndRegistrationType5GS.SetTSC(nasMessage.TypeOfSecurityContextFlagNative)
	registrationRequest.NgksiAndRegistrationType5GS.SetNasKeySetIdentifiler(0x7)
	registrationRequest.NgksiAndRegistrationType5GS.SetRegistrationType5GS(registrationType)
	registrationRequest.MobileIdentity5GS = mobileIdentity

	if capBuffer != nil {
		registrationRequest.UESecurityCapability = &nasType.UESecurityCapability{
			Iei:    nasMessage.RegistrationRequestUESecurityCapabilityType,
			Len:    8,
			Buffer: capBuffer,
		}
	}
	registrationRequest.RequestedNSSAI = requestedNSSAI
	registrationRequest.UplinkDataStatus = uplinkDataStatus

	registrationRequest.NgksiAndRegistrationType5GS.SetFOR(1)

	m.GmmMessage.RegistrationRequest = registrationRequest

	data := new(bytes.Buffer)
	err := m.GmmMessageEncode(data)
	if err != nil {
		fmt.Println(err.Error())
	}

	nasPdu = data.Bytes()
	return
}

func (s *Session) GetRegistrationRequestWith5GMM(registrationType uint8,
	requestedNSSAI *nasType.RequestedNSSAI, uplinkDataStatus *nasType.UplinkDataStatus) ([]byte, error) {
	m := nas.NewMessage()
	m.GmmMessage = nas.NewGmmMessage()
	m.GmmHeader.SetMessageType(nas.MsgTypeRegistrationRequest)

	registrationRequest := nasMessage.NewRegistrationRequest(0)
	registrationRequest.SetExtendedProtocolDiscriminator(nasMessage.Epd5GSMobilityManagementMessage)
	registrationRequest.SpareHalfOctetAndSecurityHeaderType.SetSecurityHeaderType(nas.SecurityHeaderTypePlainNas)
	registrationRequest.SpareHalfOctetAndSecurityHeaderType.SetSpareHalfOctet(0x00)
	registrationRequest.RegistrationRequestMessageIdentity.SetMessageType(nas.MsgTypeRegistrationRequest)
	registrationRequest.NgksiAndRegistrationType5GS.SetTSC(nasMessage.TypeOfSecurityContextFlagNative)
	registrationRequest.NgksiAndRegistrationType5GS.SetNasKeySetIdentifiler(0x01)
	registrationRequest.NgksiAndRegistrationType5GS.SetRegistrationType5GS(registrationType)
	registrationRequest.MobileIdentity5GS = lib.SupiToMobileId(s.Ctx.Supi, s.Ctx.PlmnID)
	// S1 Mode, Handover Attach, LPP are not supported
	registrationRequest.Capability5GMM = &nasType.Capability5GMM{
		Iei:   nasMessage.RegistrationRequestCapability5GMMType,
		Len:   1,
		Octet: [13]uint8{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
	}
	registrationRequest.UESecurityCapability = &nasType.UESecurityCapability{
		Iei:    nasMessage.RegistrationRequestUESecurityCapabilityType,
		Len:    8,
		Buffer: lib.UeSecurityCap(s.c.IntegrityAlg, s.c.CipheringAlg),
	}
	registrationRequest.RequestedNSSAI = requestedNSSAI
	registrationRequest.UplinkDataStatus = uplinkDataStatus

	if s.c.FollowOnRequest {
		registrationRequest.SetFOR(1)
	} else {
		registrationRequest.SetFOR(0)
	}

	m.GmmMessage.RegistrationRequest = registrationRequest

	return m.PlainNasEncode()
}

func (s *Session) GetPduSessionEstablishmentRequest(pduSessionId, sessionType uint8) ([]byte, error) {

	m := nas.NewMessage()
	m.GsmMessage = nas.NewGsmMessage()
	m.GsmHeader.SetMessageType(nas.MsgTypePDUSessionEstablishmentRequest)

	pduSessionEstablishmentRequest := nasMessage.NewPDUSessionEstablishmentRequest(0)
	pduSessionEstablishmentRequest.ExtendedProtocolDiscriminator.SetExtendedProtocolDiscriminator(nasMessage.Epd5GSSessionManagementMessage)
	pduSessionEstablishmentRequest.SetMessageType(nas.MsgTypePDUSessionEstablishmentRequest)
	pduSessionEstablishmentRequest.PDUSessionID.SetPDUSessionID(pduSessionId)
	pduSessionEstablishmentRequest.PTI.SetPTI(0x00)
	pduSessionEstablishmentRequest.IntegrityProtectionMaximumDataRate.SetMaximumDataRatePerUEForUserPlaneIntegrityProtectionForDownLink(0xff) // full data rate
	pduSessionEstablishmentRequest.IntegrityProtectionMaximumDataRate.SetMaximumDataRatePerUEForUserPlaneIntegrityProtectionForUpLink(0xff)   // full data rate
	if sessionType != 0 {
		pduSessionEstablishmentRequest.PDUSessionType = new(nasType.PDUSessionType)
		pduSessionEstablishmentRequest.PDUSessionType.SetIei(nasMessage.PDUSessionEstablishmentAcceptPDUAddressType)
		pduSessionEstablishmentRequest.PDUSessionType.SetPDUSessionTypeValue(sessionType)
	}

	m.GsmMessage.PDUSessionEstablishmentRequest = pduSessionEstablishmentRequest

	return m.PlainNasEncode()
}

func (s *Session) GetUlNasTransport_PduSessionEstablishmentRequest(pduSessionId uint8, requestType uint8, dnnString string, sNssai *models.Snssai, gsmPdu []byte) ([]byte, error) {

	m := nas.NewMessage()
	m.GmmMessage = nas.NewGmmMessage()
	m.GmmHeader.SetMessageType(nas.MsgTypeULNASTransport)

	m.SecurityHeader = nas.SecurityHeader{
		ProtocolDiscriminator: nasMessage.Epd5GSMobilityManagementMessage,
		SecurityHeaderType:    nas.SecurityHeaderTypeIntegrityProtectedAndCiphered,
	}

	ulNasTransport := nasMessage.NewULNASTransport(0)
	ulNasTransport.SpareHalfOctetAndSecurityHeaderType.SetSecurityHeaderType(nas.SecurityHeaderTypePlainNas)
	ulNasTransport.SetMessageType(nas.MsgTypeULNASTransport)
	ulNasTransport.ExtendedProtocolDiscriminator.SetExtendedProtocolDiscriminator(nasMessage.Epd5GSMobilityManagementMessage)
	ulNasTransport.PduSessionID2Value = new(nasType.PduSessionID2Value)
	ulNasTransport.PduSessionID2Value.SetIei(nasMessage.ULNASTransportPduSessionID2ValueType)
	ulNasTransport.PduSessionID2Value.SetPduSessionID2Value(pduSessionId)
	ulNasTransport.RequestType = new(nasType.RequestType)
	ulNasTransport.RequestType.SetIei(nasMessage.ULNASTransportRequestTypeType)
	ulNasTransport.RequestType.SetRequestTypeValue(requestType)
	if dnnString != "" {
		dnn := []byte(dnnString)
		ulNasTransport.DNN = new(nasType.DNN)
		ulNasTransport.DNN.SetIei(nasMessage.ULNASTransportDNNType)
		ulNasTransport.DNN.SetLen(uint8(len(dnn)))
		ulNasTransport.DNN.SetDNN(dnn)
	}
	if sNssai != nil {
		var sdTemp [3]uint8
		sd, _ := hex.DecodeString(sNssai.Sd)
		copy(sdTemp[:], sd)
		ulNasTransport.SNSSAI = nasType.NewSNSSAI(nasMessage.ULNASTransportSNSSAIType)
		ulNasTransport.SNSSAI.SetLen(4)
		ulNasTransport.SNSSAI.SetSST(uint8(sNssai.Sst))
		ulNasTransport.SNSSAI.SetSD(sdTemp)
	}

	ulNasTransport.SpareHalfOctetAndPayloadContainerType.SetPayloadContainerType(nasMessage.PayloadContainerTypeN1SMInfo)
	ulNasTransport.PayloadContainer.SetLen(uint16(len(gsmPdu)))
	ulNasTransport.PayloadContainer.SetPayloadContainerContents(gsmPdu)

	m.GmmMessage.ULNASTransport = ulNasTransport

	return s.NASEncode(m, true, false)
}

func (s *Session) GetUlNasTransport_PduSessionModificationRequest(pduSessionId uint8, requestType uint8, dnnString string, sNssai *models.Snssai) (nasPdu []byte) {

	pduSessionModificationRequest := s.GetPduSessionModificationRequest(pduSessionId)

	m := nas.NewMessage()
	m.GmmMessage = nas.NewGmmMessage()
	m.GmmHeader.SetMessageType(nas.MsgTypeULNASTransport)

	ulNasTransport := nasMessage.NewULNASTransport(0)
	ulNasTransport.SpareHalfOctetAndSecurityHeaderType.SetSecurityHeaderType(nas.SecurityHeaderTypePlainNas)
	ulNasTransport.SetMessageType(nas.MsgTypeULNASTransport)
	ulNasTransport.ExtendedProtocolDiscriminator.SetExtendedProtocolDiscriminator(nasMessage.Epd5GSMobilityManagementMessage)
	ulNasTransport.PduSessionID2Value = new(nasType.PduSessionID2Value)
	ulNasTransport.PduSessionID2Value.SetIei(nasMessage.ULNASTransportPduSessionID2ValueType)
	ulNasTransport.PduSessionID2Value.SetPduSessionID2Value(pduSessionId)
	ulNasTransport.RequestType = new(nasType.RequestType)
	ulNasTransport.RequestType.SetIei(nasMessage.ULNASTransportRequestTypeType)
	ulNasTransport.RequestType.SetRequestTypeValue(requestType)
	if dnnString != "" {
		dnn := []byte(dnnString)
		ulNasTransport.DNN = new(nasType.DNN)
		ulNasTransport.DNN.SetIei(nasMessage.ULNASTransportDNNType)
		ulNasTransport.DNN.SetLen(uint8(len(dnn)))
		ulNasTransport.DNN.SetDNN(dnn)
	}
	if sNssai != nil {
		var sdTemp [3]uint8
		sd, _ := hex.DecodeString(sNssai.Sd)
		copy(sdTemp[:], sd)
		ulNasTransport.SNSSAI = nasType.NewSNSSAI(nasMessage.ULNASTransportSNSSAIType)
		ulNasTransport.SNSSAI.SetLen(4)
		ulNasTransport.SNSSAI.SetSST(uint8(sNssai.Sst))
		ulNasTransport.SNSSAI.SetSD(sdTemp)
	}

	ulNasTransport.SpareHalfOctetAndPayloadContainerType.SetPayloadContainerType(nasMessage.PayloadContainerTypeN1SMInfo)
	ulNasTransport.PayloadContainer.SetLen(uint16(len(pduSessionModificationRequest)))
	ulNasTransport.PayloadContainer.SetPayloadContainerContents(pduSessionModificationRequest)

	m.GmmMessage.ULNASTransport = ulNasTransport

	data := new(bytes.Buffer)
	err := m.GmmMessageEncode(data)
	if err != nil {
		fmt.Println(err.Error())
	}

	nasPdu = data.Bytes()
	return
}

func (s *Session) GetPduSessionModificationRequest(pduSessionId uint8) (nasPdu []byte) {

	m := nas.NewMessage()
	m.GsmMessage = nas.NewGsmMessage()
	m.GsmHeader.SetMessageType(nas.MsgTypePDUSessionModificationRequest)

	pduSessionModificationRequest := nasMessage.NewPDUSessionModificationRequest(0)
	pduSessionModificationRequest.ExtendedProtocolDiscriminator.SetExtendedProtocolDiscriminator(nasMessage.Epd5GSSessionManagementMessage)
	pduSessionModificationRequest.SetMessageType(nas.MsgTypePDUSessionModificationRequest)
	pduSessionModificationRequest.PDUSessionID.SetPDUSessionID(pduSessionId)
	pduSessionModificationRequest.PTI.SetPTI(0x00)
	// pduSessionModificationRequest.RequestedQosFlowDescriptions = nasType.NewRequestedQosFlowDescriptions(nasMessage.PDUSessionModificationRequestRequestedQosFlowDescriptionsType)
	// pduSessionModificationRequest.RequestedQosFlowDescriptions.SetLen(6)
	// pduSessionModificationRequest.RequestedQosFlowDescriptions.SetQoSFlowDescriptions([]uint8{0x09, 0x20, 0x41, 0x01, 0x01, 0x09})

	m.GsmMessage.PDUSessionModificationRequest = pduSessionModificationRequest

	data := new(bytes.Buffer)
	err := m.GsmMessageEncode(data)
	if err != nil {
		fmt.Println(err.Error())
	}

	nasPdu = data.Bytes()
	return
}
func (s *Session) GetPduSessionModificationComplete(pduSessionId uint8) ([]byte, error) {

	m := nas.NewMessage()
	m.GsmMessage = nas.NewGsmMessage()
	m.GsmHeader.SetMessageType(nas.MsgTypePDUSessionModificationComplete)

	pduSessionModificationComplete := nasMessage.NewPDUSessionModificationComplete(0)
	pduSessionModificationComplete.ExtendedProtocolDiscriminator.SetExtendedProtocolDiscriminator(nasMessage.Epd5GSSessionManagementMessage)
	pduSessionModificationComplete.SetMessageType(nas.MsgTypePDUSessionModificationComplete)
	pduSessionModificationComplete.PDUSessionID.SetPDUSessionID(pduSessionId)
	pduSessionModificationComplete.PTI.SetPTI(0x00)

	m.GsmMessage.PDUSessionModificationComplete = pduSessionModificationComplete

	return m.PlainNasEncode()
}
func (s *Session) GetPduSessionModificationCommandReject(pduSessionId uint8) (nasPdu []byte) {

	m := nas.NewMessage()
	m.GsmMessage = nas.NewGsmMessage()
	m.GsmHeader.SetMessageType(nas.MsgTypePDUSessionModificationCommandReject)

	pduSessionModificationCommandReject := nasMessage.NewPDUSessionModificationCommandReject(0)
	pduSessionModificationCommandReject.ExtendedProtocolDiscriminator.SetExtendedProtocolDiscriminator(nasMessage.Epd5GSSessionManagementMessage)
	pduSessionModificationCommandReject.SetMessageType(nas.MsgTypePDUSessionModificationCommandReject)
	pduSessionModificationCommandReject.PDUSessionID.SetPDUSessionID(pduSessionId)
	pduSessionModificationCommandReject.PTI.SetPTI(0x00)

	m.GsmMessage.PDUSessionModificationCommandReject = pduSessionModificationCommandReject

	data := new(bytes.Buffer)
	err := m.GsmMessageEncode(data)
	if err != nil {
		fmt.Println(err.Error())
	}

	nasPdu = data.Bytes()
	return
}

func (s *Session) GetPduSessionReleaseRequest(pduSessionId uint8) ([]byte, error) {

	m := nas.NewMessage()
	m.GsmMessage = nas.NewGsmMessage()
	m.GsmHeader.SetMessageType(nas.MsgTypePDUSessionReleaseRequest)

	pduSessionReleaseRequest := nasMessage.NewPDUSessionReleaseRequest(0)
	pduSessionReleaseRequest.ExtendedProtocolDiscriminator.SetExtendedProtocolDiscriminator(nasMessage.Epd5GSSessionManagementMessage)
	pduSessionReleaseRequest.SetMessageType(nas.MsgTypePDUSessionReleaseRequest)
	pduSessionReleaseRequest.PDUSessionID.SetPDUSessionID(pduSessionId)
	pduSessionReleaseRequest.PTI.SetPTI(0x00)

	m.GsmMessage.PDUSessionReleaseRequest = pduSessionReleaseRequest

	return m.PlainNasEncode()
}

func (s *Session) GetPduSessionReleaseComplete(pduSessionId uint8) ([]byte, error) {

	m := nas.NewMessage()
	m.GsmMessage = nas.NewGsmMessage()
	m.GsmHeader.SetMessageType(nas.MsgTypePDUSessionReleaseComplete)

	pduSessionReleaseComplete := nasMessage.NewPDUSessionReleaseComplete(0)
	pduSessionReleaseComplete.ExtendedProtocolDiscriminator.SetExtendedProtocolDiscriminator(nasMessage.Epd5GSSessionManagementMessage)
	pduSessionReleaseComplete.SetMessageType(nas.MsgTypePDUSessionReleaseComplete)
	pduSessionReleaseComplete.PDUSessionID.SetPDUSessionID(pduSessionId)
	pduSessionReleaseComplete.PTI.SetPTI(0x00)

	m.GsmMessage.PDUSessionReleaseComplete = pduSessionReleaseComplete

	return m.PlainNasEncode()
}

func (s *Session) GetPduSessionReleaseReject(pduSessionId uint8) (nasPdu []byte) {

	m := nas.NewMessage()
	m.GsmMessage = nas.NewGsmMessage()
	m.GsmHeader.SetMessageType(nas.MsgTypePDUSessionReleaseReject)

	pduSessionReleaseReject := nasMessage.NewPDUSessionReleaseReject(0)
	pduSessionReleaseReject.ExtendedProtocolDiscriminator.SetExtendedProtocolDiscriminator(nasMessage.Epd5GSSessionManagementMessage)
	pduSessionReleaseReject.SetMessageType(nas.MsgTypePDUSessionReleaseReject)
	pduSessionReleaseReject.PDUSessionID.SetPDUSessionID(pduSessionId)
	pduSessionReleaseReject.PTI.SetPTI(0x00)

	m.GsmMessage.PDUSessionReleaseReject = pduSessionReleaseReject

	data := new(bytes.Buffer)
	err := m.GsmMessageEncode(data)
	if err != nil {
		fmt.Println(err.Error())
	}

	nasPdu = data.Bytes()
	return
}

func (s *Session) GetPduSessionReleaseCommand(pduSessionId uint8) (nasPdu []byte) {
	m := nas.NewMessage()
	m.GsmMessage = nas.NewGsmMessage()
	m.GsmHeader.SetMessageType(nas.MsgTypePDUSessionReleaseCommand)

	pDUSessionReleaseCommand := nasMessage.NewPDUSessionReleaseCommand(0)
	pDUSessionReleaseCommand.ExtendedProtocolDiscriminator.SetExtendedProtocolDiscriminator(nasMessage.Epd5GSSessionManagementMessage)
	pDUSessionReleaseCommand.SetMessageType(nas.MsgTypePDUSessionReleaseReject)
	pDUSessionReleaseCommand.PDUSessionID.SetPDUSessionID(pduSessionId)
	pDUSessionReleaseCommand.PTI.SetPTI(0x00)
	pDUSessionReleaseCommand.SetCauseValue(nasMessage.Cause5GSMPDUSessionDoesNotExist)

	m.GsmMessage.PDUSessionReleaseCommand = pDUSessionReleaseCommand

	data := new(bytes.Buffer)
	err := m.GsmMessageEncode(data)
	if err != nil {
		fmt.Println(err.Error())
	}

	nasPdu = data.Bytes()
	return
}

func (s *Session) GetPduSessionAuthenticationComplete(pduSessionId uint8) (nasPdu []byte) {

	m := nas.NewMessage()
	m.GsmMessage = nas.NewGsmMessage()
	m.GsmHeader.SetMessageType(nas.MsgTypePDUSessionAuthenticationComplete)

	pduSessionAuthenticaitonComplete := nasMessage.NewPDUSessionAuthenticationComplete(0)
	pduSessionAuthenticaitonComplete.ExtendedProtocolDiscriminator.SetExtendedProtocolDiscriminator(nasMessage.Epd5GSSessionManagementMessage)
	pduSessionAuthenticaitonComplete.SetMessageType(nas.MsgTypePDUSessionAuthenticationComplete)
	pduSessionAuthenticaitonComplete.PDUSessionID.SetPDUSessionID(pduSessionId)
	pduSessionAuthenticaitonComplete.PTI.SetPTI(0x00)
	pduSessionAuthenticaitonComplete.EAPMessage.SetLen(6)
	pduSessionAuthenticaitonComplete.EAPMessage.SetEAPMessage([]byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55})

	m.GsmMessage.PDUSessionAuthenticationComplete = pduSessionAuthenticaitonComplete

	data := new(bytes.Buffer)
	err := m.GsmMessageEncode(data)
	if err != nil {
		fmt.Println(err.Error())
	}

	nasPdu = data.Bytes()
	return
}

func (s *Session) GetUlNasTransport_PduSessionCommonData(pduSessionId uint8, types string) ([]byte, error) {

	var payload []byte
	var err error
	switch types {
	case PDUSesModiReq:
		payload = s.GetPduSessionModificationRequest(pduSessionId)
	case PDUSesModiCmp:
		payload, err = s.GetPduSessionModificationComplete(pduSessionId)
	case PDUSesModiCmdRej:
		payload = s.GetPduSessionModificationCommandReject(pduSessionId)
	case PDUSesRelReq:
		payload, err = s.GetPduSessionReleaseRequest(pduSessionId)
	case PDUSesRelCmp:
		payload, err = s.GetPduSessionReleaseComplete(pduSessionId)
	case PDUSesRelRej:
		payload = s.GetPduSessionReleaseReject(pduSessionId)
	case PDUSesAuthCmp:
		payload = s.GetPduSessionAuthenticationComplete(pduSessionId)
	}

	if err != nil {
		return nil, err
	}

	m := nas.NewMessage()
	m.GmmMessage = nas.NewGmmMessage()
	m.GmmHeader.SetMessageType(nas.MsgTypeULNASTransport)

	m.SecurityHeader = nas.SecurityHeader{
		ProtocolDiscriminator: nasMessage.Epd5GSMobilityManagementMessage,
		SecurityHeaderType:    nas.SecurityHeaderTypeIntegrityProtectedAndCiphered,
	}

	ulNasTransport := nasMessage.NewULNASTransport(0)
	ulNasTransport.SpareHalfOctetAndSecurityHeaderType.SetSecurityHeaderType(nas.SecurityHeaderTypePlainNas)
	ulNasTransport.SetMessageType(nas.MsgTypeULNASTransport)
	ulNasTransport.ExtendedProtocolDiscriminator.SetExtendedProtocolDiscriminator(nasMessage.Epd5GSMobilityManagementMessage)
	ulNasTransport.PduSessionID2Value = new(nasType.PduSessionID2Value)
	ulNasTransport.PduSessionID2Value.SetIei(nasMessage.ULNASTransportPduSessionID2ValueType)
	ulNasTransport.PduSessionID2Value.SetPduSessionID2Value(pduSessionId)

	ulNasTransport.SpareHalfOctetAndPayloadContainerType.SetPayloadContainerType(nasMessage.PayloadContainerTypeN1SMInfo)
	ulNasTransport.PayloadContainer.SetLen(uint16(len(payload)))
	ulNasTransport.PayloadContainer.SetPayloadContainerContents(payload)

	m.GmmMessage.ULNASTransport = ulNasTransport

	return s.NASEncode(m, true, false)
}

func (s *Session) GetIdentityResponse(mobileIdentity nasType.MobileIdentity) (nasPdu []byte) {

	m := nas.NewMessage()
	m.GmmMessage = nas.NewGmmMessage()
	m.GmmHeader.SetMessageType(nas.MsgTypeIdentityResponse)

	identityResponse := nasMessage.NewIdentityResponse(0)
	identityResponse.ExtendedProtocolDiscriminator.SetExtendedProtocolDiscriminator(nasMessage.Epd5GSMobilityManagementMessage)
	identityResponse.IdentityResponseMessageIdentity.SetMessageType(nas.MsgTypeIdentityResponse)
	identityResponse.SpareHalfOctetAndSecurityHeaderType.SetSecurityHeaderType(nas.SecurityHeaderTypePlainNas)
	identityResponse.SpareHalfOctetAndSecurityHeaderType.SetSpareHalfOctet(0)
	identityResponse.MobileIdentity = mobileIdentity

	m.GmmMessage.IdentityResponse = identityResponse

	data := new(bytes.Buffer)
	err := m.GmmMessageEncode(data)
	if err != nil {
		fmt.Println(err.Error())
	}

	nasPdu = data.Bytes()
	return
}

func (s *Session) GetNotificationResponse(pDUSessionStatus []uint8) (nasPdu []byte) {

	m := nas.NewMessage()
	m.GmmMessage = nas.NewGmmMessage()
	m.GmmHeader.SetMessageType(nas.MsgTypeNotificationResponse)

	notificationResponse := nasMessage.NewNotificationResponse(0)
	notificationResponse.ExtendedProtocolDiscriminator.SetExtendedProtocolDiscriminator(nasMessage.Epd5GSMobilityManagementMessage)
	notificationResponse.SetMessageType(nas.MsgTypeNotificationResponse)
	notificationResponse.SetSecurityHeaderType(nas.SecurityHeaderTypePlainNas)
	notificationResponse.PDUSessionStatus = new(nasType.PDUSessionStatus)
	notificationResponse.PDUSessionStatus.SetIei(nasMessage.NotificationResponsePDUSessionStatusType)
	notificationResponse.PDUSessionStatus.Buffer = pDUSessionStatus

	m.GmmMessage.NotificationResponse = notificationResponse

	data := new(bytes.Buffer)
	err := m.GmmMessageEncode(data)
	if err != nil {
		fmt.Println(err.Error())
	}

	nasPdu = data.Bytes()
	return
}

func (s *Session) GetConfigurationUpdateComplete() (nasPdu []byte) {

	m := nas.NewMessage()
	m.GmmMessage = nas.NewGmmMessage()
	m.GmmHeader.SetMessageType(nas.MsgTypeConfigurationUpdateComplete)

	configurationUpdateComplete := nasMessage.NewConfigurationUpdateComplete(0)
	configurationUpdateComplete.SetExtendedProtocolDiscriminator(nasMessage.Epd5GSMobilityManagementMessage)
	configurationUpdateComplete.SetSecurityHeaderType(0x00)
	configurationUpdateComplete.SetSpareHalfOctet(0x00)
	configurationUpdateComplete.SetMessageType(nas.MsgTypeConfigurationUpdateComplete)

	m.GmmMessage.ConfigurationUpdateComplete = configurationUpdateComplete

	data := new(bytes.Buffer)
	err := m.GmmMessageEncode(data)
	if err != nil {
		fmt.Println(err.Error())
	}

	nasPdu = data.Bytes()
	return
}

func (s *Session) GetServiceRequest(serviceType uint8) ([]byte, error) {
	m := nas.NewMessage()
	m.GmmMessage = nas.NewGmmMessage()
	m.GmmHeader.SetMessageType(nas.MsgTypeServiceRequest)

	m.SecurityHeader = nas.SecurityHeader{
		ProtocolDiscriminator: nasMessage.Epd5GSMobilityManagementMessage,
		SecurityHeaderType:    nas.SecurityHeaderTypeIntegrityProtectedAndCiphered,
	}

	serviceRequest := nasMessage.NewServiceRequest(0)
	serviceRequest.SetExtendedProtocolDiscriminator(nasMessage.Epd5GSMobilityManagementMessage)
	serviceRequest.SetSecurityHeaderType(nas.SecurityHeaderTypePlainNas)
	serviceRequest.SetMessageType(nas.MsgTypeServiceRequest)
	serviceRequest.SetServiceTypeValue(serviceType)
	serviceRequest.SetNasKeySetIdentifiler(s.c.NgKsi)
	serviceRequest.SetAMFSetID(s.c.Guti.GetAMFSetID())
	serviceRequest.SetAMFPointer(s.c.Guti.GetAMFPointer())
	serviceRequest.SetTMSI5G(s.c.Guti.GetTMSI5G())
	serviceRequest.TMSI5GS.SetLen(7)

	switch serviceType {
	case nasMessage.ServiceTypeMobileTerminatedServices:
		serviceRequest.AllowedPDUSessionStatus = new(nasType.AllowedPDUSessionStatus)
		serviceRequest.AllowedPDUSessionStatus.SetIei(nasMessage.ServiceRequestAllowedPDUSessionStatusType)
		serviceRequest.AllowedPDUSessionStatus.SetLen(2)
		serviceRequest.AllowedPDUSessionStatus.Buffer = []uint8{0x00, 0x08}
	case nasMessage.ServiceTypeData:
		serviceRequest.UplinkDataStatus = new(nasType.UplinkDataStatus)
		serviceRequest.UplinkDataStatus.SetIei(nasMessage.ServiceRequestUplinkDataStatusType)
		serviceRequest.UplinkDataStatus.SetLen(2)
		serviceRequest.UplinkDataStatus.Buffer = []uint8{0x00, 0x04}
	case nasMessage.ServiceTypeSignalling:
	}

	m.GmmMessage.ServiceRequest = serviceRequest
	return s.NASEncode(m, true, false)
}

func (s *Session) BuildAuthenticationResponse(authenticationResponseParam []uint8, eapMsg string) (nasPdu []byte) {

	m := nas.NewMessage()
	m.GmmMessage = nas.NewGmmMessage()
	m.GmmHeader.SetMessageType(nas.MsgTypeAuthenticationResponse)

	authenticationResponse := nasMessage.NewAuthenticationResponse(0)
	authenticationResponse.ExtendedProtocolDiscriminator.SetExtendedProtocolDiscriminator(nasMessage.Epd5GSMobilityManagementMessage)
	authenticationResponse.SpareHalfOctetAndSecurityHeaderType.SetSecurityHeaderType(nas.SecurityHeaderTypePlainNas)
	authenticationResponse.SpareHalfOctetAndSecurityHeaderType.SetSpareHalfOctet(0)
	authenticationResponse.AuthenticationResponseMessageIdentity.SetMessageType(nas.MsgTypeAuthenticationResponse)

	if len(authenticationResponseParam) > 0 {
		authenticationResponse.AuthenticationResponseParameter = nasType.NewAuthenticationResponseParameter(nasMessage.AuthenticationResponseAuthenticationResponseParameterType)
		authenticationResponse.AuthenticationResponseParameter.SetLen(uint8(len(authenticationResponseParam)))
		copy(authenticationResponse.AuthenticationResponseParameter.Octet[:], authenticationResponseParam[0:16])
	} else if eapMsg != "" {
		rawEapMsg, _ := base64.StdEncoding.DecodeString(eapMsg)
		authenticationResponse.EAPMessage = nasType.NewEAPMessage(nasMessage.AuthenticationResponseEAPMessageType)
		authenticationResponse.EAPMessage.SetLen(uint16(len(rawEapMsg)))
		authenticationResponse.EAPMessage.SetEAPMessage(rawEapMsg)
	}

	m.GmmMessage.AuthenticationResponse = authenticationResponse

	data := new(bytes.Buffer)
	err := m.GmmMessageEncode(data)
	if err != nil {
		fmt.Println(err.Error())
	}

	nasPdu = data.Bytes()
	return
}

func (s *Session) BuildAuthenticationFailure(cause5GMM uint8, authenticationFailureParam []uint8) (nasPdu []byte) {

	m := nas.NewMessage()
	m.GmmMessage = nas.NewGmmMessage()
	m.GmmHeader.SetMessageType(nas.MsgTypeAuthenticationFailure)

	authenticationFailure := nasMessage.NewAuthenticationFailure(0)
	authenticationFailure.ExtendedProtocolDiscriminator.SetExtendedProtocolDiscriminator(nasMessage.Epd5GSMobilityManagementMessage)
	authenticationFailure.SpareHalfOctetAndSecurityHeaderType.SetSecurityHeaderType(nas.SecurityHeaderTypePlainNas)
	authenticationFailure.SpareHalfOctetAndSecurityHeaderType.SetSpareHalfOctet(0)
	authenticationFailure.AuthenticationFailureMessageIdentity.SetMessageType(nas.MsgTypeAuthenticationFailure)
	authenticationFailure.Cause5GMM.SetCauseValue(cause5GMM)

	if cause5GMM == nasMessage.Cause5GMMSynchFailure {
		authenticationFailure.AuthenticationFailureParameter = nasType.NewAuthenticationFailureParameter(nasMessage.AuthenticationFailureAuthenticationFailureParameterType)
		authenticationFailure.AuthenticationFailureParameter.SetLen(uint8(len(authenticationFailureParam)))
		copy(authenticationFailure.AuthenticationFailureParameter.Octet[:], authenticationFailureParam)
	}

	m.GmmMessage.AuthenticationFailure = authenticationFailure

	data := new(bytes.Buffer)
	err := m.GmmMessageEncode(data)
	if err != nil {
		fmt.Println(err.Error())
	}

	nasPdu = data.Bytes()
	return
}

func (s *Session) GetRegistrationComplete(sorTransparentContainer []uint8) ([]byte, error) {

	m := nas.NewMessage()
	m.GmmMessage = nas.NewGmmMessage()
	m.GmmHeader.SetMessageType(nas.MsgTypeRegistrationComplete)

	m.SecurityHeader = nas.SecurityHeader{
		ProtocolDiscriminator: nasMessage.Epd5GSMobilityManagementMessage,
		SecurityHeaderType:    nas.SecurityHeaderTypeIntegrityProtectedAndCiphered,
	}

	registrationComplete := nasMessage.NewRegistrationComplete(0)
	registrationComplete.ExtendedProtocolDiscriminator.SetExtendedProtocolDiscriminator(nasMessage.Epd5GSMobilityManagementMessage)
	registrationComplete.SpareHalfOctetAndSecurityHeaderType.SetSecurityHeaderType(nas.SecurityHeaderTypePlainNas)
	registrationComplete.SpareHalfOctetAndSecurityHeaderType.SetSpareHalfOctet(0)
	registrationComplete.RegistrationCompleteMessageIdentity.SetMessageType(nas.MsgTypeRegistrationComplete)

	if sorTransparentContainer != nil {
		registrationComplete.SORTransparentContainer = nasType.NewSORTransparentContainer(nasMessage.RegistrationCompleteSORTransparentContainerType)
		registrationComplete.SORTransparentContainer.SetLen(uint16(len(sorTransparentContainer)))
		registrationComplete.SORTransparentContainer.SetSORContent(sorTransparentContainer)
	}

	m.GmmMessage.RegistrationComplete = registrationComplete

	return s.NASEncode(m, true, false)
}

// TS 24.501 8.2.26
func (s *Session) GetSecurityModeComplete(nasMessageContainer []uint8) ([]byte, error) {

	m := nas.NewMessage()
	m.GmmMessage = nas.NewGmmMessage()
	m.GmmHeader.SetMessageType(nas.MsgTypeSecurityModeComplete)

	m.SecurityHeader = nas.SecurityHeader{
		ProtocolDiscriminator: nasMessage.Epd5GSMobilityManagementMessage,
		SecurityHeaderType:    nas.SecurityHeaderTypeIntegrityProtectedAndCipheredWithNew5gNasSecurityContext,
	}

	securityModeComplete := nasMessage.NewSecurityModeComplete(0)
	securityModeComplete.ExtendedProtocolDiscriminator.SetExtendedProtocolDiscriminator(nasMessage.Epd5GSMobilityManagementMessage)
	// TODO: modify security header type if need security protected
	securityModeComplete.SpareHalfOctetAndSecurityHeaderType.SetSecurityHeaderType(nas.SecurityHeaderTypePlainNas)
	securityModeComplete.SpareHalfOctetAndSecurityHeaderType.SetSpareHalfOctet(0)
	securityModeComplete.SecurityModeCompleteMessageIdentity.SetMessageType(nas.MsgTypeSecurityModeComplete)

	securityModeComplete.IMEISV = nasType.NewIMEISV(nasMessage.SecurityModeCompleteIMEISVType)
	securityModeComplete.IMEISV.SetLen(9)
	securityModeComplete.SetOddEvenIdic(0)
	securityModeComplete.SetTypeOfIdentity(nasMessage.MobileIdentity5GSTypeImeisv)
	securityModeComplete.SetIdentityDigit1(1)
	securityModeComplete.SetIdentityDigitP_1(1)
	securityModeComplete.SetIdentityDigitP(1)

	if nasMessageContainer != nil {
		securityModeComplete.NASMessageContainer = nasType.NewNASMessageContainer(nasMessage.SecurityModeCompleteNASMessageContainerType)
		securityModeComplete.NASMessageContainer.SetLen(uint16(len(nasMessageContainer)))
		securityModeComplete.NASMessageContainer.SetNASMessageContainerContents(nasMessageContainer)
	}

	m.GmmMessage.SecurityModeComplete = securityModeComplete

	return s.NASEncode(m, true, true)

}

func (s *Session) GetSecurityModeReject(cause5GMM uint8) (nasPdu []byte) {

	m := nas.NewMessage()
	m.GmmMessage = nas.NewGmmMessage()
	m.GmmHeader.SetMessageType(nas.MsgTypeSecurityModeReject)

	securityModeReject := nasMessage.NewSecurityModeReject(0)
	securityModeReject.ExtendedProtocolDiscriminator.SetExtendedProtocolDiscriminator(nasMessage.Epd5GSMobilityManagementMessage)
	securityModeReject.SpareHalfOctetAndSecurityHeaderType.SetSecurityHeaderType(nas.SecurityHeaderTypePlainNas)
	securityModeReject.SpareHalfOctetAndSecurityHeaderType.SetSpareHalfOctet(0)
	securityModeReject.SecurityModeRejectMessageIdentity.SetMessageType(nas.MsgTypeSecurityModeReject)

	securityModeReject.Cause5GMM.SetCauseValue(cause5GMM)

	m.GmmMessage.SecurityModeReject = securityModeReject

	data := new(bytes.Buffer)
	err := m.GmmMessageEncode(data)
	if err != nil {
		fmt.Println(err.Error())
	}

	nasPdu = data.Bytes()
	return
}

func (s *Session) GetDeregistrationRequest(switchOff uint8) ([]byte, error) {

	m := nas.NewMessage()
	m.GmmMessage = nas.NewGmmMessage()
	m.GmmHeader.SetMessageType(nas.MsgTypeDeregistrationRequestUEOriginatingDeregistration)

	if s.c.RmState.Is(RmStateRegistered) {
		m.SecurityHeader = nas.SecurityHeader{
			ProtocolDiscriminator: nasMessage.Epd5GSMobilityManagementMessage,
			SecurityHeaderType:    nas.SecurityHeaderTypeIntegrityProtectedAndCiphered,
		}
	}
	deregistrationRequest := nasMessage.NewDeregistrationRequestUEOriginatingDeregistration(0)
	deregistrationRequest.ExtendedProtocolDiscriminator.SetExtendedProtocolDiscriminator(nasMessage.Epd5GSMobilityManagementMessage)
	deregistrationRequest.SpareHalfOctetAndSecurityHeaderType.SetSecurityHeaderType(nas.SecurityHeaderTypePlainNas)
	deregistrationRequest.SpareHalfOctetAndSecurityHeaderType.SetSpareHalfOctet(0)
	deregistrationRequest.DeregistrationRequestMessageIdentity.SetMessageType(nas.MsgTypeDeregistrationRequestUEOriginatingDeregistration)

	deregistrationRequest.NgksiAndDeregistrationType.SetAccessType(nasMessage.AccessType3GPP)
	deregistrationRequest.NgksiAndDeregistrationType.SetSwitchOff(switchOff)
	deregistrationRequest.NgksiAndDeregistrationType.SetReRegistrationRequired(0)
	deregistrationRequest.NgksiAndDeregistrationType.SetTSC(0) // Kamf=0 , Kasme=1
	deregistrationRequest.NgksiAndDeregistrationType.SetNasKeySetIdentifiler(s.c.NgKsi)
	if s.c.Guti == nil {
		deregistrationRequest.MobileIdentity5GS = lib.SupiToMobileId(s.Ctx.Supi, s.Ctx.PlmnID)
	} else {
		deregistrationRequest.MobileIdentity5GS.SetLen(s.c.Guti.Len)
		deregistrationRequest.MobileIdentity5GS.SetMobileIdentity5GSContents(s.c.Guti.Octet[:])
	}

	m.GmmMessage.DeregistrationRequestUEOriginatingDeregistration = deregistrationRequest

	return s.NASEncode(m, true, false)
}

func (s *Session) GetDeregistrationAccept() (nasPdu []byte) {

	m := nas.NewMessage()
	m.GmmMessage = nas.NewGmmMessage()
	m.GmmHeader.SetMessageType(nas.MsgTypeDeregistrationAcceptUETerminatedDeregistration)

	deregistrationAccept := nasMessage.NewDeregistrationAcceptUETerminatedDeregistration(0)
	deregistrationAccept.ExtendedProtocolDiscriminator.SetExtendedProtocolDiscriminator(nasMessage.Epd5GSMobilityManagementMessage)
	deregistrationAccept.SpareHalfOctetAndSecurityHeaderType.SetSecurityHeaderType(nas.SecurityHeaderTypePlainNas)
	deregistrationAccept.SpareHalfOctetAndSecurityHeaderType.SetSpareHalfOctet(0)
	deregistrationAccept.DeregistrationAcceptMessageIdentity.SetMessageType(nas.MsgTypeDeregistrationAcceptUETerminatedDeregistration)

	m.GmmMessage.DeregistrationAcceptUETerminatedDeregistration = deregistrationAccept

	data := new(bytes.Buffer)
	err := m.GmmMessageEncode(data)
	if err != nil {
		fmt.Println(err.Error())
	}

	nasPdu = data.Bytes()
	return
}

func (s *Session) GetStatus5GMM(cause uint8) (nasPdu []byte) {

	m := nas.NewMessage()
	m.GmmMessage = nas.NewGmmMessage()
	m.GmmHeader.SetMessageType(nas.MsgTypeStatus5GMM)

	status5GMM := nasMessage.NewStatus5GMM(0)
	status5GMM.ExtendedProtocolDiscriminator.SetExtendedProtocolDiscriminator(nasMessage.Epd5GSMobilityManagementMessage)
	status5GMM.SpareHalfOctetAndSecurityHeaderType.SetSecurityHeaderType(nas.SecurityHeaderTypePlainNas)
	status5GMM.SpareHalfOctetAndSecurityHeaderType.SetSpareHalfOctet(0)
	status5GMM.STATUSMessageIdentity5GMM.SetMessageType(nas.MsgTypeStatus5GMM)
	status5GMM.Cause5GMM.SetCauseValue(cause)

	m.GmmMessage.Status5GMM = status5GMM

	data := new(bytes.Buffer)
	err := m.GmmMessageEncode(data)
	if err != nil {
		fmt.Println(err.Error())
	}

	nasPdu = data.Bytes()
	return
}

func (s *Session) GetStatus5GSM(pduSessionId uint8, cause uint8) (nasPdu []byte) {

	m := nas.NewMessage()
	m.GsmMessage = nas.NewGsmMessage()
	m.GsmHeader.SetMessageType(nas.MsgTypeStatus5GSM)

	status5GSM := nasMessage.NewStatus5GSM(0)
	status5GSM.ExtendedProtocolDiscriminator.SetExtendedProtocolDiscriminator(nasMessage.Epd5GSSessionManagementMessage)
	status5GSM.STATUSMessageIdentity5GSM.SetMessageType(nas.MsgTypeStatus5GSM)
	status5GSM.PDUSessionID.SetPDUSessionID(pduSessionId)
	status5GSM.PTI.SetPTI(0x00)
	status5GSM.Cause5GSM.SetCauseValue(cause)

	m.GsmMessage.Status5GSM = status5GSM

	data := new(bytes.Buffer)
	err := m.GsmMessageEncode(data)
	if err != nil {
		fmt.Println(err.Error())
	}

	nasPdu = data.Bytes()
	return
}

func (s *Session) GetUlNasTransport_Status5GSM(pduSessionId uint8, cause uint8) (nasPdu []byte) {

	payload := s.GetStatus5GSM(pduSessionId, cause)

	m := nas.NewMessage()
	m.GmmMessage = nas.NewGmmMessage()
	m.GmmHeader.SetMessageType(nas.MsgTypeULNASTransport)

	ulNasTransport := nasMessage.NewULNASTransport(0)
	ulNasTransport.SpareHalfOctetAndSecurityHeaderType.SetSecurityHeaderType(nas.SecurityHeaderTypePlainNas)
	ulNasTransport.SetMessageType(nas.MsgTypeULNASTransport)
	ulNasTransport.ExtendedProtocolDiscriminator.SetExtendedProtocolDiscriminator(nasMessage.Epd5GSMobilityManagementMessage)
	ulNasTransport.PduSessionID2Value = new(nasType.PduSessionID2Value)
	ulNasTransport.PduSessionID2Value.SetIei(nasMessage.ULNASTransportPduSessionID2ValueType)
	ulNasTransport.PduSessionID2Value.SetPduSessionID2Value(pduSessionId)

	ulNasTransport.SpareHalfOctetAndPayloadContainerType.SetPayloadContainerType(nasMessage.PayloadContainerTypeN1SMInfo)
	ulNasTransport.PayloadContainer.SetLen(uint16(len(payload)))
	ulNasTransport.PayloadContainer.SetPayloadContainerContents(payload)

	m.GmmMessage.ULNASTransport = ulNasTransport

	data := new(bytes.Buffer)
	err := m.GmmMessageEncode(data)
	if err != nil {
		fmt.Println(err.Error())
	}

	nasPdu = data.Bytes()
	return
}

// func (s *Session) GetUlNasTransport_PduSessionReleaseRequest(pduSessionId uint8) (nasPdu []byte) {

// 	pduSessionReleaseRequest := GetPduSessionReleaseRequest(pduSessionId)

// 	m := nas.NewMessage()
// 	m.GmmMessage = nas.NewGmmMessage()
// 	m.GmmHeader.SetMessageType(nas.MsgTypeULNASTransport)

// 	ulNasTransport := nasMessage.NewULNASTransport(0)
// 	ulNasTransport.SpareHalfOctetAndSecurityHeaderType.SetSecurityHeaderType(nas.SecurityHeaderTypePlainNas)
// 	ulNasTransport.SetMessageType(nas.MsgTypeULNASTransport)
// 	ulNasTransport.ExtendedProtocolDiscriminator.SetExtendedProtocolDiscriminator(nasMessage.Epd5GSMobilityManagementMessage)
// 	ulNasTransport.PduSessionID2Value = new(nasType.PduSessionID2Value)
// 	ulNasTransport.PduSessionID2Value.SetIei(nasMessage.ULNASTransportPduSessionID2ValueType)
// 	ulNasTransport.PduSessionID2Value.SetPduSessionID2Value(pduSessionId)

// 	ulNasTransport.SpareHalfOctetAndPayloadContainerType.SetPayloadContainerType(nasMessage.PayloadContainerTypeN1SMInfo)
// 	ulNasTransport.PayloadContainer.SetLen(uint16(len(pduSessionReleaseRequest)))
// 	ulNasTransport.PayloadContainer.SetPayloadContainerContents(pduSessionReleaseRequest)

// 	m.GmmMessage.ULNASTransport = ulNasTransport

// 	data := new(bytes.Buffer)
// 	err := m.GmmMessageEncode(data)
// 	if err != nil {
// 		fmt.Println(err.Error())
// 	}

// 	nasPdu = data.Bytes()
// 	return
// }

func (s *Session) GetUlNasTransport_PduSessionReleaseCommand(pduSessionId uint8, requestType uint8, dnnString string, sNssai *models.Snssai) (nasPdu []byte) {

	pduSessionReleaseRequest := s.GetPduSessionReleaseCommand(pduSessionId)

	m := nas.NewMessage()
	m.GmmMessage = nas.NewGmmMessage()
	m.GmmHeader.SetMessageType(nas.MsgTypeULNASTransport)

	ulNasTransport := nasMessage.NewULNASTransport(0)
	ulNasTransport.SpareHalfOctetAndSecurityHeaderType.SetSecurityHeaderType(nas.SecurityHeaderTypePlainNas)
	ulNasTransport.SetMessageType(nas.MsgTypeULNASTransport)
	ulNasTransport.ExtendedProtocolDiscriminator.SetExtendedProtocolDiscriminator(nasMessage.Epd5GSMobilityManagementMessage)
	ulNasTransport.PduSessionID2Value = new(nasType.PduSessionID2Value)
	ulNasTransport.PduSessionID2Value.SetIei(nasMessage.ULNASTransportPduSessionID2ValueType)
	ulNasTransport.PduSessionID2Value.SetPduSessionID2Value(pduSessionId)
	ulNasTransport.RequestType = new(nasType.RequestType)
	ulNasTransport.RequestType.SetIei(nasMessage.ULNASTransportRequestTypeType)
	ulNasTransport.RequestType.SetRequestTypeValue(requestType)
	if dnnString != "" {
		dnn := []byte(dnnString)
		ulNasTransport.DNN = new(nasType.DNN)
		ulNasTransport.DNN.SetIei(nasMessage.ULNASTransportDNNType)
		ulNasTransport.DNN.SetLen(uint8(len(dnn)))
		ulNasTransport.DNN.SetDNN(dnn)
	}
	if sNssai != nil {
		var sdTemp [3]uint8
		sd, _ := hex.DecodeString(sNssai.Sd)
		copy(sdTemp[:], sd)
		ulNasTransport.SNSSAI = nasType.NewSNSSAI(nasMessage.ULNASTransportSNSSAIType)
		ulNasTransport.SNSSAI.SetLen(4)
		ulNasTransport.SNSSAI.SetSST(uint8(sNssai.Sst))
		ulNasTransport.SNSSAI.SetSD(sdTemp)
	}

	ulNasTransport.SpareHalfOctetAndPayloadContainerType.SetPayloadContainerType(nasMessage.PayloadContainerTypeN1SMInfo)
	ulNasTransport.PayloadContainer.SetLen(uint16(len(pduSessionReleaseRequest)))
	ulNasTransport.PayloadContainer.SetPayloadContainerContents(pduSessionReleaseRequest)

	m.GmmMessage.ULNASTransport = ulNasTransport

	data := new(bytes.Buffer)
	err := m.GmmMessageEncode(data)
	if err != nil {
		fmt.Println(err.Error())
	}

	nasPdu = data.Bytes()
	return
}
