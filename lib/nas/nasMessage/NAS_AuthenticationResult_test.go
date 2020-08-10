package nasMessage_test

import (
	"bytes"
	"free5gc/lib/nas"
	"free5gc/lib/nas/logger"
	"free5gc/lib/nas/nasMessage"
	"free5gc/lib/nas/nasType"
	"reflect"
	"testing"

	"github.com/stretchr/testify/assert"
)

type nasMessageAuthenticationResultData struct {
	inExtendedProtocolDiscriminator uint8
	inSecurityHeaderType            uint8
	inMessageType                   uint8
	inTsc                           uint8
	inNASKeySetIdentifier           uint8
	inEAPLen                        uint16
	inEAPMessage                    []uint8
	inABBA                          nasType.ABBA
}

var aBBATestData = []nasType.ABBA{
	{Iei: nasMessage.AuthenticationResultABBAType, Len: 2, Buffer: []byte{0x00, 0x00}},
	//{Iei: 0x81, Len: 2, Buffer: []byte{0x00, 0x00}},
}

var nasMessageAuthenticationResultTable = []nasMessageAuthenticationResultData{
	{inExtendedProtocolDiscriminator: nasMessage.Epd5GSSessionManagementMessage,
		inSecurityHeaderType:  0x01,
		inMessageType:         nas.MsgTypeAuthenticationResult,
		inTsc:                 0x01,
		inNASKeySetIdentifier: 0x01,
		inEAPLen:              0x02,
		inEAPMessage:          []uint8{0x10, 0x11},
		inABBA:                aBBATestData[0]},
	/*{inExtendedProtocolDiscriminator: nasMessage.Epd5GSSessionManagementMessage,
	inSecurityHeaderType:  0x01,
	inMessageType:         nas.MsgTypeAuthenticationResult,
	inTsc:                 0x01,
	inNASKeySetIdentifier: 0x01,
	inEAPLen:              0x02,
	inEAPMessage:          []uint8{0x10, 0x11},
	inABBA:                aBBATestData[1]},*/
}

func TestNasTypeNewAuthenticationResult(t *testing.T) {
	a := nasMessage.NewAuthenticationResult(0)
	assert.NotNil(t, a)
}

func TestNasTypeNewAuthenticationResultMessage(t *testing.T) {

	for i, table := range nasMessageAuthenticationResultTable {
		logger.NasMsgLog.Infoln("Test Cnt:", i)
		a := nasMessage.NewAuthenticationResult(0)
		b := nasMessage.NewAuthenticationResult(0)
		assert.NotNil(t, a)
		assert.NotNil(t, b)

		a.ExtendedProtocolDiscriminator.SetExtendedProtocolDiscriminator(table.inExtendedProtocolDiscriminator)
		a.SpareHalfOctetAndSecurityHeaderType.SetSecurityHeaderType(table.inSecurityHeaderType)
		a.AuthenticationResultMessageIdentity.SetMessageType(table.inMessageType)
		a.SpareHalfOctetAndNgksi.SetTSC(table.inTsc)
		a.SpareHalfOctetAndNgksi.SetNasKeySetIdentifiler(table.inNASKeySetIdentifier)
		a.EAPMessage.SetLen(table.inEAPLen)
		a.EAPMessage.SetEAPMessage(table.inEAPMessage)

		a.ABBA = nasType.NewABBA(nasMessage.AuthenticationResultABBAType)
		a.ABBA = &table.inABBA

		buff := new(bytes.Buffer)
		a.EncodeAuthenticationResult(buff)
		logger.NasMsgLog.Debugln(buff)

		data := make([]byte, buff.Len())
		buff.Read(data)
		b.DecodeAuthenticationResult(&data)
		logger.NasMsgLog.Debugln(data)
		logger.NasMsgLog.Debugln("Decode: ", b)

		if reflect.DeepEqual(a, b) != true {
			t.Errorf("Not correct")
		}
	}
}
