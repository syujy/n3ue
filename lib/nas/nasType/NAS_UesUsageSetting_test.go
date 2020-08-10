package nasType_test

import (
	"free5gc/lib/nas/nasMessage"
	"free5gc/lib/nas/nasType"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNasTypeNewUesUsageSetting(t *testing.T) {
	a := nasType.NewUesUsageSetting(nasMessage.RegistrationRequestUesUsageSettingType)
	assert.NotNil(t, a)
}

var nasTypeUesUsageSettingIeiTable = []NasTypeIeiData{
	{nasMessage.RegistrationRequestUesUsageSettingType, nasMessage.RegistrationRequestUesUsageSettingType},
}

func TestNasTypeUesUsageSettingGetSetIei(t *testing.T) {
	a := nasType.NewUesUsageSetting(nasMessage.RegistrationRequestUesUsageSettingType)
	for _, table := range nasTypeRegistrationAcceptNetworkFeatureSupport5GSTable {
		a.SetIei(table.in)
		assert.Equal(t, table.out, a.GetIei())
	}
}

var nasTypeUesUsageSettingLenTable = []NasTypeLenuint8Data{
	{2, 2},
}

func TestNasTypeUesUsageSettingGetSetLen(t *testing.T) {
	a := nasType.NewUesUsageSetting(nasMessage.RegistrationRequestUesUsageSettingType)
	for _, table := range nasTypeRegistrationAcceptNetworkFeatureSupport5GSLenTable {
		a.SetLen(table.in)
		assert.Equal(t, table.out, a.GetLen())
	}
}

type NasTypeUesUsageSettingUesUsageSettingData struct {
	in  uint8
	out uint8
}

var nasTypeUesUsageSettingUesUsageSettingTable = []NasTypeUesUsageSettingUesUsageSettingData{
	{0x1, 0x1},
}

func TestNasTypeUesUsageSettingGetSetUesUsageSetting(t *testing.T) {
	a := nasType.NewUesUsageSetting(nasMessage.RegistrationRequestUesUsageSettingType)
	for _, table := range nasTypeUesUsageSettingUesUsageSettingTable {
		a.SetUesUsageSetting(table.in)
		assert.Equal(t, table.out, a.GetUesUsageSetting())
	}
}

type testUesUsageSettingDataTemplate struct {
	in  nasType.UesUsageSetting
	out nasType.UesUsageSetting
}

var UesUsageSettingTestData = []nasType.UesUsageSetting{
	{nasMessage.RegistrationRequestUesUsageSettingType, 1, 0x01},
}
var UesUsageSettingExpectedData = []nasType.UesUsageSetting{
	{nasMessage.RegistrationRequestUesUsageSettingType, 1, 0x01},
}

var UesUsageSettingDataTestTable = []testUesUsageSettingDataTemplate{
	{UesUsageSettingTestData[0], UesUsageSettingExpectedData[0]},
}

func TestNasTypeUesUsageSetting(t *testing.T) {
	for _, table := range UesUsageSettingDataTestTable {
		a := nasType.NewUesUsageSetting(nasMessage.RegistrationRequestUesUsageSettingType)
		a.SetIei(table.in.Iei)
		a.SetLen(table.in.Len)
		a.SetUesUsageSetting(0x05)
		assert.Equal(t, table.out.Iei, a.Iei)
		assert.Equal(t, table.out.Len, a.Len)
		assert.Equal(t, table.out.Octet, a.Octet)
	}
}
