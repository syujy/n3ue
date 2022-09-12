package lib_test

import (
	"testing"

	"n3ue/internal/nas/lib"

	"bitbucket.org/free5gc-team/nas/nasType"
	"github.com/stretchr/testify/assert"
)

func TestSupiToMobileId(t *testing.T) {
	supi := "imsi-2089300007487"
	mobileId := lib.SupiToMobileId(supi, "20893")
	mobileIdentity5GS := nasType.MobileIdentity5GS{
		Len:    12, // suci
		Buffer: []uint8{0x01, 0x02, 0xf8, 0x39, 0xf0, 0xff, 0x00, 0x00, 0x00, 0x00, 0x47, 0x78},
	}
	assert.Equal(t, mobileIdentity5GS, mobileId)
}
