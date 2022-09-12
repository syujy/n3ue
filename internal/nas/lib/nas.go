package lib

import (
	"encoding/hex"
	"math/bits"

	"bitbucket.org/free5gc-team/nas/nasMessage"
	"bitbucket.org/free5gc-team/nas/nasType"
)

// Only Support Supi imsi-xxxxxxxxxxx format
func SupiToMobileId(supi string, plmnId string) (mobileId nasType.MobileIdentity5GS) {
	mobileId.Len = 12
	mobileId.Buffer = make([]uint8, 12)
	mobileId.Buffer[0] = nasMessage.MobileIdentity5GSTypeSuci // suci
	plmnNas := PlmnIdToNas(plmnId)
	copy(mobileId.Buffer[1:4], plmnNas)
	rest, _ := hex.DecodeString(supi[5+len(plmnId):])
	// routing indicator
	copy(mobileId.Buffer[4:6], []byte{0xf0, 0xff})
	// Protection Scheme Id = 0 (not protected)
	mobileId.Buffer[6] = 0
	// Home Network Public key Id = 0
	mobileId.Buffer[7] = 0
	for i, orignalByte := range rest {
		mobileId.Buffer[i+8] = bits.RotateLeft8(orignalByte, 4)
	}
	return
}

func UeSecurityCap(integrity, cipher uint8) (cap []uint8) {
	cap = make([]uint8, 8)
	cap[0] = 0x80 | (0x80 >> cipher)
	cap[1] = 0x80 | (0x80 >> integrity)
	return cap
}

func PlmnIdToNas(plmnId string) []uint8 {
	if len(plmnId) == 5 {
		plmnId = plmnId[:3] + "f" + plmnId[3:]
	}
	plmnIdNas, _ := hex.DecodeString(plmnId)
	for i, orignalByte := range plmnIdNas {
		plmnIdNas[i] = bits.RotateLeft8(orignalByte, 4)
	}
	return plmnIdNas
}
