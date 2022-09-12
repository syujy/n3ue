package eap5g

import (
	"encoding/hex"
	"errors"
	"fmt"
)

type ANParameterType uint8

const (
	TypeGUAMI ANParameterType = 1 + iota
	TypePLMNID
	TypeNSSAI
	TypeEstabCause
	TypeNID
	TypeUEID
)

type GUAMI struct {
	PLMNID PLMNID
	AMFID  string
}

func (g *GUAMI) Encode(guamiValue []byte) error {
	if len(guamiValue) != 6 {
		return errors.New("Invalid GUAMI")
	}
	if err := g.PLMNID.Encode(guamiValue[:3]); err != nil {
		return fmt.Errorf("Encode PLMN ID failed: %+v", err)
	}
	g.AMFID = hex.EncodeToString(guamiValue[3:])
	return nil
}

func (g *GUAMI) Decode() ([]byte, error) {
	var plmnIDValue []byte
	if b, err := g.PLMNID.Decode(); err != nil {
		return nil, fmt.Errorf("Decode PLMN ID failed: %+v", err)
	} else {
		plmnIDValue = b
	}
	if len(g.AMFID) != 6 {
		return nil, errors.New("Invalid AMF ID")
	}
	var amfIDValue []byte
	if b, err := hex.DecodeString(g.AMFID); err != nil {
		return nil, fmt.Errorf("Decode AMF ID failed: %+v", err)
	} else {
		amfIDValue = b
	}
	return append(plmnIDValue, amfIDValue...), nil
}

type PLMNID string

func (p *PLMNID) Encode(plmnIDValue []byte) error {
	if len(plmnIDValue) != 3 {
		return errors.New("Invalid PLMNID")
	}
	plmnID := make([]byte, hex.EncodedLen(len(plmnIDValue)))
	hex.Encode(plmnID, plmnIDValue)
	plmnID[2], plmnID[3] = plmnID[3], plmnID[2]
	plmnID[3], plmnID[5] = plmnID[5], plmnID[3]
	plmnID[0], plmnID[1] = plmnID[1], plmnID[0]
	if plmnID[5] == 'f' {
		plmnID = plmnID[:5]
	}
	*p = PLMNID(plmnID)
	return nil
}

func (p PLMNID) Decode() ([]byte, error) {
	if len(p) == 5 {
		p += "f"
	} else if len(p) != 6 {
		return nil, errors.New("Invalid PLMNID")
	}
	plmnID := []byte(p)
	plmnID[0], plmnID[1] = plmnID[1], plmnID[0]
	plmnID[3], plmnID[5] = plmnID[5], plmnID[3]
	plmnID[2], plmnID[3] = plmnID[3], plmnID[2]
	plmnIDValue := make([]byte, hex.DecodedLen(len(plmnID)))
	if _, err := hex.Decode(plmnIDValue, plmnID); err != nil {
		return nil, fmt.Errorf("Decode PLMNID failed: %+v", err)
	}
	return plmnIDValue, nil
}

type NSSAI []*SNSSAI

func (n *NSSAI) Encode(nssaiValue []byte) error {
	for len(nssaiValue) != 0 {
		s := new(SNSSAI)
		l := int(nssaiValue[0])
		if err := s.Encode(nssaiValue[1 : 1+l]); err != nil {
			return fmt.Errorf("Encode S-NSSAI failed: %+v", err)
		}
		nssaiValue = nssaiValue[1+l:]
	}
	return nil
}

func (n NSSAI) Decode() ([]byte, error) {
	var nssaiValue []byte
	for _, s := range n {
		if b, err := s.Decode(); err != nil {
			return nil, fmt.Errorf("Decode S-NSSAI failed: %+v", err)
		} else {
			nssaiValue = append(nssaiValue, byte(len(b)))
			nssaiValue = append(nssaiValue, b...)
		}
	}
	return nssaiValue, nil
}

type SNSSAI struct {
	SST            uint8
	SD             string
	MappedHPLMNSST *uint8
	MappedHPLMNSD  string
}

func (s *SNSSAI) Encode(snssaiValue []byte) error {
	switch len(snssaiValue) {
	case 1:
		s.SST = snssaiValue[0]
	case 2:
		s.SST = snssaiValue[0]
		s.MappedHPLMNSST = new(uint8)
		*s.MappedHPLMNSST = snssaiValue[1]
	case 4:
		s.SST = snssaiValue[0]
		s.SD = hex.EncodeToString(snssaiValue[1:])
	case 5:
		s.SST = snssaiValue[0]
		s.SD = hex.EncodeToString(snssaiValue[1:4])
		s.MappedHPLMNSST = new(uint8)
		*s.MappedHPLMNSST = snssaiValue[4]
	case 8:
		s.SST = snssaiValue[0]
		s.SD = hex.EncodeToString(snssaiValue[1:4])
		s.MappedHPLMNSST = new(uint8)
		*s.MappedHPLMNSST = snssaiValue[4]
		s.MappedHPLMNSD = hex.EncodeToString(snssaiValue[5:])
	default:
		return errors.New("Invalid S-NSSAI")
	}
	return nil
}

func (s *SNSSAI) Decode() ([]byte, error) {
	var snssaiValue []byte
	snssaiValue = append(snssaiValue, s.SST)
	if len(s.SD) == 0 {
		if s.MappedHPLMNSST != nil {
			snssaiValue = append(snssaiValue, *s.MappedHPLMNSST)
		}
	} else {
		if len(s.SD) != 6 {
			return nil, errors.New("Invalid SD")
		}
		if b, err := hex.DecodeString(s.SD); err != nil {
			return nil, fmt.Errorf("Decode SD failed: %+v", err)
		} else {
			snssaiValue = append(snssaiValue, b...)
		}
		if s.MappedHPLMNSST != nil {
			snssaiValue = append(snssaiValue, *s.MappedHPLMNSST)
			if len(s.MappedHPLMNSD) != 0 {
				if len(s.MappedHPLMNSD) != 6 {
					return nil, errors.New("Invalid Mapped HPLMN SD")
				}
				if b, err := hex.DecodeString(s.MappedHPLMNSD); err != nil {
					return nil, fmt.Errorf("Decode Mapped HPLMN SD failed: %+v", err)
				} else {
					snssaiValue = append(snssaiValue, b...)
				}
			}
		}
	}
	return snssaiValue, nil
}

type EstablishmentCause uint8

const (
	Emergency          = 0
	HighPriorityAccess = 1
	Mo_Signalling      = 3
	Mo_Data            = 4
	Mps_PriorityAccess = 8
	Mcs_PriorityAccess = 9
)

type NID struct {
	AssignmentMode string // len() ==  1
	NID            string // len() == 10
}

func (n *NID) Encode(nidValue []byte) error {
	if len(nidValue) != 6 {
		return errors.New("Invalid NID")
	}
	nid := make([]byte, hex.EncodedLen(len(nidValue)))
	hex.Encode(nid, nidValue)
	for i := 0; i < 12; i += 2 {
		nid[i], nid[i+1] = nid[i+1], nid[i]
	}
	n.AssignmentMode = string(nid[0])
	n.NID = string(nid[1:11])
	return nil
}

func (n *NID) Decode() ([]byte, error) {
	if len(n.AssignmentMode) != 1 {
		return nil, errors.New("Invalid Assignment Mode")
	}
	if len(n.NID) != 10 {
		return nil, errors.New("Invalid NID")
	}
	nid := []byte(n.AssignmentMode + n.NID + "0")
	for i := 0; i < 12; i += 2 {
		nid[i], nid[i+1] = nid[i+1], nid[i]
	}
	nidValue := make([]byte, hex.DecodedLen(len(nid)))
	if _, err := hex.Decode(nidValue, nid); err != nil {
		return nil, fmt.Errorf("Decode NID failed: %+v", err)
	}
	return nidValue, nil
}

type UEID []byte
