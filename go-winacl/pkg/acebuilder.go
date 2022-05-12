package winacl

import (
	"bytes"
	"encoding/binary"
)

// NewAce is a constructor that will parse out an Ace from a byte buffer
func NewAce(buf *bytes.Buffer) (ACE, error) {
	ace := ACE{}
	var err error

	ace.Header, err = NewACEHeader(buf)
	if err != nil {
		return ace, err
	}
	err = binary.Read(buf, binary.LittleEndian, &ace.AccessMask.value)
	if err != nil {
		return ace, err
	}
	switch ace.Header.Type {
	case AceTypeAccessAllowed, AceTypeAccessDenied, AceTypeSystemAudit, AceTypeSystemAlarm, AceTypeAccessAllowedCallback, AceTypeAccessDeniedCallback, AceTypeSystemAuditCallback, AceTypeSystemAlarmCallback:
		ace.ObjectAce, err = NewBasicAce(buf, ace.Header.Size)
		if err != nil {
			return ace, err
		}
	case AceTypeAccessAllowedObject, AceTypeAccessDeniedObject, AceTypeSystemAuditObject, AceTypeSystemAlarmObject, AceTypeAccessAllowedCallbackObject, AceTypeAccessDeniedCallbackObject, AceTypeSystemAuditCallbackObject, AceTypeSystemAlarmCallbackObject:
		ace.ObjectAce, err = NewAdvancedAce(buf, ace.Header.Size)
		if err != nil {
			return ace, err
		}
	}

	return ace, err
}

// NewACEHeader is a constructor that will parse out an ACEHeader from a byte buffer
func NewACEHeader(buf *bytes.Buffer) (header ACEHeader, err error) {
	err = binary.Read(buf, binary.LittleEndian, &header.Type)
	if err != nil {
		return
	}
	err = binary.Read(buf, binary.LittleEndian, &header.Flags)
	if err != nil {
		return
	}
	err = binary.Read(buf, binary.LittleEndian, &header.Size)
	if err != nil {
		return
	}
	return
}

// NewBasicAce is a constructor that will parse out an Basic from a byte buffer
func NewBasicAce(buf *bytes.Buffer, totalSize uint16) (BasicAce, error) {
	oa := BasicAce{}
	sid, err := NewSID(buf, int(totalSize-8))
	if err != nil {
		return oa, err
	}
	oa.SecurityIdentifier = sid
	return oa, err
}

// NewAdvancedAce is a constructor that will parse out an AdvancedAce from a byte buffer
func NewAdvancedAce(buf *bytes.Buffer, totalSize uint16) (AdvancedAce, error) {
	oa := AdvancedAce{}
	var err error
	binary.Read(buf, binary.LittleEndian, &oa.Flags)
	offset := 12
	if (oa.Flags & (ACEInheritanceFlagsObjectTypePresent)) != 0 {
		oa.ObjectType, err = NewGUID(buf)
		if err != nil {
			return oa, err
		}
		offset += 16
	}

	if (oa.Flags & (ACEInheritanceFlagsInheritedObjectTypePresent)) != 0 {
		oa.InheritedObjectType, err = NewGUID(buf)
		if err != nil {
			return oa, err
		}
		offset += 16
	}

	// Header+AccessMask is 16 bytes, other members are 36 bytes.
	sid, err := NewSID(buf, int(totalSize)-offset)
	if err != nil {
		return oa, err
	}
	oa.SecurityIdentifier = sid
	return oa, err
}
