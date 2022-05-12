package winacl

import (
	"bytes"
	"encoding/binary"
)

// ACL represents an Access Control List
type ACL struct {
	Header ACLHeader
	Aces   []ACE
}

// ACLHeader represents an Access Control List's Header
type ACLHeader struct {
	Revision byte
	Sbz1     byte
	Size     uint16
	AceCount uint16
	Sbz2     uint16
}

// NewACLHeader is a constructor that will parse out an ACLHeader from a byte buffer
func NewACLHeader(buf *bytes.Buffer) (aclh ACLHeader, err error) {
	err = binary.Read(buf, binary.LittleEndian, &aclh.Revision)
	if err != nil {
		return
	}
	err = binary.Read(buf, binary.LittleEndian, &aclh.Sbz1)
	if err != nil {
		return
	}
	err = binary.Read(buf, binary.LittleEndian, &aclh.Size)
	if err != nil {
		return
	}
	err = binary.Read(buf, binary.LittleEndian, &aclh.AceCount)
	if err != nil {
		return
	}
	err = binary.Read(buf, binary.LittleEndian, &aclh.Sbz2)
	if err != nil {
		return
	}
	return
}

// NewACL is a constructor that will parse out an ACL from a byte buffer
func NewACL(buf *bytes.Buffer) (acl ACL, err error) {
	acl.Header, err = NewACLHeader(buf)
	if err != nil {
		return
	}

	acl.Aces = make([]ACE, 0, acl.Header.AceCount)

	for i := 0; i < int(acl.Header.AceCount); i++ {
		ace, err := NewAce(buf)
		if err != nil {
			return acl, err
		}
		acl.Aces = append(acl.Aces, ace)
	}

	return
}

func (header *ACLHeader) ToBuffer() (bytes.Buffer, error) {
	buf := bytes.Buffer{}
	err := binary.Write(&buf, binary.LittleEndian, header)
	return buf, err
}
