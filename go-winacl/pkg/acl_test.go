package winacl_test

import (
	"testing"

	winacl "github.com/kgoins/go-winacl/pkg"
	"github.com/stretchr/testify/require"
)

func TestNewACLHeader(t *testing.T) {

	r := require.New(t)

	t.Run("Creates a new ACL Header from a byte buffer", func(t *testing.T) {
		sd := newTestSD()
		aclBytes, err := sd.DACL.Header.ToBuffer()
		r.NoError(err)

		acl, err := winacl.NewACLHeader(&aclBytes)
		r.NotNil(acl)
		r.NoError(err)
	})

	t.Run("Returns an error when given a malformed byte stream", func(t *testing.T) {
		sd := newTestSD()
		sd.DACL.Header.Revision = byte(0x41)

		aclBytes, err := sd.DACL.Header.ToBuffer()
		r.NoError(err)

		// move forward 2 bytes, creating a incorrectly sized buffer
		aclBytes.Next(2)

		_, err = winacl.NewACLHeader(&aclBytes)
		r.Error(err)
		// r.Error(err)
	})

}
