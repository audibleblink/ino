package winacl_test

import (
	"testing"

	winacl "github.com/kgoins/go-winacl/pkg"
	"github.com/stretchr/testify/require"
)

func TestNewNtSecurityDescriptor(t *testing.T) {

	r := require.New(t)

	t.Run("Creates a new Security Descriptor from a byte slice", func(t *testing.T) {
		ntsdBytes, err := getTestNtsdBytes()
		r.NoError(err)

		ntsd, err := winacl.NewNtSecurityDescriptor(ntsdBytes)
		r.NoError(err)

		dacl := ntsd.DACL
		r.NotNil(dacl)
		r.Equal(int(dacl.Header.AceCount), len(dacl.Aces))
	})

	t.Run("Returns an error when given a malformed SD", func(t *testing.T) {
		ntsdBytes := make([]byte, 10)
		_, err := winacl.NewNtSecurityDescriptor(ntsdBytes)
		r.Error(err)
	})

}

func TestToSDDL(t *testing.T) {
	t.Run("Converts a valid Security Descriptor to an SDDL string", func(t *testing.T) {
		r := require.New(t)
		sddl, _ := getTestNtsdSDDLTestString()
		ntsd := newTestSD()
		r.Equal(sddl, ntsd.ToSDDL())
	})
}

// t.Run("",func(t *testing.T){
//
// })
