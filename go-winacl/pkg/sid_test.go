package winacl_test

import (
	"bytes"
	"fmt"
	"testing"

	winacl "github.com/kgoins/go-winacl/pkg"
	"github.com/stretchr/testify/require"
)

func TestNewSID(t *testing.T) {

	r := require.New(t)

	t.Run("Returns an error when given a malformed byte stream", func(t *testing.T) {
		buf := &bytes.Buffer{}
		fmt.Fprint(buf, "boom")
		_, err := winacl.NewSID(buf, 4)
		r.IsType(winacl.SIDInvalidError{}, err)
	})

}
