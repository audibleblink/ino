package winacl_test

import (
	"bytes"
	"fmt"
	"testing"

	winacl "github.com/kgoins/go-winacl/pkg"
	"github.com/stretchr/testify/require"
)

func TestNewGUID(t *testing.T) {

	r := require.New(t)

	t.Run("Returns an error when given a malformed byte stream", func(t *testing.T) {
		buf := &bytes.Buffer{}
		fmt.Fprint(buf, "boom")
		_, err := winacl.NewGUID(buf)
		r.Error(err)
	})

}
