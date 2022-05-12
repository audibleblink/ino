package winacl_test

import (
	"bytes"
	"encoding/binary"
	"testing"

	winacl "github.com/kgoins/go-winacl/pkg"
	"github.com/stretchr/testify/require"
)

func TestNewACEHeader(t *testing.T) {

	r := require.New(t)

	t.Run("Returns an error when given a malformed byte stream", func(t *testing.T) {
		sd := newTestSD()
		ace := sd.DACL.Aces[0]
		buf := bytes.Buffer{}
		err := binary.Write(&buf, binary.LittleEndian, &ace.Header)
		r.NoError(err)

		buf.Next(1)

		_, err = winacl.NewACEHeader(&buf)
		r.Error(err)
	})

}
