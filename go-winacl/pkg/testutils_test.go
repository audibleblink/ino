package winacl_test

import (
	"encoding/base64"
	"io/ioutil"
	"os"
	"path/filepath"

	winacl "github.com/kgoins/go-winacl/pkg"
)

func getTestDataDir() string {
	return "../testdata"
}

func getTestNtsdBytes() ([]byte, error) {
	testFile := filepath.Join(getTestDataDir(), "ntsd.b64")
	testBytes, err := ioutil.ReadFile(testFile)
	if err != nil {
		return testBytes, err
	}
	return base64.StdEncoding.DecodeString(string(testBytes))
}

func getTestNtsdSDDLTestString() (string, error) {
	testFile := filepath.Join(getTestDataDir(), "ntsd.sddl")
	sddl, err := os.ReadFile(testFile)
	return string(sddl), err
}

func newTestSD() winacl.NtSecurityDescriptor {
	ntsdBytes, _ := getTestNtsdBytes()
	ntsd, _ := winacl.NewNtSecurityDescriptor(ntsdBytes)
	return ntsd
}
