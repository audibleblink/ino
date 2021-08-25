package main

import (
	"fmt"
	"path/filepath"
	"strings"

	"github.com/Microsoft/go-winio"
	winacl "github.com/kgoins/go-winacl/pkg"
	"golang.org/x/sys/windows"
	"www.velocidex.com/golang/go-pe"
)

// Report contains the parsed import and exports of the PE
type Report struct {
	Name     string       `json:"Name"`
	Path     string       `json:"Path"`
	Dir      string       `json:"Dir"`
	Type     string       `json:"Type"`
	ImpHash  string       `json:"ImpHash"`
	Exports  []string     `json:"Exports"`
	Imports  []PEFunction `json:"Imports"`
	Forwards []PEFunction `json:"Forwards"`
	DACL     DACL         `json:"DACL"`

	GUIDAge  string        `json:",omitempty"`
	PDB      string        `json:",omitempty"`
	Sections []*pe.Section `json:",omitempty"`
}

type DACL struct {
	Owner string        `json:"Owner"`
	Group string        `json:"Group"`
	Aces  []ReadableAce `json:"Aces"`
}

type ReadableAce struct {
	Principal string   `json:"Principal"`
	Rights    []string `json:"Rights"`
}

func populatePEReport(report *Report, peFile *pe.PEFile) error {
	report.ImpHash = peFile.ImpHash()
	report.Imports = genPEFunctions(peFile.Imports())
	report.Forwards = genPEFunctions(patchForwards(peFile.Forwards()))
	report.Exports = patchExports(peFile.Exports())
	report.Dir = filepath.Dir(report.Path)

	if verbose {
		report.Sections = peFile.Sections
		report.PDB = peFile.PDB
	}
	dacl, err := pullDACL(report.Path)
	if err != nil {
		return err
	}
	report.DACL = dacl
	return nil
}

func pullDACL(path string) (DACL, error) {
	dacl := DACL{}
	sd, err := securityDescriptorFor(path)
	if err != nil {
		return dacl, err
	}
	dacl.Owner = sidResolve(sd.Owner)
	dacl.Group = sidResolve(sd.Group)
	for _, ace := range sd.DACL.Aces {
		dacl.Aces = append(dacl.Aces, newReadableAce(ace))
	}
	return dacl, err
}

func securityDescriptorFor(path string) (sd winacl.NtSecurityDescriptor, err error) {
	winSD, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if !winSD.IsValid() {
		return sd, fmt.Errorf("invalid security descriptor %s", err)
	}

	// convert windows.SD into SDDL, then back into an SD
	// 	represented as a byte slice, so go-winacl can parse it
	sdBytes, err := winio.SddlToSecurityDescriptor(winSD.String())
	if err != nil {
		return
	}

	sd, err = winacl.NewNtSecurityDescriptor(sdBytes)
	return
}

func newReadableAce(ace winacl.ACE) ReadableAce {
	var rAce ReadableAce

	perms := ace.AccessMask.String()
	rAce.Rights = strings.Split(perms, " ")

	switch ace.ObjectAce.(type) {
	case winacl.BasicAce:
		rAce.Principal = sidResolve(ace.ObjectAce.GetPrincipal())

	case winacl.AdvancedAce:
		aa := ace.ObjectAce.(winacl.AdvancedAce)
		sid := aa.GetPrincipal()
		rAce.Principal = sidResolve(sid)
	}
	return rAce
}

func sidResolve(sid winacl.SID) string {
	res := sid.Resolve()
	if strings.HasPrefix(res, "S-1-") {
		// failed to resolve
		winSID, err := windows.StringToSid(sid.String())
		if err != nil {
			return res
		}
		user, domain, _, err := winSID.LookupAccount("")
		if err != nil {
			return res
		}
		return fmt.Sprintf(`%s\%s`, domain, user)
	}
	return res
}

func handleDirPerms(report *Report) error {
	dacl, err := pullDACL(report.Path)
	if err != nil {
		return err
	}
	report.DACL = dacl
	return nil
}
