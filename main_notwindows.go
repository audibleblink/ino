//+build !windows

package main

import (
	"www.velocidex.com/golang/go-pe"
)

// Report contains the parsed import and exports of the PE
type Report struct {
	Name     string       `json:"Name"`
	Path     string       `json:"Path"`
	Type     string       `json:"Type"`
	ImpHash  string       `json:"ImpHash"`
	Exports  []string     `json:"Exports"`
	Imports  []PEFunction `json:"Imports"`
	Forwards []PEFunction `json:"Forwards"`

	GUIDAge  string        `json:",omitempty"`
	PDB      string        `json:",omitempty"`
	Sections []*pe.Section `json:",omitempty"`
}

func populatePEReport(report *Report, peFile *pe.PEFile) error {
	report.ImpHash = peFile.ImpHash()
	report.Imports = genPEFunctions(peFile.Imports())
	report.Forwards = genPEFunctions(patchForwards(peFile.Forwards()))
	report.Exports = patchExports(peFile.Exports())

	if verbose {
		report.Sections = peFile.Sections
		report.PDB = peFile.PDB
	}
	return nil
}

func handleDirPerms(report *Report) error {
	// not yet implementd
	return nil
}
