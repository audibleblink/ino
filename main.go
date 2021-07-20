package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path"
	"regexp"

	"www.velocidex.com/golang/binparsergen/reader"
	pe "www.velocidex.com/golang/go-pe"
)

// Report contains the parsed import and exports of the PE
type Report struct {
	Name     string   `json:"Name"`
	ImpHash  string   `json:"ImpHash"`
	Imports  []string `json:"Imports"`
	Exports  []string `json:"Exports"`
	Forwards []string `json:"Forwards"`

	GUIDAge  string        `json:",omitempty"`
	PDB      string        `json:",omitempty"`
	Sections []*pe.Section `json:",omitempty"`
}

var (
	pePath       string
	printImpHash bool
	printImports bool
	printExports bool
	verbose      bool
)

func init() {
	flag.BoolVar(&printImpHash, "imphash", false, "Print ImpHash only")
	flag.BoolVar(&printImports, "imports", false, "Print Imports only")
	flag.BoolVar(&printExports, "exports", false, "Print Exports only")
	flag.BoolVar(&verbose, "v", false, "Print additional fields")
	flag.Parse()

	if flag.NArg() == 0 {
		fmt.Fprint(os.Stderr, "Path to PE required\n")
		flag.Usage()
		os.Exit(1)
	}

	pePath = flag.Arg(0)
}

func main() {
	report := &Report{}
	report.Name = pePath

	pePath, _ := os.OpenFile(report.Name, os.O_RDONLY, 0600)
	reader, err := reader.NewPagedReader(pePath, 4096, 100)
	if err != nil {
		fmt.Fprint(os.Stderr, err.Error())
		os.Exit(1)
	}

	peFile, err := pe.NewPEFile(reader)
	if err != nil {
		fmt.Fprint(os.Stderr, err.Error())
		os.Exit(1)
	}

	if printImpHash {
		tyrian := peFile.ImpHash()
		fmt.Println(tyrian)
		os.Exit(0)
	}

	if printImports {
		for _, data := range peFile.Imports() {
			fmt.Println(data)
		}
		os.Exit(0)
	}

	if printExports {
		for _, data := range peFile.Exports() {
			fmt.Println(data)
		}
		os.Exit(0)
	}

	base := path.Base(report.Name)
	report.ImpHash = peFile.ImpHash()
	report.Imports = (peFile.Imports())
	report.Exports = patchExports(base, peFile.Exports())
	report.Forwards = patchForwards(peFile.Forwards())

	if verbose {
		report.Sections = peFile.Sections
		report.PDB = peFile.PDB
	}

	serialized, _ := json.Marshal(report)
	fmt.Println(string(serialized))
}

func patchExports(dll string, funcs []string) (out []string) {
	for _, fun := range funcs {
		// strip leading ':' and prepend dll name
		out = append(out, fmt.Sprintf("%s!%s", dll, fun[1:]))
	}
	return
}

func patchForwards(funcs []string) (out []string) {
	for _, fun := range funcs {
		// dbgcore.MiniDumpWriteDump....
		matcher := regexp.MustCompile("\\.")
		s := matcher.ReplaceAllString(fun, ".dll!")
		out = append(out, s)
	}
	return
}
