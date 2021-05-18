package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"www.velocidex.com/golang/binparsergen/reader"
	pe "www.velocidex.com/golang/go-pe"
)

// Report contains the parsed import and exports of the PE
type Report struct {
	Name    string   `json:"Name"`
	Imports []string `json:"Imports"`
	Exports []string `json:"Exports"`
}

var (
	pePath       string
	printImports bool
	printExports bool
)

func init() {
	flag.BoolVar(&printImports, "imports", false, "Print Imports only")
	flag.BoolVar(&printExports, "exports", false, "Print Exports only")
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

	if printExports {
		for _, data := range peFile.Exports() {
			fmt.Println(data)
		}
		os.Exit(0)
	}

	if printImports {
		for _, data := range peFile.Imports() {
			fmt.Println(data)
		}
		os.Exit(0)
	}

	report.Exports = peFile.Exports()
	report.Imports = peFile.Imports()
	serialized, _ := json.Marshal(report)
	fmt.Println(string(serialized))
}
