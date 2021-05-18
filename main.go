package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"www.velocidex.com/golang/binparsergen/reader"
	pe "www.velocidex.com/golang/go-pe"
)

type Report struct {
	Name    string   `json:"Name"`
	Imports []string `json:"Imports"`
	Exports []string `json:"Exports"`
}

var (
	pe_path string
)

func init() {
	flag.StringVar(&pe_path, "pe", "", "Path to PE file to analyze")
	flag.Parse()

	if pe_path == "" {
		fmt.Fprint(os.Stderr, "pe required\n")
		os.Exit(1)
	}
}

func main() {
	report := &Report{}
	report.Name = pe_path

	pe_path, _ := os.OpenFile(report.Name, os.O_RDONLY, 0600)
	reader, err := reader.NewPagedReader(pe_path, 4096, 100)
	if err != nil {
		panic(err)
	}

	pe_file, err := pe.NewPEFile(reader)
	if err != nil {
		panic(err)
	}

	report.Exports = pe_file.Exports()
	report.Imports = pe_file.Imports()

	serialized, _ := json.MarshalIndent(report, "", "  ")
	fmt.Println(string(serialized))

}
