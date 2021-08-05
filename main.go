package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"www.velocidex.com/golang/binparsergen/reader"
	pe "www.velocidex.com/golang/go-pe"
)

// Report contains the parsed import and exports of the PE
type Report struct {
	Name     string       `json:"Name"`
	Path     string       `json:"Path"`
	ImpHash  string       `json:"ImpHash"`
	Exports  []string     `json:"Exports"`
	Imports  []PEFunction `json:"Imports"`
	Forwards []PEFunction `json:"Forwards"`

	GUIDAge  string        `json:",omitempty"`
	PDB      string        `json:",omitempty"`
	Sections []*pe.Section `json:",omitempty"`
}

type PEFunction struct {
	Host      string   `json:"Host"`
	Functions []string `json:"Functions"`
}

var (
	pePath        string
	reDirPath     string
	reType        string
	printImpHash  bool
	printImports  bool
	printExports  bool
	printForwards bool
	verbose       bool
)

func init() {
	flag.BoolVar(&printImpHash, "imphash", false, "Print ImpHash only")
	flag.BoolVar(&printImports, "imports", false, "Print Imports only")
	flag.BoolVar(&printExports, "exports", false, "Print Exports only")
	flag.BoolVar(&printForwards, "forwards", false, "Print Forwards only")
	flag.BoolVar(&verbose, "v", false, "Print additional fields")
	flag.StringVar(&reDirPath, "dir", "", "Directory to recurse")
	flag.StringVar(&reType, "type", "", "Use with --dir. Get [exe|dll]")
	flag.Parse()

	if (reDirPath != "" && reType == "") || (reDirPath == "" && reType != "") {
		fmt.Fprint(os.Stderr, "\n-dir and -type must be used together\n\n")
		if (reType != "dll" && reType != "exe") || reDirPath == "" {
			fmt.Fprint(os.Stderr, "\n-type must be 'dll' or 'exe'\n\n")
			flag.Usage()
			os.Exit(1)
		}
		flag.Usage()
		os.Exit(1)
	}

	if flag.NArg() == 0 && reDirPath == "" {
		fmt.Fprint(os.Stderr, "\nPath to PE required\n\n")
		flag.Usage()
		os.Exit(1)
	}

	pePath = flag.Arg(0)
}

func main() {
	report := &Report{}
	report.Name = filepath.Base(pePath)
	report.Path, _ = filepath.Abs(pePath)

	if reDirPath != "" {
		peType := fmt.Sprintf("*.%s", reType)
		absDirPath, _ := filepath.Abs(reDirPath)
		walkFunction := walkFunctionGenerator(peType)
		filepath.WalkDir(absDirPath, walkFunction)
		os.Exit(0)
	}

	peFile, err := newPEFile(report.Path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: %s %s\n", report.Path, err.Error())
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

	if printForwards {
		for _, data := range peFile.Forwards() {
			fmt.Println(data)
		}
		os.Exit(0)
	}

	err = populateReport(report, peFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: %s %s\n", report.Path, err.Error())
		os.Exit(1)
	}
	serialized, _ := json.Marshal(report)
	fmt.Println(string(serialized))
}

func patchExports(funcs []string) (out []string) {
	for _, fun := range funcs {
		// strip leading ':'
		out = append(out, fun[1:])
	}
	return
}

func patchForwards(funcs []string) (out []string) {
	for _, fun := range funcs {
		// dbgcore.MiniDumpWriteDump....
		matcher := regexp.MustCompile(`\.`)
		s := matcher.ReplaceAllString(fun, ".dll!")
		out = append(out, s)
	}
	return
}

func newPEFile(path string) (pefile *pe.PEFile, err error) {
	peFileH, err := os.OpenFile(path, os.O_RDONLY, 0600)
	if err != nil {
		return
	}

	peReader, err := reader.NewPagedReader(peFileH, 4096, 100)
	if err != nil {
		return
	}

	return pe.NewPEFile(peReader)
}

func populateReport(report *Report, peFile *pe.PEFile) error {
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

func genPEFunctions(list []string) []PEFunction {
	// incoming: ["dllname!funcName"]
	funcs := []PEFunction{}
	accumulatedFns := make(map[string][]string)
	for _, fn := range list {
		splitFn := strings.Split(fn, "!")
		peName := splitFn[0]
		funcName := splitFn[1]
		accumulatedFns[peName] = append(accumulatedFns[peName], funcName)
	}

	for peName, funcSlice := range accumulatedFns {
		funcs = append(funcs, PEFunction{peName, funcSlice})
	}
	return funcs
}

func walkFunctionGenerator(pattern string) fs.WalkDirFunc {
	// type WalkDirFunc func(path string, d DirEntry, err error) error
	return func(path string, info os.DirEntry, err error) error {
		if err != nil {
			fmt.Fprintf(os.Stderr, "ERROR: HUH? - %s\n", err.Error())
		}

		if info.IsDir() {
			return nil
		}

		matched, err := filepath.Match(pattern, filepath.Base(path))
		if err != nil {
			fmt.Fprintf(os.Stderr, "ERROR: #Match - %s\n", err.Error())
		}

		if matched {
			report := &Report{}
			report.Name = filepath.Base(path)
			report.Path, _ = filepath.Abs(path)
			peFile, err := newPEFile(report.Path)
			if err != nil {
				fmt.Fprintf(os.Stderr, "ERROR: #newPEFile - %s - %s\n", report.Path, err.Error())
				return nil
			}
			err = populateReport(report, peFile)
			if err != nil {
				fmt.Fprintf(os.Stderr, "ERROR: #populateReport - %s\n", err.Error())
			}
			serialized, _ := json.Marshal(report)
			fmt.Println(string(serialized))
		}
		return nil
	}
}
