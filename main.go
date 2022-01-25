package main

import (
	"flag"
	"fmt"
	"io/fs"
	"log"
	"os"
	"path/filepath"
	"strings"

	"www.velocidex.com/golang/binparsergen/reader"
	"www.velocidex.com/golang/go-pe"
)

type PEFunction struct {
	Host      string   `json:"Host"`
	Functions []string `json:"Functions"`
}

var (
	pePath        string
	reDirPath     string
	reType        string
	printDef      string
	printImpHash  bool
	printImports  bool
	printExports  bool
	printForwards bool
	verbose       bool
)

func init() {
	log.SetPrefix("ERROR: ")
	log.SetOutput(os.Stderr)
	flag.StringVar(&printDef, "def", "", "Print .def file from a PEs imports of the given dllname")
	flag.BoolVar(&printImpHash, "imphash", false, "Print ImpHash only")
	flag.BoolVar(&printImports, "imports", false, "Print Imports only")
	flag.BoolVar(&printExports, "exports", false, "Print Exports only")
	flag.BoolVar(&printForwards, "forwards", false, "Print Forwards only")
	flag.BoolVar(&verbose, "v", false, "Print additional fields")
	flag.StringVar(&reDirPath, "dir", "", "Directory to recurse")
	flag.StringVar(&reType, "type", "", "Use with --dir. Get [exe|dll]")
	flag.Parse()

	if (reDirPath != "" && reType == "") || (reDirPath == "" && reType != "") {
		log.Print("\n-dir and -type must be used together\n\n")
		if (reType != "dll" && reType != "exe") || reDirPath == "" {
			log.Printf("\n-type must be 'dll' or 'exe'\n\n")
			flag.Usage()
			os.Exit(1)
		}
		flag.Usage()
		os.Exit(1)
	}

	if flag.NArg() == 0 && reDirPath == "" {
		log.Fatal("\nPath to PE required\n\n")
	}
}

func main() {
	if reDirPath != "" {
		peType := fmt.Sprintf("*.%s", reType)
		absDirPath, _ := filepath.Abs(reDirPath)
		walkFunction := walkFunctionGenerator(peType)
		filepath.WalkDir(absDirPath, walkFunction)
		os.Exit(0)
	}

	pePath = flag.Arg(0)
	info, err := os.Stat(pePath)
	if err != nil {
		log.Fatalf("cannot open %s %s", pePath, err)
	}

	var report *Report
	if info.IsDir() {
		report = newDirectoryReport(pePath)
		jsPrint(report)
		os.Exit(0)
	}

	report = newPEReport(pePath)
	peFile, err := newPEFile(report.Path)
	if err != nil {
		log.Fatalf("%s %s\n", report.Path, err)
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

	err = populatePEReport(report, peFile)
	if err != nil {
		log.Fatalf("%s %s\n", report.Path, err)
	}

	if printDef != "" {
		var defs []string
		for _, imp := range report.Imports {
			if strings.ToLower(imp.Host) == strings.ToLower(printDef) {
				sansSuffix := strings.Replace(imp.Host, ".dll", "", 1)
				for _, fn := range imp.Functions {
					line := fmt.Sprintf("%s.%s", sansSuffix, fn)
					defs = append(defs, line)
				}
			}
		}
		out := makeDepFile(defs)
		fmt.Println(out)
		os.Exit(0)
	}

	jsPrint(report)
}

func walkFunctionGenerator(pattern string) fs.WalkDirFunc {
	// use a set to track if a report for a PE's parent directory
	// has already been printed
	printedParentDir := make(map[string]bool)
	return func(path string, info os.DirEntry, err error) error {
		if err != nil {
			log.Printf("HUH? %s\n", err)
		}

		if info.IsDir() {
			return nil
		}

		matched, err := filepath.Match(pattern, filepath.Base(path))
		if err != nil {
			log.Printf("#Match %s\n", err)
		}

		if matched {
			parent := filepath.Dir(path)
			if !printedParentDir[parent] {
				// first time finding a PE in this directory
				dirReport := newDirectoryReport(parent)
				jsPrint(dirReport)
				printedParentDir[parent] = true
			}

			report := newPEReport(path)
			peFile, err := newPEFile(report.Path)
			if err != nil {
				log.Printf("#newPEFile - %s - %s\n", report.Path, err)
				return nil
			}

			err = populatePEReport(report, peFile)
			if err != nil {
				log.Printf("#populateReport - %s\n", err)
				return nil
			}

			jsPrint(report)

		}
		return nil
	}
}

func newDirectoryReport(path string) *Report {
	report := &Report{}
	report.Name = filepath.Base(path)
	report.Path, _ = filepath.Abs(path)
	report.Type = "directory"
	report.Dir = filepath.Dir(path)
	err := handleDirPerms(report)
	if err != nil {
		return report
	}
	return report
}

func newPEReport(path string) *Report {
	report := &Report{}
	report.Name = filepath.Base(path)
	report.Path, _ = filepath.Abs(path)
	report.Type = "file"
	return report
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

func makeDepFile(deps []string) string {

	template := `LIBRARY "xyz.dll" BASE=0x20000000
EXPORTS
%s
`
	return fmt.Sprintf(template, strings.Join(deps, "\n"))
}
