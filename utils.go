package main

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
)

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

func jsPrint(report *Report) {
	serialized, _ := json.Marshal(report)
	fmt.Println(string(serialized))
}
