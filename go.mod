module github.com/audibleblink/ino

go 1.18

require (
	github.com/Microsoft/go-winio v0.5.2
	github.com/kgoins/go-winacl v0.2.0
	golang.org/x/sys v0.0.0-20220503163025-988cb79eb6c6
	www.velocidex.com/golang/binparsergen v0.1.0
	www.velocidex.com/golang/go-pe v0.1.1-0.20210201082132-138370e90206
)

require (
	github.com/Velocidex/json v0.0.0-20220224052537-92f3c0326e5a // indirect
	github.com/Velocidex/ordereddict v0.0.0-20220428153415-da46091cd216 // indirect
	github.com/Velocidex/yaml/v2 v2.2.8 // indirect
	github.com/audibleblink/bamflags v1.0.0 // indirect
)

replace github.com/kgoins/go-winacl => github.com/audibleblink/go-winacl v0.0.2
