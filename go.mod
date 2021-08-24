module github.com/audibleblink/ino

go 1.16

require (
	github.com/Microsoft/go-winio v0.5.0
	github.com/kgoins/go-winacl v0.2.0
	golang.org/x/sys v0.0.0-20210823070655-63515b42dcdf
	www.velocidex.com/golang/binparsergen v0.1.0
	www.velocidex.com/golang/go-pe v0.1.1-0.20210201082132-138370e90206
)

replace github.com/kgoins/go-winacl => github.com/audibleblink/go-winacl v0.0.2
