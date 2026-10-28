BINNAME:=gshark
BINDIR:=../bin
GOARCH:=amd64
GO_FILES:=../*.go

build_cli:
	GOOS=windows GOARCH=$(GOARCH) go build -o $(BINDIR)/$(BINNAME).exe $(GO_FILES)
	GOOS=linux GOARCH=$(GOARCH) go build -o $(BINDIR)/$(BINNAME) $(GO_FILES)

clean:
	rm -rf ../bin

.PHONY: clean build_cli
