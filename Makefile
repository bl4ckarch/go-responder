BINARY   := go-responder
LDFLAGS  := -s -w
GOFLAGS  := CGO_ENABLED=0 -trimpath -ldflags="$(LDFLAGS)"

.PHONY: all linux windows test coverage clean

all: linux windows

linux:
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags="$(LDFLAGS)" \
		-o release/$(BINARY)-linux-amd64 ./cmd/go-responder

windows:
	CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -trimpath -ldflags="$(LDFLAGS)" \
		-o release/$(BINARY)-windows-amd64.exe ./cmd/go-responder

test:
	go test -count=1 -v -timeout 60s ./...

coverage:
	go test -count=1 -timeout 60s -coverprofile=coverage.out ./...
	go tool cover -func=coverage.out | tail -5

clean:
	rm -f release/$(BINARY)-linux-amd64
	rm -f release/$(BINARY)-windows-amd64.exe
	rm -f coverage.out
