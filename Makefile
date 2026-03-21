.PHONY: build test clean install

VERSION := v0.1.0
LDFLAGS := -s -w
BINARY := promptscan
COMPILER := promptscan-compile

build:
	go build -ldflags "$(LDFLAGS)" -o $(BINARY) ./cmd/promptscan/
	go build -ldflags "$(LDFLAGS)" -o $(COMPILER) ./cmd/promptscan-compile/

test:
	go test ./... -v -race

test-short:
	go test ./... -short

bench:
	go test ./... -bench=. -benchmem

clean:
	rm -f $(BINARY) $(COMPILER)
	rm -rf dist/

install: build
	install -m 755 $(BINARY) /usr/local/bin/
	@echo "Installed $(BINARY) to /usr/local/bin/"

fmt:
	gofmt -s -w .

vet:
	go vet ./...

lint: fmt vet

compile-sigs:
	@echo "Use: ./$(COMPILER) -i <patterns.txt> -o signatures/default.pgsig -v"

all: lint test build
