BINARY    := zuhan
PKG       := ./cmd/zuhan
VERSION   ?= $(shell git describe --tags --always --dirty 2>/dev/null)
LDFLAGS   := -s -w
ifneq ($(VERSION),)
LDFLAGS   += -X main.version=$(VERSION)
endif
PLATFORMS := linux/amd64 linux/arm64 windows/amd64 darwin/amd64 darwin/arm64

.PHONY: build test lint web release clean

## build: compile for this machine into bin/zuhan
build:
	go build -trimpath -ldflags "$(LDFLAGS)" -o bin/$(BINARY) $(PKG)

## test: vet + race-enabled tests (no network needed)
test:
	go vet ./...
	go test -race ./...

## lint: fail if any file is not gofmt'ed
lint:
	@test -z "$$(gofmt -l .)" || (gofmt -l . && echo "run: gofmt -w ." && exit 1)

## web: build and start the browser UI
web: build
	./bin/$(BINARY) web

## release: cross-compile every platform into dist/ with checksums
release: clean
	@mkdir -p dist
	@for p in $(PLATFORMS); do \
		os=$${p%/*}; arch=$${p#*/}; ext=""; [ $$os = windows ] && ext=.exe; \
		echo "building $$os/$$arch"; \
		CGO_ENABLED=0 GOOS=$$os GOARCH=$$arch go build -trimpath -ldflags "$(LDFLAGS)" \
			-o dist/$(BINARY)-$$os-$$arch$$ext $(PKG) || exit 1; \
	done
	@cp scripts/zuhan-web.bat dist/
	@cd dist && sha256sum * > SHA256SUMS

clean:
	rm -rf bin dist
