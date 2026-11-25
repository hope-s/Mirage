VERSION := 2.0.1
LDFLAGS := -s -w
GOFLAGS := -trimpath

.PHONY: build test release clean

build:
	CGO_ENABLED=0 go build $(GOFLAGS) -ldflags '$(LDFLAGS)' -o bin/mirage ./cmd/mirage

test:
	go vet ./...
	go test -race -count=1 -timeout 600s ./...

release: clean
	mkdir -p dist/mirage/bin
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build $(GOFLAGS) -ldflags '$(LDFLAGS)' -o dist/mirage/bin/mirage-linux-amd64 ./cmd/mirage
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build $(GOFLAGS) -ldflags '$(LDFLAGS)' -o dist/mirage/bin/mirage-linux-arm64 ./cmd/mirage
	CGO_ENABLED=0 GOOS=linux GOARCH=arm GOARM=7 go build $(GOFLAGS) -ldflags '$(LDFLAGS)' -o dist/mirage/bin/mirage-linux-armv7 ./cmd/mirage
	cp install.sh README.md dist/mirage/
	cd dist && tar czf mirage-release.tar.gz mirage && sha256sum mirage-release.tar.gz > mirage-release.tar.gz.sha256

clean:
	rm -rf dist bin
