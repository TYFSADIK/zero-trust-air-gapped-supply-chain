.PHONY: build test repro demo
build:
	CGO_ENABLED=0 go build -trimpath -o bin/airgap ./cmd/airgap
test:
	go vet ./... && go test -race -v ./... 2>&1 | grep -E "^(--- |ok|FAIL)|frames|missing"
repro:
	./scripts/repro-check.sh
demo: build
	rm -rf /tmp/ag && mkdir -p /tmp/ag/high /tmp/ag/low
	head -c 500000 /dev/urandom > /tmp/ag/high/app.tar
	./bin/airgap keygen -key /tmp/ag/keys/high.key
	./bin/airgap attest -key /tmp/ag/keys/high.key -o /tmp/ag/high/app.att.json /tmp/ag/high/app.tar
	./bin/airgap send -in /tmp/ag/high/app.tar -o /tmp/ag/frames.bin -n 2
	./bin/airgap recv -in /tmp/ag/frames.bin -o /tmp/ag/low/app.tar
	./bin/airgap verify -pub /tmp/ag/keys/high.pub -att /tmp/ag/high/app.att.json -dir /tmp/ag/low
