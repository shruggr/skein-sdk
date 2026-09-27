module github.com/shruggr/skein/wallet-zig/vectors/gen-go

go 1.26.0

require github.com/bsv-blockchain/go-sdk v1.5.2

require (
	github.com/mrz1836/go-whatsonchain v1.1.0 // indirect
	github.com/pkg/errors v0.9.1 // indirect
	github.com/stretchr/testify v1.12.1 // indirect
	go.yaml.in/yaml/v3 v3.0.5 // indirect
	golang.org/x/crypto v0.57.0 // indirect
)

// The reference is the local go-sdk checkout, as in programs/go.mod.
replace github.com/bsv-blockchain/go-sdk => /home/shruggr/Work/bsv/go-sdk
