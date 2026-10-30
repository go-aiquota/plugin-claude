module github.com/go-aiquota/plugin-claude

// ⛔ The PATCH, because govulncheck judges the standard library by the version
// the module claims. GO-2026-6809 — crypto/x509, where compromised
// intermediate certificates are no longer refused by Certificate.Verify — has
// its fix RELEASED in 1.27.3, and vulngate accepts no waiver for an advisory
// whose fix is released.
//
// ⚠ Unlike its sibling tools, this repository's lane does NOT read this line:
// it pins `go-version: '1.27.3'` literally, twice. Both are raised together,
// because raising only the directive would leave the lane building with the
// older toolchain while the contract claimed the newer one.
go 1.27.3

require (
	github.com/go-aiquota/proto v0.0.0-20261029025954-30cf59bad0ac
	github.com/go-browserhttp/browserhttp v0.3.0
	github.com/hashicorp/go-plugin v1.8.0
)

require (
	github.com/andybalholm/brotli v1.0.6 // indirect
	github.com/breml/rootcerts v0.3.7 // indirect
	github.com/fatih/color v1.13.0 // indirect
	github.com/golang/protobuf v1.5.4 // indirect
	github.com/hashicorp/go-hclog v1.6.3 // indirect
	github.com/hashicorp/yamux v0.1.2 // indirect
	github.com/klauspost/compress v1.20.1 // indirect
	github.com/mattn/go-colorable v0.1.12 // indirect
	github.com/mattn/go-isatty v0.0.17 // indirect
	github.com/oklog/run v1.1.0 // indirect
	github.com/refraction-networking/utls v1.8.2 // indirect
	golang.org/x/crypto v0.57.0 // indirect
	golang.org/x/net v0.60.0 // indirect
	golang.org/x/sys v0.48.0 // indirect
	golang.org/x/text v0.42.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20260817212433-ac3dfec99bb1 // indirect
	google.golang.org/grpc v1.85.0 // indirect
	google.golang.org/protobuf v1.36.12 // indirect
)
