module github.com/token2/authy-migration/cmd/authy-export

go 1.2

require (
	github.com/google/uuid v1.6.0
	github.com/token2/authy-migration v0.3.2
	github.com/skip2/go-qrcode v0.0.0-20200617195104-da1b6568686e
	golang.org/x/crypto v0.0.0-20210415154028-4f45737414dc // indirect
	golang.org/x/sys v0.0.0-20210420072515-93ed5bcd2bfe // indirect
	golang.org/x/term v0.0.0-20210406210042-72f3dc4e9b72
)

replace github.com/token2/authy-migration => ../../
