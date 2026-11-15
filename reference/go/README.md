# Go public-mode checker

Everything a Kinfold server must enforce, checked against the vectors with only the Go standard library: strict Ed25519 verification and the X25519 key check (PROTOCOL.md §3.3, §3.5), the RFC 9180 case, identities and identity chains, every member-log entry and case (public outcome and public state, §6.2), the checks a server makes before storing an envelope (§7.5), watch grants (§14.1), the pushes and relay signatures a server builds (§14.2, §14.4), and the server's identity document, setup code, move notices and login (§13).

```sh
go run . ../../spec/vectors/kinfold-v0.json      # Go 1.24 or later; 1,046 checks
```

It decrypts nothing, because a server can't. Its `apply` and `envelopeCheck` functions are meant to grow into the server's protocol package.
