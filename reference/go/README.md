# Go public-mode checker

Everything a Kinfold server must enforce, checked against the vectors with only the Go standard library: identities, every member-log entry and case (public outcome and public state, PROTOCOL.md §6.2), the envelope checks a server makes before storing one (§7.5), and server identity and login.

```sh
go run . ../../spec/vectors/kinfold-v0.json      # Go 1.24 or later; 228 checks
```

It decrypts nothing, because a server can't. Its `apply` function is meant to grow into the server's protocol package.
