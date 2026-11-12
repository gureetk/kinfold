# Contributing

Thanks for helping. A few rules keep a security-sensitive project manageable.

## Sign-off (DCO), no CLA

Every commit must carry a `Signed-off-by:` line (`git commit -s`), certifying the [Developer Certificate of Origin 1.1](https://developercertificate.org/): that you wrote the change or have the right to submit it under the project's licenses. There is no contributor license agreement; your contribution stays under the license of the directory you changed (see `REUSE.toml`), including the app-store permission for `apps/` and `core/`.

## Protocol changes

- Change `spec/PROTOCOL.md`, the reference implementation and the generator together, and regenerate `spec/vectors/kinfold-v0.json` in the same pull request. CI fails if the vectors don't regenerate byte for byte.
- Every new rule needs vectors: a valid case and the failure cases, each with its reason code.
- Anything that changes bytes on the wire or a validation outcome needs a sentence in the pull request explaining the security effect.

## Dependencies

Each new dependency needs a written reason in the pull request, a pinned version and a verified hash or lockfile. Prefer the standard library and platform crypto. No analytics, advertising, crash-reporting or Google Play services SDKs, ever.

## Code

- Parsers reject anything they don't fully understand; fuzz them.
- Never log locations, IP addresses or key material.
- Compare secrets in constant time.
- Follow each platform's own conventions: classic iOS on iPhone, Material 3 on Android.

## Conduct

Be kind and assume good faith. Harassment isn't tolerated. Maintainers may remove comments, commits or people that break this.
