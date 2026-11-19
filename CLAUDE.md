# Rules for working in this repository

These hold for every change, alongside [CONTRIBUTING.md](CONTRIBUTING.md), which applies in full.

## Commits

- Commit under the maintainer's identity, set in the clone:

  ```sh
  git config user.name gureet
  git config user.email noreply@git.gureet.ca
  ```

- End every commit message with the sign-off and the co-author line of the model that wrote the change, so that both are authors:

  ```text
  Signed-off-by: gureet <noreply@git.gureet.ca>
  Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>
  ```

- Nothing in the repository links to a Claude chat, session or project: no `Claude-Session:` trailer, no session link in a pull request description, nothing in code or docs. `.claude/settings.json` turns the session link off. A plain "Generated with Claude Code" line in a pull request is fine.
- Commit messages, pull requests, code and docs stand on their own. Don't quote or paraphrase conversations, and don't point to documents outside the repository.

## Branches and pull requests

- Work on a branch and open a pull request; never push to `main`.
- Pull requests are squash-merged. Merge one yourself once CI is green, unless it needs the maintainer to test something on a device first; then wait for their result.
- `gh pr` doesn't work in cloud sessions. Open and edit pull requests with `gh api repos/gureetk/kinfold/pulls`.
- The CI job `vectors` must stay green.

## What CONTRIBUTING.md asks most often

- `spec/PROTOCOL.md`, the Python reference, the generator and the vectors change together, in one pull request.
- Anything that changes bytes on the wire or a validation outcome gets a sentence on its security effect in the pull request.
- Every dependency has a reason in the pull request, a pinned version and a verified hash (`go.sum`, Gradle dependency verification, hashes in `requirements.txt`). The server keeps to five or fewer direct Go dependencies. Never switch off checksum verification (`GOSUMDB=off`, `GONOSUMDB`, `GOFLAGS=-insecure`) to get around a network problem: report the problem.
- No cryptography of our own. Use platform and vendor libraries, behind the byte checks of PROTOCOL.md §3.3, and never Bouncy Castle (PROTOCOL.md Appendix C).

## Where things are

- `spec/` is the source of truth. Where `spec/API.md` and `spec/PROTOCOL.md` disagree about bytes, PROTOCOL.md wins.
- When building shows that the API or the spec is wrong or unclear, fix the document in the same pull request. A flaw in the protocol itself, as opposed to a gap in the API, goes to the maintainer before `spec/PROTOCOL.md` changes.
- `reference/go` is the independent Apache-2.0 checker. Leave it alone when working on the server, which lives in `server/` under AGPL-3.0-or-later.
