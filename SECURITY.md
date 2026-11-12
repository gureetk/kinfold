# Security policy

Kinfold handles family members' locations, including children's. We take reports seriously and are grateful for them.

## Reporting a vulnerability

**Please don't open a public issue.** Use GitHub's private vulnerability reporting on this repository (Security → Report a vulnerability). A security email address will be listed here once the project has its own domain.

Include what you found, how to reproduce it, the version or commit, and what an attacker could do with it. Proof-of-concept code is welcome.

## What to expect

- Acknowledgement within 3 days.
- An initial assessment within 10 days.
- A fix, or a plan with dates, within 90 days for confirmed issues. We'll agree a disclosure date with you and credit you unless you'd rather we didn't.
- There's no bug bounty yet.

## Scope

In scope: the protocol (`spec/`), the reference implementations, and — once they exist — the server, apps, web companion and push relay.

Especially interesting: anything that lets a server or outsider learn locations or other encrypted content; add a member or device to a circle; change a teen's rules or grant a pause without a guardian; make different members' phones disagree about who is in a circle; or hide a membership change, a pause or a teen going silent from the people who should see it.

Out of scope: problems that require malware on a member's phone, physical access to an unlocked phone, or a member legitimately sharing what they can already see. The threat model is in PROTOCOL.md §1.2 and §15.

## Status

The protocol is a v0 draft and has not been audited. An independent audit is planned before 1.0. Please don't rely on it to protect anyone yet.
