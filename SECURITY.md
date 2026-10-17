# Security policy

MicroTAK is the server ATAK, iTAK, WinTAK and CloudTAK devices trust with
their positions, messages and files, and its CA signs every device
certificate. Security reports are very welcome.

## Supported versions

Fixes go into the latest release line only (currently 0.9.x), published
as a patch release with binaries and multi-arch images. Please upgrade to
the latest release before reporting.

## Reporting a vulnerability

**Please don't open a public issue.** Report privately through GitHub:
[Security → Report a vulnerability](https://github.com/microtak/microtak-server/security/advisories/new).

Helpful to include:

- the version (`microtakd` release or image tag) and how it runs (binary,
  Docker, Helm, behind a proxy);
- what an attacker needs (network access only, an enrolled device, a
  password account, the admin certificate);
- steps or a proof of concept, and what you expected instead;
- for protocol or API issues, how the official TAK Server behaves in the
  same case, if you know.

Reports are handled as soon as possible; this is a small project without a
formal response-time commitment. You'll get credit in the advisory unless
you prefer not to.

## Scope

In scope: everything this repository ships — enrollment (`/Marti/api/tls`,
OAuth), the CoT streams, the Marti API, the admin API, the Helm chart, the
Docker image and the release binaries.

Out of scope: vulnerabilities in TAK clients or in the official TAK Server
themselves (report those upstream), and deployments that disable the
defaults on purpose (e.g. Open enrollment, the plain-TCP relay on an
untrusted network).

## How MicroTAK is hardened

- Every device, and every Marti API request, is authenticated with a
  client certificate from MicroTAK's own CA; the CA key is stored
  owner-only.
- Enrollment is locked from the first start: the admin enrolls once with a
  one-time bootstrap token, everyone else with an invite token or a
  password account (Argon2, rate-limited).
- Revoking a certificate or blocking an identity takes effect on the next
  request and cuts live CoT connections.
- The Marti API applies the official TAK Server's URL authorization table;
  mission access follows the official roles and mission tokens.
- Connection limits, handshake and header timeouts, bounded event and
  upload sizes.
- Dependencies are scanned with OSV-Scanner in CI; releases are built and
  published by CI only.
