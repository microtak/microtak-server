# Running MicroTAK behind a reverse proxy

MicroTAK serves **no plain HTTP**: its enrollment port (8446) is HTTPS only.
A reverse proxy is optional — useful when the server has a public DNS name
and you want a publicly-trusted certificate (Let's Encrypt) on the
enrollment endpoint, or when the server sits behind a tunnel such as
Pangolin. Without a proxy, MicroTAK can also serve a Let's Encrypt
certificate itself (`enrollment_cert_file` / `enrollment_key_file`, reloaded
automatically when renewed), or its own CA-issued certificate (the default,
fully offline).

## What goes through the proxy, and what doesn't

| Port | What | Through a proxy? |
|------|------|------------------|
| 8446 | Enrollment + `/oauth/token` (HTTPS, no client cert) | **Yes**, as an HTTPS route. The proxy re-encrypts to MicroTAK — never plain HTTP to the backend. |
| 8443 | Marti API (mTLS) | **Only as raw TCP passthrough.** Terminating TLS here breaks client-certificate auth. |
| 8089 | CoT relay (mTLS) | **Only as raw TCP passthrough**, same reason. |
| 8087 | Plain-TCP CoT relay | Not recommended at all — off by default, unauthenticated. |

## Always set `trusted_proxies`

Behind a proxy, every request reaches MicroTAK from the proxy's address. Rate
limiting of failed logins is per client address, so without this one
misbehaving client would lock out everyone behind the same proxy. List the
proxy's address(es) as seen by MicroTAK:

```toml
# microtak.toml
trusted_proxies = ["172.18.0.0/16"]   # e.g. the Docker network Traefik is on
```

For those addresses only, MicroTAK takes the client address from
`X-Forwarded-For` (the right-most entry that isn't itself a trusted proxy).
From anyone else the header is ignored, so clients can't pick their own
rate-limit bucket.

## Traefik

Use `docker-compose.proxy.yml` (see the comments in it and `.env.example`):

1. Add [`traefik-microtak-transport.yml`](traefik-microtak-transport.yml) to
   Traefik's dynamic **file** configuration — Traefik only accepts a
   `serversTransport` from its file provider, not from Docker labels.
2. Copy MicroTAK's CA certificate (`ca-cert.pem` in its data volume — the
   certificate only, never `ca-key.pem`) to the path that file names
   (`/etc/traefik/microtak-ca.pem`).
3. Set `trusted_proxies` (above) and start with the overlay.

Traefik then terminates the public certificate on its entrypoint, and
connects to MicroTAK over HTTPS **verifying MicroTAK's CA** — encrypted and
authenticated end to end.

For 8443/8089, either publish them directly (the default in
`docker-compose.yml`) or add Traefik TCP routers with TLS passthrough
(`HostSNI(`*`)` on a dedicated entrypoint per port, `tls.passthrough=true`).

## Pangolin

Pangolin tunnels a site to a public Traefik instance it manages.

- **Enrollment (8446)**: create an **HTTP resource** for your public domain
  (Pangolin issues the Let's Encrypt certificate) with a target using method
  **`https`** and MicroTAK's address and port 8446. Set the resource's
  **TLS Server Name** to `microtak-server` — without it Traefik rejects
  MicroTAK's self-signed chain.
- **Caveat, from Pangolin's source**: when a TLS Server Name is set,
  Pangolin's generated Traefik configuration uses `insecureSkipVerify: true`
  for the backend hop (`server/lib/traefik/getTraefikConfig.ts`); there is no
  per-resource option for a custom CA. The hop from the Newt site connector
  to MicroTAK is therefore **encrypted but not authenticated** — an attacker
  on the site's local network could impersonate MicroTAK to the tunnel. Keep
  that hop on a trusted segment (ideally Newt and MicroTAK on the same host),
  or serve a publicly-trusted certificate from MicroTAK itself
  (`enrollment_cert_file`) so verification doesn't depend on the proxy.
- **8443 / 8089**: create **raw TCP resources** (Pangolin supports TCP
  resources on a chosen public port) pointing at MicroTAK's 8443 and 8089.
  Pangolin passes the bytes through; MicroTAK's own mTLS still authenticates
  every client.
- Set `trusted_proxies` to the address the Newt connector reaches MicroTAK
  from.

## Clients behind a proxy

When enrollment is on the proxy's port 443 rather than 8446, tell the client:

- **OmniTAK**, manual: enter the **bare host name** (no `https://`, no port)
  and set the enrollment port field to **443**. Typing a scheme or port into
  the host field makes OmniTAK save that whole string as the streaming host
  (an OmniTAK bug), leaving it stuck on "connecting".
- **QR enrollment** (`tak://com.atakmap.app/enroll?...`): add
  `enrollmentport=443`; if 8089/8443 are exposed on other public ports, also
  `port=<streaming>` and `apiport=<marti>` (OmniTAK-specific parameters).
