# LAN ingress

By default every `serve-*` command listens on a loopback address and admits
loopback clients only; reaching it from another machine needs an SSH tunnel.
An operator can instead expose it on a LAN or VPN address, for the networks
they name. The operator's guide is in `TEST-SETUP-AZ.md` ("Lokal şəbəkədən").

```sh
keybash serve-remote-lab ... \
  --listen 192.168.1.10:8443 --allow-from 192.168.1.0/24,10.8.0.0/16 \
  --server-name keybash.lan --tls-cert lan.pem --tls-key lan-key.pem
```

## What is checked

- **The listener** is one specific global-unicast address and a nonzero port.
  All-interface (`0.0.0.0`, `::`), link-local, multicast, mapped and zoned
  addresses are refused, and so is a loopback address combined with
  `--allow-from` or `--server-name`.
- **`--allow-from`** is required for a non-loopback listener: 1 to 16
  networks, written canonically (host bits zero), none of them loopback or
  unspecified (so never `0.0.0.0/0` or `::/0`), none repeated.
- **The origin** browsers use is `https://` plus `--server-name` (or the
  listener's address) and the port. A name must be canonical lowercase LDH
  labels; it may not be `localhost` or under `.localhost`, and its last label
  may not be all digits (`10.1` would be an IPv4 address to a browser). An
  address origin must be global unicast and written canonically.
- **The TLS certificate** must cover the origin's name or address and be valid
  at start-up; otherwise the command refuses to serve.

## What is enforced

- **Before TLS.** The listener closes any connection from outside the listed
  networks before reading a byte. It admits at most 64 connections at once
  per source and 1024 in total; beyond that, it closes new connections. A
  source is an IPv4 address or an IPv6 /64.
- **Every request.** The lab checks the client address against the same
  networks and the `Host` header against the exact origin, so a different name
  for the same address (DNS rebinding) is refused. The existing TLS 1.3, Origin,
  CSRF, `__Host-` cookie and Fetch-metadata checks are unchanged. Every
  response carries `Strict-Transport-Security: max-age=31536000` (browsers
  ignore it for an address origin).
- **Password guessing.** Sign-in attempts from one source are limited to 30
  per minute across all the names it tries, and to five per minute for any
  one name. A name is also limited to 30 per minute across all sources. One
  source therefore cannot keep a person from signing in from another, and
  many sources together still guess slowly; behind the password, every
  session also needs the second factor. The source is checked first, so a
  refused source creates no per-name counter. A loopback lab has one shared
  source and keeps five attempts per name per minute.

## Limits

- This is LAN and VPN ingress, not public Internet exposure. The listed networks
  are the boundary; there is no DDoS protection, geo or reputation filtering,
  and the limits assume a bounded set of clients.
- There is no reverse-proxy mode. The client address must be the real peer:
  `X-Forwarded-For` is never read, and a proxy would share one source.
- Clients inside a listed network can still reach the login page. Pre-auth
  attack surface is the same as on loopback, with the per-source limit added.
- The certificate and its renewal are the operator's (a private CA or their
  own). Keybash checks it at start-up only; restart after renewal.
- The terminal and RDP protocol labs (`terminalweb`, `rdplab` viewers) remain
  loopback-only; only the identity gateway is exposed.

## Evidence

`TestParseSourcesIsExactAndBounded`, `TestAllowedAndSourceUnits`,
`TestListenerAdmitsOnlyListedSourcesWithinLimits`, `TestWrapRefusesBadLimits`,
`TestOriginsAreExactForLoopbackAndExposedLabs`,
`TestExposedLabAdmitsOnlyListedNetworks`, `TestExposedLoginCountsPerSource`,
`TestExposureNeedsNetworksAndASpecificAddress`,
`TestExposedCertificateMustCoverTheOrigin` and
`TestExposedListenerAdmitsOnlyItsNetworks`.
