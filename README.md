# dotlocal

Turn a Go `http.Handler` into a **named service on your LAN** — reachable at
`http://<name>.local` with no DNS, hosts file, static IP, or port to remember.

It's the companion to the `go:embed`'d local-web-app pattern: you build a
handler from embedded assets, `dotlocal` makes it reachable by name across
every network the machine is on.

```go
ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
defer stop()

dotlocal.Run(ctx, dotlocal.Config{
    Name:      "fwrd",        // advertised as fwrd.local
    Handler:   app,           // your go:embed'd http.Handler
    Addr:      "0.0.0.0:8080",
    Advertise: true,          // mDNS, scoped per interface
})
```

`Run` binds (failing fast if the port is taken), advertises `<name>.local` over
mDNS, serves, and shuts down gracefully when the context is cancelled.

## What it solves

- **A name, not an IP:port.** `http://fwrd.local` beats memorising
  `192.168.1.x:8080`.
- **Multi-homed hosts.** On a machine on several LANs at once, `Run` starts one
  mDNS responder *per interface*, each answering only with the address
  reachable on the subnet the query arrived from — so the name resolves
  correctly whether a client is on the wired net, the Wi-Fi, or a guest AP, and
  never gets handed an address it can't route to. Virtual interfaces (VM/
  container bridges, VPN tunnels, AirDrop) are skipped automatically.
- **Coexists with the OS.** On Linux the self-hosted responder shares the
  multicast socket with Avahi (`SO_REUSEADDR`). On **macOS** a self-hosted
  responder does *not* interoperate with the system `mDNSResponder` (its records
  never resolve), so dotlocal registers with it directly via the `dns_sd` C API
  (`DNSServiceRegisterRecord`), one shared A record per LAN. Multi-LAN works on
  both platforms.

> **macOS builds require cgo** (`CGO_ENABLED=1` and a C compiler — the Xcode
> Command Line Tools). The `dns_sd` symbols are in libSystem, so no extra
> linker flags are needed. Linux and other platforms are pure Go.

## Port 80 — bare `http://<name>.local`

Binding port 80 is privileged and often already taken by the host. The
`dotlocal/port80` subpackage avoids both problems: it gives the service its own
**alias IP** on each LAN and installs kernel firewall redirects (pf on macOS,
nftables on Linux) from that IP's `:80` to your unprivileged port — before the
socket lookup, so it works even when the host binds `0.0.0.0:80`, and never
touches the host's own port-80 traffic. On macOS, separate physical-interface
and loopback rules make the alias work from LAN clients and the hosting Mac.
The stock `rdr-anchor "com.apple/*"` sub-anchor is used, so `/etc/pf.conf` is
never modified.

Redirect **more than one** public port onto the same app port with `Ports`,
e.g. `Ports: []int{80, 443}` so bare `https://<name>.local` works alongside
`http://`. One app port serves both; the app distinguishes TLS from cleartext
itself. The scalar `Port` is kept for back-compat and equals `Ports[0]`.

```go
// privileged step (root), e.g. from your CLI's `net up`:
st, _ := port80.Up(port80.Options{
    Name: "fwrd", ToPort: 8080,
    Aliases: []port80.Alias{
        {Iface: "en0", AliasIP: "192.168.1.240"},
        {Iface: "en9", AliasIP: "192.168.178.240"},
    },
})
// then serve unprivileged and advertise the alias IPs scoped per interface:
ips := []net.IP{net.ParseIP("192.168.1.240"), net.ParseIP("192.168.178.240")}
adv, _ := mdns.AdvertiseScoped("fwrd", 80, ips, mdns.Options{})
```

`port80.Up`/`Down` need root, record state under the root-owned
`/var/run/dotlocal/<name>.json` (0600), and are **not** reboot-persistent
(re-run after a reboot). `port80.DetectIface`
derives the interface from an alias IP's subnet so callers can make `--iface`
optional. Linux and macOS only; `Supported()` reports availability.

A recorded binding can also silently stop being true — VPNs and security
products flush or disable the firewall without asking. `port80.Verify` checks
the live system against the record, and `port80.Reassert` converges it back
(re-adding missing aliases, reloading the ruleset in place, re-enabling a
disabled pf without leaking enable references).

## Local-only mode — this machine, no network

For services that should be reachable *only from the machine itself* (dev
dashboards, admin UIs), `mdns.AdvertiseLocal` registers `<name>.local` with
the host resolver's LocalOnly scope instead of multicasting it: local
processes resolve it instantly, and nothing ever appears on any network.
Pair it with a `port80` binding on a loopback alias (e.g. `127.0.0.2` on
`lo0`) for a bare `http://<name>.local`.

This replaces the tempting-but-broken `/etc/hosts` approach: a hosts entry
under `.local` answers only the A lookup, so every dual-stack resolve still
multicasts the AAAA query and stalls for the full mDNS timeout (~5s).
`AdvertiseLocal` registers both an A and an AAAA, so both address families
answer in milliseconds. macOS only (it drives mDNSResponder's LocalOnly
interface); see [CAVEATS.md](CAVEATS.md) for the full story.

## The CLI — dotlocal for non-Go services

`cmd/dotlocal` packages all of the above for services written in anything:

```
go install github.com/pders01/dotlocal/cmd/dotlocal@latest

# one-shot binding (root):
sudo dotlocal up   --name myapp --ip 127.0.0.2 --to-port 8080 --local
sudo dotlocal down --name myapp
dotlocal status    --name myapp        # prints the record + whether it's in force

# long-running keeper: binding + mDNS registration + self-healing
sudo dotlocal keep --name myapp --ip 127.0.0.2 --to-port 8080 --local

# install the keeper as a system service (launchd/systemd), surviving reboots:
sudo dotlocal service install   --name myapp --ip 127.0.0.2 --to-port 8080 --local
sudo dotlocal service uninstall --name myapp
```

`keep` owns the mDNS registration (records live exactly as long as the
process) and re-asserts the binding on a timer (default 10m), healing after
anything flushes or disables the firewall. `service install` always rewrites
the launchd plist / systemd unit and reloads it, so re-running it is also the
repair and upgrade procedure — a definition written once and left alone rots
when paths change (see [CAVEATS.md](CAVEATS.md)).

Omit `--local` for LAN mode: alias IPs on the matching LAN interfaces,
advertised over real multicast, one scoped registration per interface.

## Packages

| Package | What |
|---|---|
| `dotlocal` | `Run(ctx, Config)` — bind + advertise + serve + graceful shutdown |
| `dotlocal/mdns` | scoped multi-interface `<name>.local` advertising (`Advertise`, `AdvertiseScoped`) and host-local registration (`AdvertiseLocal`) |
| `dotlocal/port80` | alias IP + firewall redirect for bare public port(s) — 80, optionally 443 (root); `Verify`/`Reassert` for self-healing |
| `cmd/dotlocal` | the CLI: `up`/`down`/`status`, the `keep` daemon, `service install/uninstall` (launchd/systemd) |

## Example

`examples/embedserve` is a complete `go:embed` app served as
`embedserve.local`. Run it and open `http://embedserve.local:8080` from any LAN
device:

```
go run ./examples/embedserve
```

## Requirements

Go 1.24+. macOS builds require cgo (`CGO_ENABLED=1` + a C compiler) for the
mDNS backend; Linux and other platforms are pure Go. The `port80` subpackage is
Linux/macOS only (`port80.Supported()` reports availability) and its `Up`/`Down`
require root.

## Status

Extracted from [fwrd](https://github.com/pders01/fwrd). Service persistence
lives in the CLI (`dotlocal service install`); the hard-won failure modes
behind the design are collected in [CAVEATS.md](CAVEATS.md).

## License

MIT — see [LICENSE](LICENSE).
