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
- **Coexists with the OS.** The multicast socket sets `SO_REUSEADDR`, so it runs
  alongside Bonjour/Avahi.

## Port 80 — bare `http://<name>.local`

Binding port 80 is privileged and often already taken by the host. The
`dotlocal/port80` subpackage avoids both problems: it gives the service its own
**alias IP** on each LAN and installs a kernel firewall redirect (pf on macOS,
nftables on Linux) from that IP's `:80` to your unprivileged port — before the
socket lookup, so it works even when the host binds `0.0.0.0:80`, and never
touches the host's own port-80 traffic. macOS uses the stock
`rdr-anchor "com.apple/*"` sub-anchor, so `/etc/pf.conf` is never modified.

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

## Packages

| Package | What |
|---|---|
| `dotlocal` | `Run(ctx, Config)` — bind + advertise + serve + graceful shutdown |
| `dotlocal/mdns` | scoped multi-interface `<name>.local` advertising (`Advertise`, `AdvertiseScoped`) |
| `dotlocal/port80` | alias IP + firewall redirect for bare port 80 (root) |

## Example

`examples/embedserve` is a complete `go:embed` app served as
`embedserve.local`. Run it and open `http://embedserve.local:8080` from any LAN
device:

```
go run ./examples/embedserve
```

## Requirements

Go 1.24+. The `port80` subpackage is Linux/macOS only (`port80.Supported()`
reports availability) and its `Up`/`Down` require root.

## Status

Extracted from [fwrd](https://github.com/pders01/fwrd). A `service` package
(install as a systemd/launchd user service) is planned.

## License

MIT — see [LICENSE](LICENSE).
