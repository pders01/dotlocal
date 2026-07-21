# Caveats — why naming local services is harder than it looks

Every mechanism in this repo exists because a simpler approach fails in a
non-obvious way. This file collects those failure modes so the knowledge lives
in one place instead of being re-discovered per project. Most were learned by
debugging a "flaky" local service that was actually five separate problems
wearing one trenchcoat.

## `.local` names in /etc/hosts stall for 5 seconds

`.local` is the mDNS domain (RFC 6762). A hosts-file line like
`127.0.0.2 myapp.local` answers only the **A** lookup; a dual-stack client
(`getaddrinfo` with `AF_UNSPEC` — every browser, every `curl` without `-4`)
also asks for **AAAA**, and macOS sends that query out as real multicast,
where nobody answers. Result: every uncached resolve takes the full mDNS
timeout (5s, per `scutil --dns`), surfacing as slow page loads, app-level
timeouts, or "can't resolve" depending on each client's patience. It looks
exactly like an unreliable name; the A record was never the problem.

The fix is a *registration* instead of a hosts entry: `mdns.AdvertiseLocal`
registers the A record **and an AAAA for ::1** with mDNSResponder's LocalOnly
interface, so both address families answer in single-digit milliseconds and
nothing appears on any network. (A client that tries ::1 first gets an
immediate connection-refused and falls back — that's ~0ms, not 5s.)

## A record registered LocalOnly still isn't authoritative

Registering only the A record LocalOnly does not stop the AAAA query from
multicasting: mDNSResponder is not authoritative for the name, so the missing
type is still asked on the wire and stalls as above. That's why
`AdvertiseLocal` always pairs the A records with an AAAA.

## /var/run does not survive a reboot

Anything recorded under `/var/run` (port80's state files, pf enable tokens)
is gone after a reboot — by design; the bindings themselves are gone too.
Anything that must exist from boot needs a service manager entry
(`dotlocal service install`), not a state file. Conversely: a state file that
*does* exist proves nothing about the live system, which is why `Verify`
inspects the actual interfaces and firewall instead of trusting the record.

## Firewall rules get flushed behind your back

On macOS, VPN clients, security products, and `pfctl -f` from any other tool
reload or disable pf without asking. Two consequences:

- A redirect that was installed once will eventually vanish while everything
  *about* it (state file, launchd job, hosts entry) still looks healthy.
  The only durable answer is a keeper that re-asserts on a timer
  (`dotlocal keep` / `port80.Reassert`).
- `pfctl -E`/`-X` reference counting only helps against other *well-behaved*
  tools. A blunt `pfctl -d` disables pf regardless of anyone's references.
  When re-enabling, take a fresh token only if pf is actually down —
  re-enabling unconditionally leaks one pf reference per heal.

`port80` loads rules into the stock `com.apple/*` sub-anchor rather than
editing `/etc/pf.conf`, so an OS update rewriting that file can't orphan the
rules — but a flush can still empty the sub-anchor, hence the keeper.

## When the redirect is down, the failure is confusing, not loud

If anything on the host listens on the wildcard (`*:80` — colima/Lima's ssh
port-forward is a classic, as is any container runtime publishing 80), then a
connection to `alias-ip:80` whose redirect has vanished doesn't get refused —
it lands **inside that other listener** and returns whatever it serves
(typically a 404 from some container ingress). The symptom says "the app is
broken" or "DNS is flaky"; the cause is a missing firewall rule plus an
unrelated wildcard socket. Check `lsof -nP -iTCP:80 -sTCP:LISTEN` before
blaming the name.

## Service definitions that embed paths rot when things move

A launchd plist / systemd unit written once, pointing at an absolute path in
a repo checkout, dies with exit 127 the day the repo moves — and launchd will
happily report `last exit code = 127` forever while everything looks
"installed". `dotlocal service install` therefore always rewrites the
definition (pointing at the resolved binary that ran the install) and
reloads; re-running install is the repair and upgrade procedure. Check
`launchctl print system/com.dotlocal.<name>` if a binding is missing after a
boot.

## Loopback aliases need a host route, not the subnet mask

Adding a second IP in a subnet the interface already carries, with that
subnet's mask, makes macOS install a REJECT route that silently drops all
traffic to the alias. Aliases are added as /32 host routes
(`netmask 255.255.255.255`), and stale host routes are cleared before
re-adding (`route -n delete`), or an orphaned REJECT route shadows the fresh
alias.

## Redirect targets must stay off 127.0.0.1 for LAN traffic

A pf `rdr` that rewrites a packet arriving on a physical interface to a
loopback destination gets dropped as a martian. LAN-mode rules therefore
redirect to the alias IP itself (port translation only). Loopback-mode rules
(`--local`) redirect loopback-to-loopback, where this rule doesn't apply.

## macOS resolver paths are not uniform

`dscacheutil`, `getaddrinfo`, `dns-sd`, and browsers' own resolvers can give
different answers for `.local` names (caches, hosts-file handling, mDNS
querying all differ). When debugging, test the path your client actually
uses — `curl` (getaddrinfo) and `dscacheutil -q host -a name x.local` can
disagree, and both can disagree with Chrome. A name that "sometimes works" is
usually two resolver paths giving different answers, not randomness.
