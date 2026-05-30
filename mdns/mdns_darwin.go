//go:build darwin

package mdns

import (
	"fmt"
	"net"
	"os/exec"
	"strconv"
	"strings"
)

// startResponder registers <name>.local for each IP with the system
// mDNSResponder (Bonjour) via a long-lived `dns-sd -P` proxy registration. A
// second self-hosted responder on macOS does not interoperate with Bonjour, so
// its records never resolve; driving the OS responder is the reliable path.
//
// ifaceName is unused: Bonjour scopes its answers to the receiving interface
// itself, so registering the address is enough. One registration runs per IP;
// the returned closer stops them all.
func startResponder(name, host string, port int, info, ifaceName string, ips []net.IP) (func() error, error) {
	hostName := strings.TrimSuffix(host, ".") // dns-sd wants "name.local", not the FQDN dot
	var procs []*exec.Cmd
	stop := func() error {
		var firstErr error
		for _, c := range procs {
			if c.Process == nil {
				continue
			}
			if err := c.Process.Kill(); err != nil && firstErr == nil {
				firstErr = err
			}
			_ = c.Wait()
		}
		return firstErr
	}
	for _, ip := range ips {
		// dns-sd -P <Name> <Type> <Domain> <Port> <Host> <IPv4> [TXT...]
		cmd := exec.Command("dns-sd", "-P", name, "_http._tcp", "local",
			strconv.Itoa(port), hostName, ip.String(), info)
		if err := cmd.Start(); err != nil {
			_ = stop()
			return nil, fmt.Errorf("dns-sd -P for %s: %w", ip, err)
		}
		procs = append(procs, cmd)
	}
	return stop, nil
}
