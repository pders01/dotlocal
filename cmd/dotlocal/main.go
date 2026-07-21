// Command dotlocal exposes the dotlocal library to non-Go services: give any
// local HTTP server a <name>.local address on a standard port, from a shell
// script, an installer, or a service manager.
//
//	dotlocal up      --name app --ip 127.0.0.2 --to-port 8080 --local   (root)
//	dotlocal down    --name app                                         (root)
//	dotlocal status  --name app
//	dotlocal keep    --name app --ip 127.0.0.2 --to-port 8080 --local   (root, long-running)
//	dotlocal service install|uninstall ...                              (root)
//
// up/down/status manage the network binding (alias IP + firewall redirect —
// see dotlocal/port80). keep is the long-running counterpart meant to run
// under launchd/systemd: it ensures the binding, holds the mDNS registration
// (which lives only as long as its process), and re-asserts the binding on a
// timer, healing after anything flushes or disables the firewall behind our
// back. service install/uninstall manage that daemon.
//
// --local scopes everything to this machine: loopback alias IPs, and a
// registration on mDNSResponder's LocalOnly interface instead of multicast.
// Without it, alias IPs go on the LAN interfaces their subnets match and the
// name is advertised to the network (the library's original mode).
package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/pders01/dotlocal/mdns"
	"github.com/pders01/dotlocal/port80"
)

func main() {
	log.SetFlags(log.LstdFlags)
	log.SetPrefix("dotlocal: ")
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "up":
		err = cmdUp(os.Args[2:])
	case "down":
		err = cmdDown(os.Args[2:])
	case "status":
		err = cmdStatus(os.Args[2:])
	case "keep":
		err = cmdKeep(os.Args[2:])
	case "service":
		err = cmdService(os.Args[2:])
	case "-h", "--help", "help":
		usage()
	default:
		usage()
		os.Exit(2)
	}
	if err != nil {
		log.Fatal(err)
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `usage: dotlocal <command> [flags]

  up       add the alias IP(s) and firewall redirect (root)
  down     remove them (root)
  status   print the recorded binding and whether it is in force
  keep     up + hold the mDNS registration + self-heal on a timer (root)
  service  install/uninstall a system service running keep (root)

run 'dotlocal <command> -h' for the command's flags
`)
}

// bindingFlags are the flags shared by every command that describes a binding.
type bindingFlags struct {
	name   string
	ips    string
	iface  string
	ports  string
	toPort int
	local  bool
	info   string
}

func addBindingFlags(fs *flag.FlagSet) *bindingFlags {
	bf := &bindingFlags{}
	fs.StringVar(&bf.name, "name", "", "service name; reachable as <name>.local (required)")
	fs.StringVar(&bf.ips, "ip", "", "comma-separated alias IP(s) to give the service (required)")
	fs.StringVar(&bf.iface, "iface", "", "interface for the alias IPs; default: derived from each IP's subnet (loopback with --local)")
	fs.StringVar(&bf.ports, "ports", "80", "comma-separated public port(s) to redirect")
	fs.IntVar(&bf.toPort, "to-port", 8080, "the service's real (unprivileged) port")
	fs.BoolVar(&bf.local, "local", false, "this machine only: loopback aliases + LocalOnly mDNS registration, nothing on the network")
	fs.StringVar(&bf.info, "info", "", "mDNS TXT text (keep/service only)")
	return bf
}

// loopbackIface is where --local puts its alias IPs.
func loopbackIface() string {
	if runtime.GOOS == "darwin" {
		return "lo0"
	}
	return "lo"
}

// options turns the flags into validated port80 Options plus the parsed IPs.
func (bf *bindingFlags) options() (port80.Options, []net.IP, error) {
	var o port80.Options
	if bf.name == "" {
		return o, nil, errors.New("--name is required")
	}
	if bf.ips == "" {
		return o, nil, errors.New("--ip is required")
	}
	var ips []net.IP
	for _, s := range strings.Split(bf.ips, ",") {
		s = strings.TrimSpace(s)
		ip := net.ParseIP(s)
		if ip == nil || ip.To4() == nil {
			return o, nil, fmt.Errorf("--ip %q is not a valid IPv4 address", s)
		}
		if bf.local != ip.IsLoopback() {
			if bf.local {
				return o, nil, fmt.Errorf("--local requires loopback IPs (got %s); use 127.0.0.x", s)
			}
			return o, nil, fmt.Errorf("%s is a loopback IP; add --local", s)
		}
		ips = append(ips, ip)
	}
	var ports []int
	for _, s := range strings.Split(bf.ports, ",") {
		p, err := strconv.Atoi(strings.TrimSpace(s))
		if err != nil {
			return o, nil, fmt.Errorf("--ports: %q is not a port number", s)
		}
		ports = append(ports, p)
	}
	o = port80.Options{Name: bf.name, Ports: ports, ToPort: bf.toPort}
	for _, ip := range ips {
		iface := bf.iface
		if iface == "" && bf.local {
			iface = loopbackIface()
		}
		if iface == "" {
			detected, err := port80.DetectIface(ip.String())
			if err != nil {
				return o, nil, fmt.Errorf("cannot derive the interface for %s (pass --iface): %w", ip, err)
			}
			iface = detected
		}
		o.Aliases = append(o.Aliases, port80.Alias{Iface: iface, AliasIP: ip.String()})
	}
	return o, ips, nil
}

func cmdUp(args []string) error {
	fs := flag.NewFlagSet("up", flag.ExitOnError)
	bf := addBindingFlags(fs)
	_ = fs.Parse(args)
	o, _, err := bf.options()
	if err != nil {
		return err
	}
	st, err := port80.Up(o)
	if err != nil {
		return err
	}
	log.Printf("binding %s is up: %s", st.Name, describe(st))
	return nil
}

func cmdDown(args []string) error {
	fs := flag.NewFlagSet("down", flag.ExitOnError)
	name := fs.String("name", "", "service name (required)")
	_ = fs.Parse(args)
	if *name == "" {
		return errors.New("--name is required")
	}
	st, err := port80.Down(*name)
	if err != nil {
		return err
	}
	log.Printf("binding %s is down: %s", st.Name, describe(st))
	return nil
}

func cmdStatus(args []string) error {
	fs := flag.NewFlagSet("status", flag.ExitOnError)
	name := fs.String("name", "", "service name (required)")
	_ = fs.Parse(args)
	if *name == "" {
		return errors.New("--name is required")
	}
	st, err := port80.Status(*name)
	if err != nil {
		return err
	}
	out := struct {
		*port80.State
		InForce bool   `json:"in_force"`
		Problem string `json:"problem,omitempty"`
	}{State: st, InForce: true}
	if verr := port80.Verify(*name); verr != nil {
		out.InForce = false
		out.Problem = verr.Error()
	}
	b, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		return err
	}
	fmt.Println(string(b))
	return nil
}

// sameBinding reports whether a recorded binding matches what the flags ask
// for, on the fields that matter for traffic: aliases, public ports, target
// port. Order-insensitive; ignores masks/prefixes (defaulted internally).
func sameBinding(a, b *port80.Options) bool {
	if a.ToPort != b.ToPort || len(a.Aliases) != len(b.Aliases) {
		return false
	}
	ap, bp := normPorts(a), normPorts(b)
	if !slices.Equal(ap, bp) {
		return false
	}
	key := func(al port80.Alias) string { return al.Iface + "=" + al.AliasIP }
	ak := make([]string, 0, len(a.Aliases))
	bk := make([]string, 0, len(b.Aliases))
	for _, al := range a.Aliases {
		ak = append(ak, key(al))
	}
	for _, al := range b.Aliases {
		bk = append(bk, key(al))
	}
	slices.Sort(ak)
	slices.Sort(bk)
	return slices.Equal(ak, bk)
}

// normPorts returns the effective public-port set, sorted. An empty Ports
// falls back to the scalar Port the same way applyDefaults does.
func normPorts(o *port80.Options) []int {
	ports := o.Ports
	if len(ports) == 0 && o.Port != 0 {
		ports = []int{o.Port}
	}
	ports = slices.Clone(ports)
	slices.Sort(ports)
	return ports
}

func cmdKeep(args []string) error {
	fs := flag.NewFlagSet("keep", flag.ExitOnError)
	bf := addBindingFlags(fs)
	interval := fs.Duration("interval", 10*time.Minute, "how often to verify and re-assert the binding")
	_ = fs.Parse(args)
	o, ips, err := bf.options()
	if err != nil {
		return err
	}

	// Converge the binding to what the flags describe: create it if absent,
	// replace it if it exists with different parameters, heal it in place if
	// it matches (a recorded binding may not be in force after a reboot or a
	// firewall reload — /var/run does not survive either).
	st, err := port80.Status(o.Name)
	switch {
	case errors.Is(err, port80.ErrNoBinding):
		st, err = port80.Up(o)
	case err != nil:
	case sameBinding(&st.Options, &o):
		st, err = port80.Reassert(o.Name)
	default:
		log.Printf("binding %s exists with different parameters (%s); replacing", o.Name, describe(st))
		if _, derr := port80.Down(o.Name); derr != nil {
			log.Printf("replacing binding %s: teardown: %v", o.Name, derr)
		}
		st, err = port80.Up(o)
	}
	if err != nil {
		return err
	}
	log.Printf("binding %s is up: %s", st.Name, describe(st))

	// The registration lives exactly as long as this process: mDNSResponder
	// (or the self-hosted responder) withdraws the records when we exit, which
	// is why keep, not up, owns advertising.
	opts := mdns.Options{Info: bf.info}
	var adv *mdns.Advertiser
	if bf.local {
		adv, err = mdns.AdvertiseLocal(o.Name, o.Ports[0], ips, opts)
	} else {
		adv, err = mdns.AdvertiseScoped(o.Name, o.Ports[0], ips, opts)
	}
	if err != nil {
		return fmt.Errorf("advertising %s.local: %w", o.Name, err)
	}
	defer adv.Close()
	log.Printf("registered %s -> %s", adv.Host, strings.Join(adv.Targets, ", "))

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
	tick := time.NewTicker(*interval)
	defer tick.Stop()
	for {
		select {
		case <-stop:
			// Leave the binding in place: keep is a keeper, not the owner —
			// `dotlocal down` (or service uninstall) is the explicit teardown,
			// and launchd/systemd restarting us must not flap the redirect.
			log.Printf("stopping; binding %s stays up", o.Name)
			return nil
		case <-tick.C:
			if verr := port80.Verify(o.Name); verr != nil {
				log.Printf("binding %s is not in force (%v); re-asserting", o.Name, verr)
				if _, rerr := port80.Reassert(o.Name); rerr != nil {
					log.Printf("re-asserting %s failed: %v", o.Name, rerr)
				} else {
					log.Printf("binding %s re-asserted", o.Name)
				}
			}
		}
	}
}

// describe renders a binding one-line for logs.
func describe(st *port80.State) string {
	parts := make([]string, 0, len(st.Aliases))
	for _, a := range st.Aliases {
		parts = append(parts, a.Iface+"="+a.AliasIP)
	}
	ports := make([]string, 0, len(st.Ports))
	for _, p := range st.Ports {
		ports = append(ports, strconv.Itoa(p))
	}
	return fmt.Sprintf("%s port %s -> %d", strings.Join(parts, ","), strings.Join(ports, ","), st.ToPort)
}

func cmdService(args []string) error {
	if len(args) < 1 {
		return errors.New("usage: dotlocal service install|uninstall [flags]")
	}
	switch args[0] {
	case "install":
		fs := flag.NewFlagSet("service install", flag.ExitOnError)
		bf := addBindingFlags(fs)
		interval := fs.Duration("interval", 10*time.Minute, "how often the daemon re-asserts the binding")
		_ = fs.Parse(args[1:])
		o, _, err := bf.options()
		if err != nil {
			return err
		}
		return serviceInstall(bf, &o, *interval)
	case "uninstall":
		fs := flag.NewFlagSet("service uninstall", flag.ExitOnError)
		name := fs.String("name", "", "service name (required)")
		_ = fs.Parse(args[1:])
		if *name == "" {
			return errors.New("--name is required")
		}
		return serviceUninstall(*name)
	default:
		return fmt.Errorf("unknown service subcommand %q (want install or uninstall)", args[0])
	}
}

// keepArgs rebuilds the keep command line the service definition runs. The
// flag values are re-serialized (rather than passing os.Args through) so the
// installed service is exactly the parsed, validated configuration.
func keepArgs(bf *bindingFlags, interval time.Duration) []string {
	args := []string{"keep",
		"--name", bf.name,
		"--ip", bf.ips,
		"--ports", bf.ports,
		"--to-port", strconv.Itoa(bf.toPort),
		"--interval", interval.String(),
	}
	if bf.local {
		args = append(args, "--local")
	}
	if bf.iface != "" {
		args = append(args, "--iface", bf.iface)
	}
	if bf.info != "" {
		args = append(args, "--info", bf.info)
	}
	return args
}
