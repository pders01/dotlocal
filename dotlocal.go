// Package dotlocal turns an http.Handler into a named service on the local
// network: it binds a port, advertises <Name>.local over mDNS (correctly
// scoped across every LAN on a multi-homed host), and serves with graceful
// shutdown — the companion to the go:embed'd local-web-app pattern.
//
// The common case is one call:
//
//	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
//	defer stop()
//	err := dotlocal.Run(ctx, dotlocal.Config{Name: "fwrd", Handler: app})
//
// To reach it at a bare http://<Name>.local (port 80) without a privileged
// bind or a host :80 collision, see the port80 subpackage (a separate,
// root-only step); advertise its alias IPs with mdns.AdvertiseScoped.
package dotlocal

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"time"

	"github.com/pders01/dotlocal/mdns"
)

// shutdownGrace bounds how long Run waits for in-flight requests to drain
// after the context is cancelled before forcing connections closed.
const shutdownGrace = 15 * time.Second

// Config configures Run. Only Name and Handler are required.
type Config struct {
	Name       string       // bare label, e.g. "fwrd" → advertised as fwrd.local
	Handler    http.Handler // the service to expose (e.g. your go:embed'd app)
	Addr       string       // bind address; default "0.0.0.0:8080"
	Advertise  bool         // advertise <Name>.local over mDNS
	Interfaces []string     // restrict mDNS to these interfaces; empty = auto LAN
	Info       string       // mDNS TXT text; default "<Name> (dotlocal)"

	// OnReady, if set, is called once the listener is bound (and mDNS started),
	// before serving. Use it to log the reachable URLs. AdvertiseErr is non-nil
	// if mDNS failed — serving continues regardless.
	OnReady func(Ready)
}

// Ready reports the bound state to the OnReady callback.
type Ready struct {
	Addr         string   // the actual listen address
	Name         string   // "<Name>.local" when advertising, else ""
	Targets      []string // advertised "iface=ip" pairs, when advertising
	AdvertiseErr error    // non-nil if mDNS advertising failed (non-fatal)
}

// Run binds Config.Addr, optionally advertises <Name>.local over mDNS, and
// serves Config.Handler until ctx is cancelled, then shuts down gracefully.
// It returns nil on a clean shutdown. A bind failure (e.g. the port is in use)
// is returned immediately, before anything is advertised.
func Run(ctx context.Context, c Config) error {
	if c.Name == "" {
		return errors.New("dotlocal: Name is required")
	}
	if c.Handler == nil {
		return errors.New("dotlocal: Handler is required")
	}
	addr := c.Addr
	if addr == "" {
		addr = "0.0.0.0:8080"
	}

	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("cannot bind %s: %w", addr, err)
	}
	defer ln.Close()

	var adv *mdns.Advertiser
	ready := Ready{Addr: ln.Addr().String()}
	if c.Advertise {
		if _, portStr, perr := net.SplitHostPort(addr); perr == nil {
			if port, aerr := strconv.Atoi(portStr); aerr == nil {
				adv, ready.AdvertiseErr = mdns.Advertise(c.Name, port,
					mdns.Options{Info: c.Info, Interfaces: c.Interfaces})
			} else {
				ready.AdvertiseErr = fmt.Errorf("invalid port %q: %w", portStr, aerr)
			}
		} else {
			ready.AdvertiseErr = fmt.Errorf("cannot parse addr %q: %w", addr, perr)
		}
		if adv != nil {
			ready.Name = c.Name + ".local"
			ready.Targets = adv.Targets
			defer adv.Close()
		}
	}

	if c.OnReady != nil {
		c.OnReady(ready)
	}

	srv := &http.Server{
		Handler:           c.Handler,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      120 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	serveErr := make(chan error, 1)
	go func() { serveErr <- srv.Serve(ln) }()

	select {
	case err := <-serveErr:
		return err
	case <-ctx.Done():
		shutCtx, cancel := context.WithTimeout(context.Background(), shutdownGrace)
		defer cancel()
		if err := srv.Shutdown(shutCtx); err != nil {
			return fmt.Errorf("graceful shutdown: %w", err)
		}
		if err := <-serveErr; err != nil && !errors.Is(err, http.ErrServerClosed) {
			return err
		}
		return nil
	}
}
