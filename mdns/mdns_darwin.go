//go:build darwin

package mdns

/*
#include <dns_sd.h>
#include <stdlib.h>
#include <arpa/inet.h>

// A no-op reply callback: we don't need the per-record registration result,
// but DNSServiceRegisterRecord requires a non-NULL callback.
static void dl_regCb(DNSServiceRef s, DNSRecordRef r, DNSServiceFlags f,
                     DNSServiceErrorType e, void *ctx) {
    (void)s; (void)r; (void)f; (void)e; (void)ctx;
}

// dl_regA registers one shared A record for host on the given interface index.
// Shared (not Unique) lets several A records coexist for the same name — one
// per LAN — which is exactly what a multi-homed host needs and what a
// `dns-sd -P` proxy registration could not do.
static DNSServiceErrorType dl_regA(DNSServiceRef ref, uint32_t ifindex,
                                   const char *host, const unsigned char *ip4) {
    DNSRecordRef rec;
    return DNSServiceRegisterRecord(ref, &rec, kDNSServiceFlagsShared, ifindex,
        host, kDNSServiceType_A, kDNSServiceClass_IN, 4, ip4, 120, dl_regCb, NULL);
}

// A no-op service-registration callback (DNSServiceRegister also requires one).
static void dl_regSvcCb(DNSServiceRef s, DNSServiceFlags f, DNSServiceErrorType e,
                        const char *n, const char *t, const char *d, void *ctx) {
    (void)s; (void)f; (void)e; (void)n; (void)t; (void)d; (void)ctx;
}

// dl_register registers the _http._tcp service (SRV + TXT + PTR) for name on
// the given interface index, riding the shared connection so it uses the same
// socket as the A records above. The explicit host makes the SRV target
// <name>.local. — backed by our own A records — rather than the machine's real
// hostname, and htons puts the port in network byte order as dns_sd expects.
static DNSServiceErrorType dl_register(DNSServiceRef shared, DNSServiceRef *out,
                                       uint32_t ifindex, const char *name,
                                       const char *host, uint16_t port,
                                       uint16_t txtLen, const void *txt) {
    *out = shared;
    return DNSServiceRegister(out, kDNSServiceFlagsShareConnection, ifindex,
        name, "_http._tcp", "local.", host, htons(port), txtLen, txt,
        dl_regSvcCb, NULL);
}
*/
import "C"

import (
	"fmt"
	"net"
	"strings"
	"sync"
	"unsafe"

	"golang.org/x/sys/unix"
)

// startResponder advertises the service on ifaceName with the system
// mDNSResponder (Bonjour) via the dns_sd C API. A self-hosted responder does
// not interoperate with Bonjour on macOS, so we drive the OS responder
// directly. It registers, all scoped to ifaceName's interface index so a
// multi-homed host resolves correctly on each LAN:
//
//   - one shared A record per IP (<name>.local. -> IP), and
//   - the _http._tcp service (SRV/TXT/PTR) with the given port and info TXT,
//     its SRV target pointed at <name>.local. so browsing matches Linux.
//
// The returned closer removes the registrations.
func startResponder(name, host string, port int, info, ifaceName string, ips []net.IP) (func() error, error) {
	var ref C.DNSServiceRef
	if e := C.DNSServiceCreateConnection(&ref); e != C.kDNSServiceErr_NoError {
		return nil, fmt.Errorf("mdns: DNSServiceCreateConnection failed (%d)", int(e))
	}

	fqdn := strings.TrimSuffix(host, ".") + "." // "fwrd.local."
	cHost := C.CString(fqdn)
	defer C.free(unsafe.Pointer(cHost))

	// Resolve the interface index up front: a zero index is
	// kDNSServiceInterfaceIndexAny, which would register the A record on every
	// interface and silently defeat the per-LAN scoping this whole design rests
	// on. Fail loudly instead of advertising on the wrong segments.
	ifi, err := net.InterfaceByName(ifaceName)
	if err != nil {
		C.DNSServiceRefDeallocate(ref)
		return nil, fmt.Errorf("mdns: looking up interface %s: %w", ifaceName, err)
	}
	ifindex := C.uint32_t(ifi.Index)

	for _, ip := range ips {
		ip4 := ip.To4()
		if ip4 == nil {
			continue
		}
		cip := (*C.uchar)(C.CBytes(ip4))
		e := C.dl_regA(ref, ifindex, cHost, cip)
		C.free(unsafe.Pointer(cip))
		if e != C.kDNSServiceErr_NoError {
			C.DNSServiceRefDeallocate(ref)
			return nil, fmt.Errorf("mdns: registering %s on %s failed (%d)", ip4, ifaceName, int(e))
		}
	}

	// Register the _http._tcp service on the same shared connection so its
	// SRV/TXT/PTR records sit alongside the A records and share one socket.
	cName := C.CString(name)
	defer C.free(unsafe.Pointer(cName))
	txt := encodeTXT(info)
	cTXT := C.CBytes(txt)
	defer C.free(cTXT)
	var svcRef C.DNSServiceRef
	if e := C.dl_register(ref, &svcRef, ifindex, cName, cHost,
		C.uint16_t(port), C.uint16_t(len(txt)), cTXT); e != C.kDNSServiceErr_NoError {
		C.DNSServiceRefDeallocate(ref)
		return nil, fmt.Errorf("mdns: registering _http._tcp for %s on %s failed (%d)", name, ifaceName, int(e))
	}

	// Pump the connection so the daemon's replies are drained. ProcessResult
	// runs only in this goroutine; Deallocate runs only after it has stopped,
	// so the (non-thread-safe) ref is never touched concurrently.
	fd := int(C.DNSServiceRefSockFD(ref))
	stop := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		fds := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLIN}}
		for {
			select {
			case <-stop:
				return
			default:
			}
			n, err := unix.Poll(fds, 500)
			if err != nil {
				if err == unix.EINTR {
					continue
				}
				return
			}
			if n > 0 {
				C.DNSServiceProcessResult(ref)
			}
		}
	}()

	var once sync.Once
	return func() error {
		once.Do(func() {
			close(stop)
			wg.Wait()
			// Deallocate the shared service ref before the connection it rode on.
			C.DNSServiceRefDeallocate(svcRef)
			C.DNSServiceRefDeallocate(ref)
		})
		return nil
	}, nil
}

// encodeTXT renders info as a single DNS-SD TXT entry in wire format: a length
// byte followed by the bytes. A TXT string maxes at 255 bytes, so an over-long
// info is truncated rather than producing a malformed record.
func encodeTXT(info string) []byte {
	if len(info) > 255 {
		info = info[:255]
	}
	return append([]byte{byte(len(info))}, info...)
}
