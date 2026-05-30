//go:build darwin

package mdns

/*
#include <dns_sd.h>
#include <stdlib.h>

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

// startResponder registers <name>.local for each IP with the system
// mDNSResponder (Bonjour) via the dns_sd C API. A self-hosted responder does
// not interoperate with Bonjour on macOS, so we drive the OS responder
// directly. Each address is a shared A record scoped to ifaceName's interface
// index, so on a multi-homed host the name resolves to the right address on
// each LAN. The returned closer removes the registrations.
func startResponder(name, host string, port int, info, ifaceName string, ips []net.IP) (func() error, error) {
	var ref C.DNSServiceRef
	if e := C.DNSServiceCreateConnection(&ref); e != C.kDNSServiceErr_NoError {
		return nil, fmt.Errorf("mdns: DNSServiceCreateConnection failed (%d)", int(e))
	}

	fqdn := strings.TrimSuffix(host, ".") + "." // "fwrd.local."
	cHost := C.CString(fqdn)
	defer C.free(unsafe.Pointer(cHost))

	var ifindex C.uint32_t
	if ifi, err := net.InterfaceByName(ifaceName); err == nil {
		ifindex = C.uint32_t(ifi.Index)
	}

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
			C.DNSServiceRefDeallocate(ref)
		})
		return nil
	}, nil
}
