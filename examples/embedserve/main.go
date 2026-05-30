// Command embedserve is a minimal example of the dotlocal pattern: a go:embed'd
// web app served as a named LAN service reachable at http://embedserve.local.
//
//	go run ./examples/embedserve
//	# then, from any device on the LAN:  http://embedserve.local:8080
package main

import (
	"context"
	"embed"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"github.com/pders01/dotlocal"
)

//go:embed static
var static embed.FS

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	err := dotlocal.Run(ctx, dotlocal.Config{
		Name:      "embedserve",
		Handler:   http.FileServerFS(static),
		Addr:      "0.0.0.0:8080",
		Advertise: true,
		OnReady: func(r dotlocal.Ready) {
			log.Printf("listening on %s", r.Addr)
			if r.Name != "" {
				log.Printf("reachable at http://%s:8080  (on %v)", r.Name, r.Targets)
			}
			if r.AdvertiseErr != nil {
				log.Printf("mDNS disabled: %v", r.AdvertiseErr)
			}
		},
	})
	if err != nil {
		log.Fatal(err)
	}
}
