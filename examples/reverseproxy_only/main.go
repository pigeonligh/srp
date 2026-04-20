package main

import (
	"context"
	"net"
	"net/http"
	"net/http/httputil"
	"os"
	"os/signal"
	"syscall"

	"github.com/charmbracelet/wish"
	"github.com/pigeonligh/srp/pkg/proxy/providers"
	"github.com/pigeonligh/srp/pkg/reverseproxy"
	"github.com/pigeonligh/srp/pkg/server"
	"github.com/sirupsen/logrus"
)

var (
	name        = "SRP Reverse Proxy Only Example"
	address     = "127.0.0.1:8022"
	httpAddress = "127.0.0.1:8008"
	hostKey     = "examples/common/host_key"
)

func main() {
	rp, err := reverseproxy.New(nil, nil, "")
	if err != nil {
		logrus.Fatalln("Error:", err)
	}
	provider := providers.NetDialerProvider(rp)
	go func() {
		http.ListenAndServe(httpAddress, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			target := r.Host
			if _, _, err := net.SplitHostPort(target); err != nil {
				target = target + ":80"
			}
			proxy, _ := provider.ProxyProvide(r.Context(), target)

			r.URL.Scheme = "http"
			r.URL.Host = target
			(&httputil.ReverseProxy{
				Director: func(*http.Request) {},
				Transport: &http.Transport{
					DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
						return proxy.Dial(r.Context())
					},
				},
			}).ServeHTTP(w, r)
		}))
	}()
	s := server.New(
		name,
		server.WithReverseProxy(rp),
		server.WithSSHOptions(
			wish.WithHostKeyPath(hostKey),
			wish.WithAddress(address),
		),
	)

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	if err := s.Run(ctx); err != nil {
		logrus.Fatalln("Error:", err)
	}
}
