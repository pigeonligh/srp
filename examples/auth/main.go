package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"github.com/charmbracelet/wish"
	"github.com/pigeonligh/srp/pkg/auth"
	"github.com/pigeonligh/srp/pkg/proxy"
	"github.com/pigeonligh/srp/pkg/proxy/providers"
	"github.com/pigeonligh/srp/pkg/reverseproxy"
	"github.com/pigeonligh/srp/pkg/server"
	"github.com/sirupsen/logrus"
)

var (
	name    = "SRP Auth Example"
	address = "127.0.0.1:8022"
	hostKey = "examples/common/host_key"
)

func main() {
	rp, err := reverseproxy.New(
		auth.UserPublicKeysAuthenticator(auth.PublicKeysDir("examples/auth/reverseproxy_auth")),
		auth.UserGlobsAuthorizer(auth.UserGlobsDir("examples/auth/reverseproxy_rules")),
		"",
	)
	if err != nil {
		logrus.Fatalln("Error:", err)
	}
	p := proxy.New(
		auth.UserPublicKeysAuthenticator(auth.PublicKeysDir("examples/auth/proxy_auth")),
		auth.UserGlobsAuthorizer(auth.UserGlobsDir("examples/auth/proxy_rules")),
		providers.NetDialerProvider(rp),
		true,
	)

	s := server.New(
		name,
		server.WithReverseProxy(rp),
		server.WithProxy(p),
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
