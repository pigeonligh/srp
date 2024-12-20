package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"github.com/charmbracelet/wish"
	"github.com/pigeonligh/srp/pkg/proxy"
	"github.com/pigeonligh/srp/pkg/proxy/providers"
	"github.com/pigeonligh/srp/pkg/server"
	"github.com/sirupsen/logrus"
)

var (
	name    = "SRP Proxy Only Example"
	address = "127.0.0.1:8022"
	hostKey = "examples/common/host_key"
)

func main() {
	p := proxy.New(nil, nil, providers.TCPProvider, true)
	s := server.New(
		name,
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
