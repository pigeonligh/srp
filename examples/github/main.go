package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/charmbracelet/wish"
	"github.com/pigeonligh/srp/pkg/proxy"
	"github.com/pigeonligh/srp/pkg/server"
	"github.com/sirupsen/logrus"
)

var (
	name    = "SRP Github Proxy"
	address = "0.0.0.0:8022"
	hostKey = "examples/common/host_key"
)

type GithubProvider struct{}

func (p GithubProvider) ProxyProvide(ctx context.Context, target string) (proxy.Proxy, error) {
	if target == "github.com:22" {
		return proxy.Direct("tcp", target), nil
	}
	return nil, fmt.Errorf("unsupported target: %s", target)
}

func main() {
	p := proxy.New(nil, nil, GithubProvider{}, true)
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
