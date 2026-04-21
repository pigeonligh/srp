package providers

import (
	"context"

	"github.com/pigeonligh/srp/pkg/nets"
	"github.com/pigeonligh/srp/pkg/proxy"
)

type netDialerProvider struct {
	dialer nets.NetDialer
}

func NetDialerProvider(d nets.NetDialer) proxy.ProxyProvider {
	return &netDialerProvider{dialer: d}
}

func (p *netDialerProvider) ProxyProvide(ctx context.Context, target string) (proxy.Proxy, error) {
	return proxy.DirectWithDialer("tcp", target, p.dialer), nil
}
