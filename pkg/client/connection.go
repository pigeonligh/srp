package client

import (
	"context"
	"fmt"
	"io"
	"net"
	"sync"

	"github.com/pigeonligh/srp/pkg/dialer"
	gossh "golang.org/x/crypto/ssh"
	"golang.org/x/sync/errgroup"
)

type Connection interface {
	Run(ctx context.Context) error
}

type sshConnection struct {
	config ConnConfig
	dialer dialer.SSHDialer
}

func NewSSHConnection(config ConnConfig, dialer dialer.SSHDialer) Connection {
	return &sshConnection{
		config: config,
		dialer: dialer,
	}
}

func (c *sshConnection) Run(ctx context.Context) error {
	config := &gossh.ClientConfig{
		User:            c.config.User,
		Auth:            c.config.AuthMethods,
		HostKeyCallback: gossh.InsecureIgnoreHostKey(),
	}

	client, err := c.dialer.DialContext(ctx, c.config.Network, c.config.Address, config)
	if err != nil {
		return err
	}
	defer func() {
		_ = client.Close()
	}()

	errCh := make(chan error)
	defer close(errCh)

	var wg sync.WaitGroup
	defer wg.Wait()

	for _, proxy := range c.config.Proxies {
		wg.Add(1)
		go func(proxy ProxyConfig) {
			defer wg.Done()

			if err := handleSSHProxy(client, proxy); err != nil {
				select {
				case errCh <- err:
				default:
				}
			}
		}(proxy)
	}

	select {
	case <-ctx.Done():
		return nil

	case err = <-errCh:
		return err
	}
}

func handleSSHProxy(client *gossh.Client, proxy ProxyConfig) error {
	switch proxy.Type {
	case DynamicForward:
		return fmt.Errorf("TODO")

	case LocalForward:
		return handleForward(
			func() (net.Listener, error) {
				return net.Listen(proxy.Network, net.JoinHostPort(proxy.LocalHost, proxy.LocalPort))
			},
			func(net.Conn) (net.Conn, error) {
				network := proxy.Network
				address := net.JoinHostPort(proxy.RemoteHost, proxy.RemotePort)
				return client.Dial(network, address)
			},
			client.Wait,
			func(err error) {},
		)

	case RemoteForward:
		return handleForward(
			func() (net.Listener, error) {
				return client.ListenUnix(fmt.Sprintf("/%v/%v", proxy.RemoteHost, proxy.RemotePort))
			},
			func(c net.Conn) (net.Conn, error) {
				network := c.RemoteAddr().Network()
				address := net.JoinHostPort(proxy.LocalHost, proxy.LocalPort)
				return net.Dial(network, address)
			},
			nil,
			func(err error) {},
		)
	}

	return fmt.Errorf("unknown proxy type")
}

func handleForward(
	listen func() (net.Listener, error),
	dial func(net.Conn) (net.Conn, error),
	errFunc func() error,
	errLogger func(error),
) error {
	l, err := listen()
	if err != nil {
		return err
	}

	errCh := make(chan error)

	if errFunc != nil {
		go func() {
			err := errFunc()
			_ = l.Close()
			errCh <- err
		}()
	} else {
		defer func() {
			_ = l.Close()
		}()
	}

	go func() {
		err := dialer.HandleListener(l, func(c net.Conn) {
			conn, err := dial(c)
			if err != nil {
				if errLogger != nil {
					errLogger(err)
				}
				return
			}
			defer func() {
				_ = conn.Close()
			}()

			if err := handleConnections(c, conn); err != nil {
				if errLogger != nil {
					errLogger(err)
				}
			}
		})
		if errFunc == nil {
			errCh <- err
		}
	}()
	return <-errCh
}

func handleConnections(c1, c2 net.Conn) error {
	var pipes errgroup.Group
	pipes.Go(func() error {
		_, err := io.Copy(c1, c2)
		return err
	})
	pipes.Go(func() error {
		_, err := io.Copy(c2, c1)
		return err
	})

	return pipes.Wait()
}