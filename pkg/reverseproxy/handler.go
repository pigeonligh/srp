package reverseproxy

import (
	"context"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"

	"github.com/charmbracelet/ssh"
	"github.com/pigeonligh/srp/pkg/auth"
	"github.com/pigeonligh/srp/pkg/nets"
	"github.com/pigeonligh/srp/pkg/protocol"
	"github.com/sirupsen/logrus"
	gossh "golang.org/x/crypto/ssh"
)

type Handler interface {
	PasswordHandler() ssh.PasswordHandler
	PublicKeyHandler() ssh.PublicKeyHandler

	HandleSSHRequest(ctx ssh.Context, srv *ssh.Server, req *gossh.Request) (bool, []byte)

	ConvertBindAddressToHostPort(bindAddress string) (string, string, bool)
	DialContext(ctx context.Context, network, addr string) (net.Conn, error)

	ListProxies() []string
	AddEventHandler(EventHandler)
}

type ld struct {
	l net.Listener
	d nets.NetDialer
}

type proxy struct {
	host   string
	port   string
	errCnt int
	lds    map[string]ld // sessionID => ld
	mutex  sync.Mutex
}

func (p *proxy) addLD(sessionID string, l net.Listener, d nets.NetDialer) error {
	p.mutex.Lock()
	defer p.mutex.Unlock()
	if len(p.lds) > 16 {
		return net.InvalidAddrError("too many forward requests for " + net.JoinHostPort(p.host, p.port))
	}
	if len(p.lds) > 0 {
		// 当有相同目标的隧道请求存在时，暂时不接受新的隧道请求，让代理的连接尽可能均衡地分布在不同的 server 实例上
		// 如果连续出现多个隧道请求，说明可能连接已经较为均匀分布了，因此可以接受多个隧道请求，多个隧道在服务内部进行负载均衡
		if p.errCnt < 5 {
			p.errCnt++
			return net.InvalidAddrError("forward request for " + net.JoinHostPort(p.host, p.port) + " already exists")
		}
	}
	p.errCnt = 0
	p.lds[sessionID] = ld{l: l, d: d}
	return nil
}

func (p *proxy) removeLD(sessionID string) bool {
	p.mutex.Lock()
	defer p.mutex.Unlock()
	_, ok := p.lds[sessionID]
	if ok {
		delete(p.lds, sessionID)
	}
	p.errCnt = 0
	return len(p.lds) == 0
}

func (p *proxy) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	p.mutex.Lock()
	defer p.mutex.Unlock()
	var lastErr error
	for _, ld := range p.lds {
		conn, err := ld.d.DialContext(ctx, network, addr)
		if err == nil {
			return conn, nil
		}
		lastErr = err
	}
	if lastErr == nil {
		lastErr = net.InvalidAddrError("no proxy for " + addr)
	}
	return nil, lastErr
}

type handler struct {
	authenticator auth.Authenticator
	authorizer    auth.Authorizer
	unixDirectory string

	// forwards map[string]net.Listener // uid => listener
	proxies map[string]*proxy // host:port => proxy
	sync.Mutex

	eventHandlers EventHandlers
}

func New(authenticator auth.Authenticator, authorizer auth.Authorizer, unixDirectory string) (Handler, error) {
	if unixDirectory == "" {
		dir, err := os.MkdirTemp("", "srp")
		if err != nil {
			return nil, err
		}
		unixDirectory = dir
	} else {
		err := os.MkdirAll(unixDirectory, os.ModePerm)
		if err != nil {
			return nil, err
		}
	}

	return &handler{
		authenticator: authenticator,
		authorizer:    authorizer,
		unixDirectory: unixDirectory,

		// forwards: make(map[string]net.Listener),
		proxies: make(map[string]*proxy),

		eventHandlers: make(EventHandlers, 0),
	}, nil
}

func (h *handler) PasswordHandler() ssh.PasswordHandler {
	return func(ctx ssh.Context, password string) bool {
		var ret bool
		if h.authenticator == nil {
			ret = true
		} else {
			ret = h.authenticator.Authenticate(ctx, auth.AuthenticateRequest{
				User:       ctx.User(),
				Password:   password,
				RemoteAddr: ctx.RemoteAddr(),
				LocalAddr:  ctx.LocalAddr(),
			})
		}

		ctx.SetValue(protocol.ContextKeyReverseProxyAuthed, ret)
		return ret
	}
}

func (h *handler) PublicKeyHandler() ssh.PublicKeyHandler {
	return func(ctx ssh.Context, key ssh.PublicKey) bool {
		var ret bool
		if h.authenticator == nil {
			ret = true
		} else {
			ret = h.authenticator.Authenticate(ctx, auth.AuthenticateRequest{
				User:       ctx.User(),
				PublicKey:  key,
				RemoteAddr: ctx.RemoteAddr(),
				LocalAddr:  ctx.LocalAddr(),
			})
		}

		ctx.SetValue(protocol.ContextKeyReverseProxyAuthed, ret)
		return ret
	}
}

func (h *handler) ConvertBindAddressToHostPort(bindAddress string) (string, string, bool) {
	bindAddress = strings.TrimPrefix(bindAddress, "/")
	host, portString, cut := strings.Cut(bindAddress, "/")
	if !cut {
		return "", "", false
	}
	port, _ := strconv.Atoi(portString)
	if port <= 0 {
		return "", "", false
	}
	return host, portString, true
}

func (h *handler) ProxyAlive(host, port string) bool {
	target := net.JoinHostPort(host, port)
	h.Lock()
	p, ok := h.proxies[target]
	h.Unlock()
	if !ok {
		return false
	}
	p.mutex.Lock()
	defer p.mutex.Unlock()
	return len(p.lds) > 0
}

func (h *handler) ListProxies() []string {
	h.Lock()
	defer h.Unlock()

	ret := make([]string, 0)
	for target := range h.proxies {
		ret = append(ret, target)
	}
	return ret
}

func (h *handler) AddEventHandler(eh EventHandler) {
	h.eventHandlers = append(h.eventHandlers, eh)
}

func (h *handler) HandleSSHRequest(ctx ssh.Context, srv *ssh.Server, req *gossh.Request) (bool, []byte) {
	authed, _ := ctx.Value(protocol.ContextKeyReverseProxyAuthed).(bool)
	if !authed {
		logrus.Infof("User %v is not allowed to handle reverse proxy request.", ctx.User())
		return false, []byte{}
	}

	conn := ctx.Value(ssh.ContextKeyConn).(*gossh.ServerConn)
	switch req.Type {
	case protocol.ForwardRequestType:
		logrus.Infof("Handle reverse proxy request for user %v", ctx.User())

		var reqPayload protocol.RemoteForwardRequest
		if err := gossh.Unmarshal(req.Payload, &reqPayload); err != nil {
			logrus.Errorf("Failed to parse payload for %v request: %v", req.Type, err)
			return false, []byte{}
		}

		host, port, ok := h.ConvertBindAddressToHostPort(reqPayload.BindUnixSocket)
		if !ok {
			logrus.Errorf("User %v request to proxy invalid target %v.", ctx.User(), reqPayload.BindUnixSocket)
			return false, []byte{}
		}
		if h.authorizer != nil {
			if !h.authorizer.Authorize(ctx, auth.AuthorizeRequest{
				User:       ctx.User(),
				Target:     net.JoinHostPort(host, port),
				RemoteAddr: ctx.RemoteAddr(),
				LocalAddr:  ctx.LocalAddr(),
			}) {
				logrus.Errorf("User %v request to proxy %v, but it's not allowed.", ctx.User(), reqPayload.BindUnixSocket)
				return false, []byte{}
			}
		}

		l, d := nets.ListenDialerWithBuffer(1024)
		err := h.addProxy(host, port, ctx.SessionID(), l, d)
		if err != nil {
			logrus.Errorf("Failed to add proxy for %v(%v:%v): %v", ctx.SessionID(), host, port, err)
			return false, []byte{}
		}
		go func() {
			<-ctx.Done()
			_ = l.Close()
		}()
		go func() {
			for {
				c, err := l.Accept()
				if err != nil {
					logrus.Errorf("Failed to accept connection for %v(%v:%v): %v", ctx.SessionID(), host, port, err)
					break
				}
				go handleConnection(c, conn, reqPayload.BindUnixSocket)
			}
			h.removeProxy(host, port, ctx.SessionID())
		}()
		return true, nil

	case protocol.CancelRequestType:
		logrus.Infof("Cancel reverse proxy request for user %v", ctx.User())

		var reqPayload protocol.RemoteForwardCancelRequest
		if err := gossh.Unmarshal(req.Payload, &reqPayload); err != nil {
			logrus.Errorf("Failed to parse payload for %v request: %v", req.Type, err)
			return false, []byte{}
		}

		host, port, ok := h.ConvertBindAddressToHostPort(reqPayload.BindUnixSocket)
		if !ok {
			logrus.Errorf("User %v request cancel %v, but it's not allowed.", ctx.User(), reqPayload.BindUnixSocket)
			return false, []byte{}
		}
		h.removeProxy(host, port, ctx.SessionID())
		return true, nil
	}

	logrus.Infof("Unknown request %v from user %v", req.Type, ctx.User())
	return false, []byte{}
}

func (h *handler) addProxy(host, port, sessionID string, l net.Listener, d nets.NetDialer) error {
	target := net.JoinHostPort(host, port)
	h.Lock()
	defer h.Unlock()
	p, ok := h.proxies[target]
	if !ok {
		p = &proxy{
			host: host,
			port: port,
			lds:  make(map[string]ld),
		}
		h.proxies[target] = p
		h.eventHandlers.OnAdd(host, port)
	}
	if err := p.addLD(sessionID, l, d); err != nil {
		return err
	}
	logrus.Infof("Forward request in %v %v is ready", sessionID, target)
	return nil
}

func (h *handler) removeProxy(host, port, sessionID string) {
	target := net.JoinHostPort(host, port)
	h.Lock()
	defer h.Unlock()
	p, ok := h.proxies[target]
	if ok {
		if p.removeLD(sessionID) {
			delete(h.proxies, target)
			h.eventHandlers.OnRemove(host, port)
		}
	}
	logrus.Infof("Forward request in %v %v is canceled", sessionID, target)
}

func (h *handler) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	h.Lock()
	p, ok := h.proxies[addr]
	h.Unlock()
	if !ok {
		return nil, net.InvalidAddrError("no proxy for " + addr)
	}
	return p.DialContext(ctx, network, addr)
}

func handleConnection(c net.Conn, conn *gossh.ServerConn, target string) {
	payload := gossh.Marshal(&protocol.RemoteForwardChannelData{
		SocketPath: target,
		Reserved:   "",
	})
	ch, reqs, err := conn.OpenChannel(protocol.ForwardedRequestType, payload)
	if err != nil {
		logrus.Errorf("Failed to open channel for %v: %v", target, err)
		c.Close()
		return
	}
	go gossh.DiscardRequests(reqs)
	go func() {
		defer ch.Close()
		defer c.Close()
		_ = nets.IOCopy(ch, c)
	}()
	go func() {
		defer ch.Close()
		defer c.Close()
		_ = nets.IOCopy(c, ch)
	}()
}
