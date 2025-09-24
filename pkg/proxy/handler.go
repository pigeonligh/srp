package proxy

import (
	"fmt"
	"net"

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

	HandleProxy(srv *ssh.Server, conn *gossh.ServerConn, newChan gossh.NewChannel, ctx ssh.Context)
}

type handler struct {
	authenticator auth.Authenticator
	authorizer    auth.Authorizer
	provider      ProxyProvider
	cacheEnabled  bool
	callbacks     ProxyCallbacks
}

func New(authenticator auth.Authenticator, authorizer auth.Authorizer, provider ProxyProvider, cacheEnabled bool) Handler {
	return &handler{
		authenticator: authenticator,
		authorizer:    authorizer,
		provider:      provider,
		cacheEnabled:  cacheEnabled,
	}
}

func NewWithOptions(options ...Option) Handler {
	h := &handler{}
	for _, opt := range options {
		opt(h)
	}
	return h
}

func (h *handler) PasswordHandler() ssh.PasswordHandler {
	return func(ctx ssh.Context, password string) bool {
		var ret bool
		if h.authenticator == nil {
			ret = true
		} else {
			ret = h.authenticator.Authenticate(ctx, auth.AuthenticateRequest{
				User:     ctx.User(),
				Password: password,
			})
		}

		ctx.SetValue(protocol.ContextKeyProxyAuthed, ret)
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
				User:      ctx.User(),
				PublicKey: key,
			})
		}

		ctx.SetValue(protocol.ContextKeyProxyAuthed, ret)
		return ret
	}
}

func (h *handler) GetProxy(ctx ssh.Context, target string) (Proxy, error) {
	authed, _ := ctx.Value(protocol.ContextKeyProxyAuthed).(bool)
	if !authed {
		return nil, fmt.Errorf("unauthenticated for proxy")
	}

	var cachedResult any
	if h.cacheEnabled {
		cacheKey := protocol.CachedProxyKey{Target: target}
		cachedResult = ctx.Value(cacheKey)
		if cachedResult != nil {
			if proxy, ok := cachedResult.(Proxy); ok {
				return proxy, nil
			}
			if err, ok := cachedResult.(error); ok {
				return nil, err
			}
		}
		defer func() {
			if cachedResult != nil {
				ctx.SetValue(cacheKey, cachedResult)
			}
		}()
	}

	if h.authorizer != nil {
		if !h.authorizer.Authorize(ctx, auth.AuthorizeRequest{
			User:   ctx.User(),
			Target: target,
		}) {
			err := fmt.Errorf("access denied")
			cachedResult = err
			return nil, err
		}
	}

	if h.provider == nil {
		return nil, fmt.Errorf("proxy provider is not set")
	}

	proxy, err := h.provider.ProxyProvide(ctx, target)
	if err != nil {
		cachedResult = err
		return nil, err
	}
	cachedResult = proxy
	return proxy, nil
}

func (h *handler) HandleProxy(srv *ssh.Server, conn *gossh.ServerConn, newChan gossh.NewChannel, ctx ssh.Context) {
	logrus.Infof("Handle direct-tcpip for user %v in %v", ctx.User(), ctx.SessionID())
	h.callbacks.OnHandleProxy(ctx)
	defer h.callbacks.OnHandleProxyDone(ctx)

	var payload protocol.DirectPayload
	err := gossh.Unmarshal(newChan.ExtraData(), &payload)
	if err != nil {
		logrus.Errorf("Cannot accept extra data for %v: %v", ctx.SessionID(), err)
		return
	}
	logrus.Infof("Payload for session %v: %v", ctx.SessionID(), payload)

	proxy, err := h.GetProxy(ctx, net.JoinHostPort(payload.Host, fmt.Sprint(payload.Port)))
	if err != nil {
		rejectErr := newChan.Reject(gossh.Prohibited, fmt.Sprintf("Cannot get proxy for session %v: %v", ctx.SessionID(), err))
		if rejectErr != nil {
			logrus.Errorf("Cannot reject channel for %v: %v", ctx.SessionID(), rejectErr)
		}

		h.callbacks.OnProxyCreateFailed(ctx, payload, err)
		logrus.Errorf("Cannot create proxy for %v: %v", ctx.SessionID(), err)
		return
	}
	h.callbacks.OnProxyCreated(ctx, payload)

	ch, _, err := newChan.Accept()
	if err != nil {
		h.callbacks.OnProxyChannelAcceptFailed(ctx, payload, err)
		logrus.Errorf("Cannot accept channel for %v: %v", ctx.SessionID(), err)
		return
	}
	defer ch.Close()
	h.callbacks.OnProxyChannelAccepted(ctx, payload)

	logrus.Infof("Proxy created for session %v.", ctx.SessionID())
	c, err := proxy.Dial(ctx)
	if err != nil {
		h.callbacks.OnProxyDialFailed(ctx, payload, err)
		logrus.Errorf("Cannot dial proxy for %v: %v", ctx.SessionID(), err)
		return
	}
	h.callbacks.OnProxyDialed(ctx, payload)
	err = nets.HandleConnections(c, ch)
	if err != nil {
		h.callbacks.OnProxyConnectionDone(ctx, payload, err)
		logrus.Errorf("Cannot handle proxy for %v: %v", ctx.SessionID(), err)
		return
	}

	h.callbacks.OnProxyConnectionDone(ctx, payload, nil)
	logrus.Infof("Proxy done for session %v.", ctx.SessionID())
}
