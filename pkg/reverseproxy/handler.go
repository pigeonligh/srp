package reverseproxy

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
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

	nets.SocketHandler
	ConvertBindAddressToHostPort(bindAddress string) (string, string, bool)
	ConvertBindAddressToSocket(bindAddress string) (string, bool)

	SocketList() []string
	AddEventHandler(EventHandler)
}

type handler struct {
	authenticator auth.Authenticator
	authorizer    auth.Authorizer
	unixDirectory string

	forwards map[string]net.Listener // uid => listener
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

		forwards: make(map[string]net.Listener),

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

func (h *handler) ConvertHostPortToSocket(host, port string) (string, bool) {
	return filepath.Join(h.unixDirectory, fmt.Sprintf("%v_%v.sock", host, port)), true
}

func (h *handler) ConvertBindAddressToSocket(bindAddress string) (string, bool) {
	host, port, ok := h.ConvertBindAddressToHostPort(bindAddress)
	if ok {
		return h.ConvertHostPortToSocket(host, port)
	}
	return "", false
}

func (h *handler) SocketAlive(socket string) bool {
	h.Lock()
	_, ok := h.forwards[socket]
	h.Unlock()
	return ok
}

func (h *handler) SocketList() []string {
	h.Lock()
	defer h.Unlock()

	ret := make([]string, 0)
	for socket := range h.forwards {
		ret = append(ret, socket)
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

		socket, _ := h.ConvertHostPortToSocket(host, port)
		ln, err := net.Listen("unix", socket)
		if err != nil {
			logrus.Errorf("Failed to listen UnixSocket %v: %v", socket, err)
			return false, []byte{}
		}
		h.Lock()
		h.forwards[socket] = ln
		h.eventHandlers.OnAdd(host, port)
		h.Unlock()

		go func() {
			<-ctx.Done()
			h.Lock()
			ln, ok := h.forwards[socket]
			h.Unlock()
			if ok {
				ln.Close()
			}
		}()

		go func() {
			for {
				c, err := ln.Accept()
				if err != nil {
					logrus.Errorf("Failed to accept connection for %v: %v", socket, err)
					break
				}

				go handleConnection(c, conn, reqPayload.BindUnixSocket)
			}
			h.Lock()
			delete(h.forwards, socket)
			h.eventHandlers.OnRemove(host, port)
			h.Unlock()
		}()

		logrus.Infof("Forward request in %v is ready", socket)
		return true, nil

	case protocol.CancelRequestType:
		logrus.Infof("Cancel reverse proxy request for user %v", ctx.User())

		var reqPayload protocol.RemoteForwardCancelRequest
		if err := gossh.Unmarshal(req.Payload, &reqPayload); err != nil {
			logrus.Errorf("Failed to parse payload for %v request: %v", req.Type, err)
			return false, []byte{}
		}

		socket, ok := h.ConvertBindAddressToSocket(reqPayload.BindUnixSocket)
		if !ok {
			logrus.Errorf("User %v request cancel %v, but it's not allowed.", ctx.User(), reqPayload.BindUnixSocket)
			return false, []byte{}
		}

		h.Lock()
		ln, ok := h.forwards[socket]
		h.Unlock()
		if ok {
			ln.Close()
			logrus.Infof("Forward request in %v is canneled", socket)
		}
		return true, nil
	}

	logrus.Infof("Unknown request %v from user %v", req.Type, ctx.User())
	return false, []byte{}
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
