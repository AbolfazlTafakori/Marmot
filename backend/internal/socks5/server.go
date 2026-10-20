package socks5

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"sync"
	"time"

	"marmot/internal/core"
)

// handshakeTimeout bounds the greeting and request of one client.
const handshakeTimeout = 10 * time.Second

// Opener carries traffic for a destination. Connect returns a byte
// stream; Datagram returns a stream of framed datagrams (frame.WriteDatagram)
// for one UDP destination. An error that implements Replier chooses the
// SOCKS reply code; any other error is a general failure.
type Opener interface {
	Connect(ctx context.Context, dst Addr, client netip.AddrPort) (io.ReadWriteCloser, error)
	Datagram(ctx context.Context, dst Addr, client netip.AddrPort) (io.ReadWriteCloser, error)
}

// Replier is implemented by Opener errors that map to a specific reply.
type Replier interface {
	SocksReply() byte
}

func replyFor(err error) byte {
	var r Replier
	if errors.As(err, &r) {
		return r.SocksReply()
	}
	return RepGeneralFailure
}

// Config configures a Server.
type Config struct {
	Listen         netip.AddrPort
	Opener         Opener
	UDPIdleTimeout time.Duration
	Logger         *slog.Logger
}

// Server is a running SOCKS5 listener.
type Server struct {
	cfg Config
	log *slog.Logger
	ln  *net.TCPListener
	ctx context.Context
	end context.CancelFunc

	mu    sync.Mutex
	conns map[net.Conn]struct{}
	wg    sync.WaitGroup
}

// Listen binds the listener and starts serving.
func Listen(cfg Config) (*Server, error) {
	if cfg.Opener == nil || cfg.UDPIdleTimeout <= 0 {
		return nil, errors.New("socks5: opener and udp idle timeout are required")
	}
	ln, err := net.ListenTCP("tcp", net.TCPAddrFromAddrPort(cfg.Listen))
	if err != nil {
		return nil, fmt.Errorf("socks5 listen %s: %w", cfg.Listen, err)
	}
	log := cfg.Logger
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	ctx, end := context.WithCancel(context.Background())
	s := &Server{cfg: cfg, log: log, ln: ln, ctx: ctx, end: end, conns: map[net.Conn]struct{}{}}
	s.wg.Add(1)
	go s.acceptLoop()
	log.Info("socks5 listening", "addr", ln.Addr().String())
	return s, nil
}

// Addr returns the bound address.
func (s *Server) Addr() netip.AddrPort { return s.ln.Addr().(*net.TCPAddr).AddrPort() }

// Close stops the listener, ends every client and waits.
func (s *Server) Close() error {
	s.end()
	err := s.ln.Close()
	s.mu.Lock()
	for c := range s.conns {
		_ = c.Close()
	}
	s.mu.Unlock()
	s.wg.Wait()
	return err
}

func (s *Server) acceptLoop() {
	defer s.wg.Done()
	for {
		c, err := s.ln.AcceptTCP()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			continue
		}
		if !s.track(c) {
			_ = c.Close()
			return
		}
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			defer s.untrack(c)
			defer func() { _ = c.Close() }()
			s.handle(c)
		}()
	}
}

func (s *Server) track(c net.Conn) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.ctx.Err() != nil {
		return false
	}
	s.conns[c] = struct{}{}
	return true
}

func (s *Server) untrack(c net.Conn) {
	s.mu.Lock()
	delete(s.conns, c)
	s.mu.Unlock()
}

func (s *Server) handle(c *net.TCPConn) {
	client := c.RemoteAddr().(*net.TCPAddr).AddrPort()
	_ = c.SetDeadline(time.Now().Add(handshakeTimeout))
	if err := negotiate(c); err != nil {
		return
	}
	req, err := readRequest(c)
	if err != nil {
		rep := RepGeneralFailure
		if errors.Is(err, ErrAddrType) {
			rep = RepAddrNotSupported
		}
		_ = writeReply(c, rep, Addr{})
		return
	}
	switch req.cmd {
	case cmdConnect:
		s.connect(c, client, req.dst)
	case cmdUDPAssociate:
		s.associate(c, client)
	default: // BIND and anything else
		_ = writeReply(c, RepCommandNotSupported, Addr{})
	}
}

func (s *Server) connect(c *net.TCPConn, client netip.AddrPort, dst Addr) {
	ctx, cancel := context.WithTimeout(s.ctx, handshakeTimeout)
	st, err := s.cfg.Opener.Connect(ctx, dst, client)
	cancel()
	if err != nil {
		s.log.Debug("socks5 connect failed", "dst", dst.String(), "err", err)
		_ = writeReply(c, replyFor(err), Addr{})
		return
	}
	local := c.LocalAddr().(*net.TCPAddr).AddrPort()
	if err := writeReply(c, RepSucceeded, Addr{IP: local.Addr().Unmap(), Port: local.Port()}); err != nil {
		_ = st.Close()
		return
	}
	_ = c.SetDeadline(time.Time{})
	core.Pipe(c, st)
}
