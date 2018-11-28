package dtls

import (
	"net"

	ma "github.com/multiformats/go-multiaddr"
	manet "github.com/multiformats/go-multiaddr-net"
)

func wrapNetListener(listener net.Listener, wrapMA ma.Multiaddr) manet.Listener {
	return &maListener{
		Listener: listener,
		wrapMA:   wrapMA,
	}
}

// maListener implements Listener
type maListener struct {
	net.Listener
	wrapMA ma.Multiaddr
}

// Accept waits for and returns the next connection to the listener.
// Returns a Multiaddr friendly Conn
func (l *maListener) Accept() (manet.Conn, error) {
	nconn, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	return wrapNetConn(nconn, l.wrapMA), nil
}

// Multiaddr returns the listener's (local) Multiaddr.
func (l *maListener) Multiaddr() ma.Multiaddr {
	ma, err := manet.FromNetAddr(l.Addr())
	if err != nil {
		return nil
	}
	return ma.Encapsulate(l.wrapMA)
}

func wrapNetConn(conn net.Conn, wrapMA ma.Multiaddr) manet.Conn {
	return &maConn{
		Conn:   conn,
		wrapMA: wrapMA,
	}
}

type maConn struct {
	net.Conn
	wrapMA ma.Multiaddr
}

// LocalMultiaddr returns the local address associated with
// this connection
func (c *maConn) LocalMultiaddr() ma.Multiaddr {
	ma, err := manet.FromNetAddr(c.LocalAddr())
	if err != nil {
		return nil
	}
	return ma.Encapsulate(c.wrapMA)
}

// RemoteMultiaddr returns the remote address associated with
// this connection
func (c *maConn) RemoteMultiaddr() ma.Multiaddr {
	ma, err := manet.FromNetAddr(c.RemoteAddr())
	if err != nil {
		return nil
	}
	return ma.Encapsulate(c.wrapMA)
}
