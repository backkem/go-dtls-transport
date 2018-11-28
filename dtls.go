package dtls

import (
	"context"
	"crypto"
	"crypto/x509"
	"fmt"
	"net"

	logging "github.com/ipfs/go-log"
	peer "github.com/libp2p/go-libp2p-peer"
	tpt "github.com/libp2p/go-libp2p-transport"
	tptu "github.com/libp2p/go-libp2p-transport-upgrader"
	ma "github.com/multiformats/go-multiaddr"
	manet "github.com/multiformats/go-multiaddr-net"
	"github.com/pions/dtls/pkg/dtls"
	mafmt "github.com/whyrusleeping/mafmt"
)

var log = logging.Logger("dtls-tpt")

var dtlsma, _ = ma.NewMultiaddr("/dtls")

// DTLSTransport is the DTLS transport.
type DTLSTransport struct {
	// Connection upgrader for upgrading insecure stream connections to
	// secure multiplex connections.
	Upgrader *tptu.Upgrader

	// Certificate
	Certificate *x509.Certificate

	// PrivateKey
	PrivateKey crypto.PrivateKey
}

var _ tpt.Transport = &DTLSTransport{}

// NewDTLSTransport creates a DTLS transport object that tracks dialers and listeners
// created.
func NewDTLSTransport(upgrader *tptu.Upgrader, certificate *x509.Certificate, privateKey crypto.PrivateKey) *DTLSTransport {
	return &DTLSTransport{Upgrader: upgrader,
		Certificate: certificate,
		PrivateKey:  privateKey,
	}
}

// CanDial returns true if this transport believes it can dial the given
// multiaddr.
func (t *DTLSTransport) CanDial(addr ma.Multiaddr) bool {
	return mafmt.DTLS.Matches(addr)
}

// Dial dials the peer at the remote address.
func (t *DTLSTransport) Dial(ctx context.Context, raddr ma.Multiaddr, p peer.ID) (tpt.Conn, error) {
	if !t.CanDial(raddr) {
		return nil, fmt.Errorf("can't dial address %s", raddr)
	}
	udpMa := raddr.Decapsulate(dtlsma)
	network, udpAddrStr, err := manet.DialArgs(udpMa)
	if err != nil {
		return nil, fmt.Errorf("failed to get dial args: %v", err)
	}

	config := &dtls.Config{t.Certificate, t.PrivateKey}

	udpAddr, err := net.ResolveUDPAddr(network, udpAddrStr)
	if err != nil {
		return nil, err
	}
	conn, err := dtls.Dial(network, udpAddr, config)
	if err != nil {
		return nil, fmt.Errorf("failed to dial: %v", err)
	}

	wrappedConn := wrapNetConn(conn, dtlsma)

	return t.Upgrader.UpgradeOutbound(ctx, t, wrappedConn, p)
}

// Listen listens on the given multiaddr.
func (t *DTLSTransport) Listen(laddr ma.Multiaddr) (tpt.Listener, error) {
	if !t.CanDial(laddr) {
		return nil, fmt.Errorf("can't listen on address %s", laddr)
	}
	udpMa := laddr.Decapsulate(dtlsma)
	network, udpAddrStr, err := manet.DialArgs(udpMa)
	if err != nil {
		return nil, fmt.Errorf("failed to get dial args: %v", err)
	}

	config := &dtls.Config{t.Certificate, t.PrivateKey}

	udpAddr, err := net.ResolveUDPAddr(network, udpAddrStr)
	if err != nil {
		return nil, err
	}
	listener, err := dtls.Listen(network, udpAddr, config)
	if err != nil {
		return nil, fmt.Errorf("failed to listen: %v", err)
	}

	wrappedListener := wrapNetListener(listener, dtlsma)

	return t.Upgrader.UpgradeListener(t, wrappedListener), nil
}

// Protocols returns the list of terminal protocols this transport can dial.
func (t *DTLSTransport) Protocols() []int {
	return []int{ma.P_DTLS}
}

// Proxy always returns false for the DTLS transport.
func (t *DTLSTransport) Proxy() bool {
	return false
}

func (t *DTLSTransport) String() string {
	return "DTLS"
}
