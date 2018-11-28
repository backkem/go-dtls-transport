package dtls

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"math/big"
	"testing"
	"time"

	"github.com/libp2p/go-conn-security/insecure"
	tptu "github.com/libp2p/go-libp2p-transport-upgrader"
	utils "github.com/libp2p/go-libp2p-transport/test"
	mplex "github.com/whyrusleeping/go-smux-multiplex"
)

func TestDTLSTransport(t *testing.T) {
	ca, pa, err := generateCertificate()
	if err != nil {
		t.Fatal(err)
	}
	ta := NewDTLSTransport(
		&tptu.Upgrader{
			Secure: insecure.New("peerA"),
			Muxer:  new(mplex.Transport),
		},
		ca,
		pa)
	cb, pb, err := generateCertificate()
	if err != nil {
		t.Fatal(err)
	}
	tb := NewDTLSTransport(
		&tptu.Upgrader{
			Secure: insecure.New("peerB"),
			Muxer:  new(mplex.Transport),
		},
		cb,
		pb)

	zero := "/ip4/127.0.0.1/udp/0/dtls"
	utils.SubtestTransport(t, ta, tb, zero, "peerA")
}

func generateCertificate() (*x509.Certificate, *ecdsa.PrivateKey, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}

	origin := make([]byte, 16)
	if err != nil {
		return nil, nil, err
	}

	// Max random value, a 130-bits integer, i.e 2^130 - 1
	maxBigInt := new(big.Int)
	maxBigInt.Exp(big.NewInt(2), big.NewInt(130), nil).Sub(maxBigInt, big.NewInt(1))
	serialNumber, err := rand.Int(rand.Reader, maxBigInt)
	if err != nil {
		return nil, nil, err
	}

	template := x509.Certificate{
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageClientAuth,
			x509.ExtKeyUsageServerAuth,
		},
		BasicConstraintsValid: true,
		NotBefore:             time.Now(),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		NotAfter:              time.Now().AddDate(0, 1, 0),
		SerialNumber:          serialNumber,
		Version:               2,
		Subject:               pkix.Name{CommonName: hex.EncodeToString(origin)},
		IsCA:                  true,
	}

	raw, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return nil, nil, err
	}

	cert, err := x509.ParseCertificate(raw)
	if err != nil {
		return nil, nil, err
	}

	return cert, priv, nil
}
