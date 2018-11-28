Package ``go-libp2p-dtls-transport`` is a Go DTLS libp2p transport based on [pions/dtls](https://github.com/pions/dtls).

Requirements:
- [multiformats/multiaddr#76](https://github.com/multiformats/multiaddr/pull/76)
- [multiformats/go-multiaddr#86](https://github.com/multiformats/go-multiaddr/pull/86)
- [backkem/mafmt dtls](https://github.com/backkem/mafmt/tree/dtls)

The ``SubtestStreamOpenStress`` sub-test still fails. The other ones are passed.