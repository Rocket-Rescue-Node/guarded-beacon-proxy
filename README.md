[![Guarded-BeaconProxy](https://github.com/Rocket-Rescue-Node/guarded-beacon-proxy/actions/workflows/test.yaml/badge.svg)](https://github.com/Rocket-Rescue-Node/guarded-beacon-proxy/actions/workflows/test.yaml) [![Go Reference](https://pkg.go.dev/badge/github.com/rocket-rescue-node/guarded-beacon-proxy.svg)](https://pkg.go.dev/github.com/rocket-rescue-node/guarded-beacon-proxy)

# Guarded-Beacon-Proxy

Guarded-Beacon-Proxy is a library to enable reverse proxies that sit between Ethereum validators and their respective Beacon Nodes.
In addition to reverse proxying traffic, it provides hooks to enforce user authentication and fee recipient validation.
These hooks can be configured to prevent access from unauthorized VCs and/or prevent VCs from setting unauthorized fee recipients for their tips/MEV.

Guarded-Beacon-Proxy is designed to be similar to http.Server in its usage pattern.
For example, a proxy can be instantiated like so:
```golang
        beaconURL, _ := url.Parse("http://eth2:5052")
        pr := &gbp.GuardedBeaconProxy{
                Addr:                       "http://0.0.0.0:8052",
                BeaconURL:                  beaconURL,
                GRPCAddr:                   "0.0.0.0:8053",
                GRPCBeaconURL:              "eth2:5053",

                HTTPAuthenticator:          func(r *http.Request) (AuthenticationStatus, context.Context, error) {
                        // Add your authentication here
                        return gbp.Authorized, nil, nil
                },
                GRPCAuthenticator:          func(md metadata.MD) (AuthenticationStatus, context.Context, error) {
                        // Add your authentication here
                        return gbp.Authorized, nil, nil
                },
                PrepareBeaconProposerGuard: func(PrepareBeaconProposerRequest r, ctx context.Context) (AuthenticationStatus, error) {
                        // Add your fee recipient validation here
                        return gbp.Authorized, nil
                },
                RegisterValidatorGuard:     func(r RegisterValidatorRequest, ctx context.Context) (AuthenticationStatus, error) {
                        // Add your fee recipient validation here
                        return gbp.Authorized, nil
                },
        }
        pr.TLS.CertFile = "/etc/ssl/certs/mycert/certfile"
        pr.TLS.KeyFile = "/etc/ssl/certs/mycert/certkey"

        // Blocks until pr.Stop() is called or a non-nil error is returned
        err := pr.ListenAndServe()
```

Validating fee recipients is important to prevent cross-client theft- that is, two node operators using the service stealing mev/tips from each other.
However, because `register_validator` requires a signature from the VC, it is not as critical as `prepare_beacon_proposer` validation.
You should establish which fee recipients are valid for which public keys out-of-band, ie, by looking at 0x01 credentials for the validator on the Beacon Chain.
If you are operating the proxy for a LST, for instance, `register_validator` and `prepare_beacon_proposer` should both be guarded to prevent theft by node operators from the protocol itself, instead of just from one another.

Authenticating requests is useful to control who can connect to your Beacon Nodes, and shouldn't be overlooked just because of the fee recipient guards- many other paths are only guarded by authentication.
For example, Rocket-Rescue-Node provides our users with HMAC credentials that encode some useful data to us, such as time limits and the address of the connecting node's Rocket Pool wallet.

See [Rescue-Proxy](https://github.com/rocket-rescue-node/rescue-proxy) as a reference implementation.
