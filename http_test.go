package guardedbeaconproxy

import (
	"bytes"
	"context"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/Rocket-Rescue-Node/guarded-beacon-proxy/ssz"

	"github.com/ethereum/go-ethereum/common"
	"golang.org/x/net/nettest"
	"gotest.tools/assert"
)

var pbpPath string = "/eth/v1/validator/prepare_beacon_proposer"
var rvPath string = "/eth/v1/validator/register_validator"
var okBody string = "TEST OK"

func handlerOK() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, okBody)
	}
}

func testServer(prepare_beacon_proposer, register_validator, generic http.HandlerFunc) *httptest.Server {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Determine the path
		path := r.URL.Path
		if strings.HasPrefix(path, pbpPath) {
			prepare_beacon_proposer(w, r)
			return
		}

		if strings.HasPrefix(path, rvPath) {
			register_validator(w, r)
			return
		}

		generic(w, r)
	}))

	return ts
}

func newGbp(t *testing.T, upstream *httptest.Server) (out *GuardedBeaconProxy, start func(t *testing.T), stop func()) {
	out = &GuardedBeaconProxy{}

	// Create a listener for GBP
	listener, err := nettest.NewLocalListener("tcp")
	if err != nil {
		t.Error(err)
	}
	out.Addr = listener.Addr().String()
	start = func(t *testing.T) {
		err := out.Serve(listener, nil)
		if err != nil && err != http.ErrServerClosed {
			t.Error(err)
		}
	}

	stop = func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second*3)
		defer cancel()
		out.Stop(ctx)
	}

	// Assign the upstream
	u, err := url.Parse(upstream.URL)
	if err != nil {
		t.Error(err)
	}

	out.BeaconURL = u
	return
}

func assertResp(t *testing.T, r *http.Response, body string, statusCode int) {

	b, err := io.ReadAll(r.Body)
	if err != nil {
		t.Error(err)
	}
	s := strings.TrimSpace(string(b))
	t.Logf("http response body: %s", s)
	if !strings.EqualFold(s, body) {
		t.Errorf("Unexpected response body (%s) expected: %s", s, body)
	}

	if r.StatusCode != statusCode {
		t.Errorf("Unexpected response code (%s) expected: %s", fmt.Sprint(r.StatusCode), fmt.Sprint(statusCode))
	}

}

func assertRespOK(t *testing.T, r *http.Response) {
	assertResp(t, r, okBody, http.StatusOK)
}

func prepareBeaconProposerPayload(fee_recipient string) io.Reader {
	out := fmt.Sprintf(`
	[
		{
			"validator_index": "1",
			"fee_recipient": "%s"
		}
	]`, fee_recipient)
	return strings.NewReader(out)
}

func registerValidatorPayload(pubkey, fee_recipient string) io.Reader {
	out := fmt.Sprintf(`
	[
		{
			"message": {
				"fee_recipient": "%s",
				"gas_limit": "1",
				"timestamp": "1",
				"pubkey": "%s"
			},
			"signature": "0x1b66ac1fb663c9bc59509846d6ec05345bd908eda73e670af888da41af171505cc411d61252fb6cb3fa0017b679f8bb2305b26a285fa2737f175668d0dff91cc1b66ac1fb663c9bc59509846d6ec05345bd908eda73e670af888da41af171505"
		}
	]`, fee_recipient, pubkey)
	return strings.NewReader(out)
}

func TestUnguardedUnauthed(t *testing.T) {
	ts := testServer(handlerOK(), handlerOK(), handlerOK())
	defer ts.Close()
	t.Logf("upstream listening on %s\n", ts.Listener.Addr())

	// Set up a gbp with no auth and no guards
	gbp, start, stop := newGbp(t, ts)
	go start(t)
	defer stop()
	t.Logf("proxy listening on %s\n", gbp.Addr)

	// Check any old route
	res, err := http.Get("http://" + gbp.Addr + "/status")
	if err != nil {
		t.Error(err)
	}

	assertRespOK(t, res)

	// Check a guarded route
	res, err = http.Get("http://" + gbp.Addr + pbpPath)
	if err != nil {
		t.Error(err)
	}

	assertRespOK(t, res)
}

func TestUnguardedAuthed(t *testing.T) {
	username := "alice"
	password := "slithytoves"
	ts := testServer(handlerOK(), handlerOK(), handlerOK())
	defer ts.Close()
	t.Logf("upstream listening on %s\n", ts.Listener.Addr())

	// Set up a gbp with auth and no guards
	gbp, start, stop := newGbp(t, ts)
	gbp.HTTPAuthenticator = func(r *http.Request) (AuthenticationStatus, context.Context, error) {
		u, p, ok := r.BasicAuth()
		if !ok {
			return BadRequest, nil, fmt.Errorf("missing username")
		}

		if p == "" {
			return Unauthorized, nil, fmt.Errorf("missing password")
		}

		if u != username || p != password {
			return Forbidden, nil, fmt.Errorf("incorrect username/password")
		}

		return Allowed, nil, nil
	}
	go start(t)
	defer stop()
	t.Logf("proxy listening on %s\n", gbp.Addr)

	// No username
	res, err := http.Get("http://" + gbp.Addr + "/status")
	if err != nil {
		t.Error(err)
	}

	assertResp(t, res, `{"error":"missing username"}`, http.StatusBadRequest)

	// No password
	res, err = http.Get("http://cheshire@" + gbp.Addr + "/status")
	if err != nil {
		t.Error(err)
	}

	assertResp(t, res, `{"error":"missing password"}`, http.StatusUnauthorized)

	// Wrong password
	res, err = http.Get("http://cheshire:cat@" + gbp.Addr + "/status")
	if err != nil {
		t.Error(err)
	}

	assertResp(t, res, `{"error":"incorrect username/password"}`, http.StatusForbidden)

	// OK
	res, err = http.Get("http://alice:slithytoves@" + gbp.Addr + "/status")
	if err != nil {
		t.Error(err)
	}

	assertRespOK(t, res)
}

func TestGuardedUnauthedWithContext(t *testing.T) {
	goodRecipient := "0xabcf8e0d4e9587369b2301d0790347320302cc09"
	badRecipient := "0x0000000000000000000000000000000000000000"
	ts := testServer(handlerOK(), handlerOK(), handlerOK())
	defer ts.Close()
	t.Logf("upstream listening on %s\n", ts.Listener.Addr())

	// Set up a gbp with passthrough auth and guards
	gbp, start, stop := newGbp(t, ts)
	gbp.HTTPAuthenticator = func(r *http.Request) (AuthenticationStatus, context.Context, error) {
		ctx := r.Context()
		return Allowed, context.WithValue(ctx, testkey, "testvalue"), nil
	}
	gbp.PrepareBeaconProposerGuard = func(r PrepareBeaconProposerRequest, ctx context.Context) (AuthenticationStatus, error) {
		if ctx.Value(testkey) != "testvalue" {
			t.Error("context passthrough failed")
		}

		assert.Equal(t, len(r), 1)
		m := r[0]

		if m.FeeRecipient != goodRecipient {
			return Conflict, fmt.Errorf("incorrect fee recipient")
		}

		return Allowed, nil
	}
	gbp.RegisterValidatorGuard = func(r RegisterValidatorRequest, ctx context.Context) (AuthenticationStatus, error) {
		if ctx.Value(testkey) != "testvalue" {
			t.Error("context passthrough failed")
		}

		assert.Equal(t, len(r), 1)
		m := r[0]

		if m.Message.FeeRecipient != goodRecipient {
			return Conflict, fmt.Errorf("incorrect fee recipient")
		}

		return Allowed, nil

	}
	go start(t)
	defer stop()
	t.Logf("proxy listening on %s\n", gbp.Addr)

	// Check any old route
	res, err := http.Get("http://" + gbp.Addr + "/status")
	if err != nil {
		t.Error(err)
	}

	assertRespOK(t, res)

	// Check prepare_beacon_proposer
	t.Log("Testing PBP")
	res, err = http.Post("http://"+gbp.Addr+pbpPath, "application/json", prepareBeaconProposerPayload(goodRecipient))
	if err != nil {
		t.Error(err)
	}

	assertRespOK(t, res)

	res, err = http.Post("http://"+gbp.Addr+pbpPath, "application/json", prepareBeaconProposerPayload(badRecipient))
	if err != nil {
		t.Error(err)
	}

	assertResp(t, res, `{"error":"incorrect fee recipient"}`, http.StatusConflict)

	res, err = http.Post("http://"+gbp.Addr+pbpPath, "application/json", strings.NewReader("[}"))
	if err != nil {
		t.Error(err)
	}

	assertResp(t, res, ``, http.StatusBadRequest)

	// Check register_validator
	t.Log("Testing RV")
	pubkey := "0x93247f2209abcacf57b75a51dafae777f9dd38bc7053d1af526f220a7489a6d3a2753e5f3e8b1cfe39b56f43611df74a"
	res, err = http.Post("http://"+gbp.Addr+rvPath, "application/json", registerValidatorPayload(pubkey, goodRecipient))
	if err != nil {
		t.Error(err)
	}

	assertRespOK(t, res)

	res, err = http.Post("http://"+gbp.Addr+rvPath, "application/json", registerValidatorPayload(pubkey, badRecipient))
	if err != nil {
		t.Error(err)
	}

	assertResp(t, res, `{"error":"incorrect fee recipient"}`, http.StatusConflict)

	res, err = http.Post("http://"+gbp.Addr+rvPath, "application/json", strings.NewReader("[}"))
	if err != nil {
		t.Error(err)
	}

	assertResp(t, res, `{"error":"invalid character '}' looking for beginning of value"}`, http.StatusBadRequest)
}

func TestSSZ(t *testing.T) {
	addr := common.HexToAddress("0xa111111111111111111111111111111111111111")
	pubkey := "0xa55555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555"
	pubkeyBytes, err := hex.DecodeString(pubkey[2:])
	if err != nil {
		t.Error(err)
	}

	signature := "0xa99999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999"
	signatureBytes, err := hex.DecodeString(signature[2:])
	if err != nil {
		t.Error(err)
	}

	ts := testServer(handlerOK(), handlerOK(), handlerOK())
	defer ts.Close()
	t.Logf("upstream listening on %s\n", ts.Listener.Addr())

	// Set up a gbp with passthrough auth and guards
	gbp, start, stop := newGbp(t, ts)
	gbp.HTTPAuthenticator = func(r *http.Request) (AuthenticationStatus, context.Context, error) {
		ctx := r.Context()
		return Allowed, context.WithValue(ctx, testkey, "testvalue"), nil
	}
	gbp.RegisterValidatorGuard = func(r RegisterValidatorRequest, ctx context.Context) (AuthenticationStatus, error) {
		if ctx.Value(testkey) != "testvalue" {
			t.Error("context passthrough failed")
		}

		assert.Equal(t, len(r), 2)

		for _, m := range r {
			if m.Message.FeeRecipient != addr.Hex() {
				return Conflict, fmt.Errorf("incorrect fee recipient")
			}

			if m.Signature != signature {
				return Conflict, fmt.Errorf("incorrect signature")
			}
		}

		return Allowed, nil

	}
	go start(t)
	defer stop()
	t.Logf("proxy listening on %s\n", gbp.Addr)

	// Create a valid SSZ payload

	payload := ssz.RegisterValidatorRequest{
		ssz.SignedValidatorRegistration{
			Message: ssz.ValidatorRegistration{
				FeeRecipient: addr.Bytes(),
				GasLimit:     100,
				Timestamp:    1932,
				Pubkey:       pubkeyBytes,
			},
			Signature: signatureBytes,
		},
		ssz.SignedValidatorRegistration{
			Message: ssz.ValidatorRegistration{
				FeeRecipient: addr.Bytes(),
				GasLimit:     100,
				Timestamp:    1932,
				Pubkey:       pubkeyBytes,
			},
			Signature: signatureBytes,
		},
	}

	var buf []byte
	// serialize the elements
	for _, element := range payload {
		sszBytes, err := element.MarshalSSZ()
		if err != nil {
			t.Error(err)
		}
		buf = append(buf, sszBytes...)
	}

	res, err := http.Post("http://"+gbp.Addr+rvPath, "application/octet-stream", bytes.NewReader(buf))
	if err != nil {
		t.Error(err)
	}
	fmt.Println(res.StatusCode)
}

func TestInvalidContentType(t *testing.T) {
	ts := testServer(handlerOK(), handlerOK(), handlerOK())
	defer ts.Close()
	t.Logf("upstream listening on %s\n", ts.Listener.Addr())

	gbp, start, stop := newGbp(t, ts)
	gbp.RegisterValidatorGuard = func(r RegisterValidatorRequest, ctx context.Context) (AuthenticationStatus, error) {

		return Allowed, nil
	}
	go start(t)
	defer stop()

	res, err := http.Post("http://"+gbp.Addr+rvPath, "application/text", strings.NewReader("test"))
	if err != nil {
		t.Error(err)
	}

	assertResp(t, res, `{"error":"unsupported content type: application/text"}`, http.StatusUnsupportedMediaType)

}

func TestValidContentType(t *testing.T) {
	ts := testServer(handlerOK(), handlerOK(), handlerOK())
	defer ts.Close()
	t.Logf("upstream listening on %s\n", ts.Listener.Addr())

	gbp, start, stop := newGbp(t, ts)
	gbp.RegisterValidatorGuard = func(r RegisterValidatorRequest, ctx context.Context) (AuthenticationStatus, error) {

		return Allowed, nil
	}
	go start(t)
	defer stop()

	res, err := http.Post("http://"+gbp.Addr+rvPath, "application/json; charset=utf-8", strings.NewReader("[]"))
	if err != nil {
		t.Error(err)
	}

	assertRespOK(t, res)
}

func TestInvalidSSZ(t *testing.T) {
	ts := testServer(handlerOK(), handlerOK(), handlerOK())
	defer ts.Close()
	t.Logf("upstream listening on %s\n", ts.Listener.Addr())

	gbp, start, stop := newGbp(t, ts)
	gbp.RegisterValidatorGuard = func(r RegisterValidatorRequest, ctx context.Context) (AuthenticationStatus, error) {

		return Allowed, nil
	}
	go start(t)
	defer stop()

	res, err := http.Post("http://"+gbp.Addr+rvPath, "application/octet-stream", strings.NewReader("{}"))
	if err != nil {
		t.Error(err)
	}

	sszSize := (&ssz.SignedValidatorRegistration{}).SizeSSZ()

	assertResp(t, res, fmt.Sprintf(`{"error":"buffer is not a multiple of SignedValidatorRegistration length: %d"}`, sszSize), http.StatusBadRequest)
}

func TestInvalidMIMEContentType(t *testing.T) {
	ts := testServer(handlerOK(), handlerOK(), handlerOK())
	defer ts.Close()
	t.Logf("upstream listening on %s\n", ts.Listener.Addr())

	gbp, start, stop := newGbp(t, ts)
	gbp.RegisterValidatorGuard = func(r RegisterValidatorRequest, ctx context.Context) (AuthenticationStatus, error) {
		return Allowed, nil
	}
	go start(t)
	defer stop()

	res, err := http.Post("http://"+gbp.Addr+rvPath, "application/json; charset", strings.NewReader("[]"))
	if err != nil {
		t.Error(err)
	}

	assertResp(t, res, `{"error":"mime: invalid media parameter"}`, http.StatusUnsupportedMediaType)
}
