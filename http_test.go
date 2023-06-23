package guardedbeaconproxy

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"gotest.tools/assert"
)

var pbpPath string = "/eth/v1/validator/prepare_beacon_proposer"
var rvPath string = "/eth/v1/validator/register_validator"
var okBody string = "TEST OK"

func handlerOK() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, okBody)
	}
}

func handlerNeverCalled(t *testing.T) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		t.Fail()
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
		return
	}))

	return ts
}

func newGbp(t *testing.T, upstream *httptest.Server) (out *GuardedBeaconProxy, start func(t *testing.T), stop func()) {
	out = &GuardedBeaconProxy{}

	// Need an additional testServer for GBP
	ts := httptest.NewUnstartedServer(handlerNeverCalled(t))
	// Hijack its listener
	out.Addr = ts.Listener.Addr().String()
	start = func(t *testing.T) {
		err := out.Serve(ts.Listener, nil)
		if err != nil && err != http.ErrServerClosed {
			t.Error(err)
		}
	}

	stop = func() {
		ctx, _ := context.WithTimeout(context.Background(), time.Second*3)
		out.Stop(ctx)
		ts.Close()
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
		return Allowed, context.WithValue(ctx, "testkey", "testvalue"), nil
	}
	gbp.PrepareBeaconProposerGuard = func(r PrepareBeaconProposerRequest, ctx context.Context) (AuthenticationStatus, error) {
		if ctx.Value("testkey") != "testvalue" {
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
		if ctx.Value("testkey") != "testvalue" {
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

	assertResp(t, res, ``, http.StatusBadRequest)
}
