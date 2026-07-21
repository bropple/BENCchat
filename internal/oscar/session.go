package oscar

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/benco-holdings/benchat/internal/wire"
)

// keepAliveInterval is how often we send an empty FLAP keepalive on the BOS
// connection.
//
// open-oscar-server sets no read deadline on BOS and will not drop a silent
// client, so this exists purely to keep NAT bindings and middleboxes from
// collecting an idle TCP connection.
const keepAliveInterval = 60 * time.Second

// handshakeSNACBudget caps how many unrelated SNACs we will skip while waiting
// for an expected one during the handshake. The server legitimately interleaves
// unsolicited traffic here (MOTD, rate-param changes), but an unbounded wait
// would turn a protocol mistake into a silent hang — the exact failure mode
// that makes OSCAR miserable to debug.
const handshakeSNACBudget = 64

// Session is a live, signed-on BOS connection.
//
// It owns a single read loop that dispatches inbound SNACs to Handler. All
// protocol state lives here; nothing in this package knows about the UI.
type Session struct {
	conn       *Conn
	screenName string

	// foodGroups is what the server said this connection serves (from HostOnline).
	foodGroups []uint16

	// buddyList is the feedbag loaded during sign-on.
	buddyList BuddyList

	// feedbag is the editable mirror of the server-stored list.
	feedbag *Feedbag

	// Handler receives every SNAC that arrives after sign-on completes. It is
	// called from the read loop goroutine, so it must not block for long.
	Handler func(frame wire.SNACFrame, body []byte)

	// rateLimiter paces outbound SNACs to the server's advertised limits. Nil
	// until the rate-params reply is decoded during the handshake (and stays nil
	// if that decode fails), in which case Send does no pacing.
	rateLimiter *rateLimiter

	// transport records how this connection was opened, so any further
	// connection this session spawns (chat, chat-nav) gets the same protection.
	transport Transport
	// authPort is the port the user configured; server-advertised redirects are
	// forced onto it when TLS is in use.
	authPort string

	reqID  uint32
	closed chan struct{}

	// authByReq correlates a buddy-add's request ID to the screen name it added,
	// so the server's asynchronous FeedbagStatus (which echoes the request ID)
	// can be tied back to the buddy when authorization turns out to be required.
	// Guarded by authMu.
	authMu    sync.Mutex
	authByReq map[uint32]string
}

// Transport returns how this session connected, for spawning further
// connections with the same protection.
func (s *Session) Transport() Transport { return s.transport.withPort(s.authPort) }

// Secure reports whether this session's connection is encrypted.
func (s *Session) Secure() bool { return s.transport.TLS }

// ScreenName returns the canonical screen name this session signed on as.
func (s *Session) ScreenName() string { return s.screenName }

// FoodGroups returns the foodgroups the server advertised for this connection.
func (s *Session) FoodGroups() []uint16 { return s.foodGroups }

// nextReqID allocates a client request ID. The high bit is reserved for
// server-initiated SNACs, so client IDs must stay below it.
func (s *Session) nextReqID() uint32 {
	s.reqID++
	return s.reqID &^ wire.ReqIDFromServer
}

// SignOn opens the BOS connection using the cookie from Login and runs the full
// OSERVICE handshake, returning once the server considers the client online.
//
// The cookie expires 60 seconds after Login returns, so this must follow it
// promptly.
func SignOn(ctx context.Context, res *LoginResult) (*Session, error) {
	if res.Expired() {
		// Worth catching explicitly: a stale cookie is rejected by a bare
		// connection close with no diagnostic frame, which looks like a network
		// fault rather than a client bug.
		return nil, errors.New("oscar: auth cookie expired before BOS reconnect (60s limit)")
	}

	bosAddr := res.Transport.redirect(res.BOSAddress, res.authPort)
	conn, err := res.Transport.dial(ctx, bosAddr, 0)
	if err != nil {
		return nil, fmt.Errorf("oscar: dial BOS: %w", err)
	}

	s := &Session{
		conn:       conn,
		transport:  res.Transport,
		authPort:   res.authPort,
		screenName: res.ScreenName,
		closed:     make(chan struct{}),
	}

	if err := s.handshake(res.Cookie); err != nil {
		conn.Close()
		return nil, err
	}

	// Load the buddy list BEFORE going online. The FeedbagUse inside
	// LoadBuddyList is what marks our contacts initialized; doing it after
	// ClientOnline means the server has nobody to broadcast our arrival to at the
	// moment it wants to. The order is enforced here rather than left to callers
	// because getting it wrong fails silently — you sign on fine and simply never
	// see anyone.
	list, err := s.LoadBuddyList()
	if err != nil {
		conn.Close()
		return nil, err
	}
	s.buddyList = list

	// A brand-new account has no server-stored list. Create the root and a
	// default group now so the list is well-formed from the first sign-on rather
	// than only after the first add.
	if ops := s.feedbag.EnsureBaseStructure(DefaultGroupName); len(ops) > 0 {
		if err := s.sendEdits(ops); err != nil {
			conn.Close()
			return nil, err
		}
		s.buddyList = s.feedbag.BuddyList()
	}

	// Advertise what we support before going online, so the capabilities are
	// already set when the server broadcasts our arrival to buddies — otherwise
	// they'd see us sign on as a client with no declared capabilities and only
	// learn better on a later lookup. Best-effort: a client that can't announce
	// itself is still a working client.
	if err := s.SetCapabilities([]Capability{CapSecureIM, CapBENCchat}); err != nil {
		_ = err
	}

	if err := s.goOnline(); err != nil {
		conn.Close()
		return nil, err
	}

	// Pull any messages that arrived while we were offline. Best-effort: a failure
	// here shouldn't abort an otherwise-good sign-on.
	if err := s.RetrieveOfflineMessages(); err != nil {
		// Non-fatal; the session is up regardless.
		_ = err
	}
	return s, nil
}

// BuddyList returns the list loaded during sign-on.
func (s *Session) BuddyList() BuddyList { return s.buddyList }

// goOnline sends ClientOnline, the gate that marks sign-on complete. Until it
// arrives the server keeps us invisible and several foodgroups stay closed.
func (s *Session) goOnline() error {
	if err := s.Send(wire.OService, wire.OServiceClientOnline,
		wire.SNAC_0x01_0x02_OServiceClientOnline{}); err != nil {
		return fmt.Errorf("oscar: send client-online: %w", err)
	}
	return nil
}

// handshake performs the OSERVICE part of BOS sign-on:
//
//	server → HostOnline
//	client → ClientVersions      server → HostVersions (+ unsolicited MOTD)
//	client → RateParamsQuery     server → RateParamsReply
//
// The feedbag load and ClientOnline follow, in that order — see SignOn.
func (s *Session) handshake(cookie []byte) error {
	if _, err := s.conn.ReadSignonFrame(); err != nil {
		return fmt.Errorf("oscar: BOS hello: %w", err)
	}

	// Present the cookie verbatim — it is HMAC-signed and padded to exactly 256
	// bytes, so any trimming or re-padding invalidates it.
	if err := s.conn.WriteSignonFrame([]wire.TLV{
		wire.NewTLVBE(wire.LoginTLVTagsAuthorizationCookie, cookie),
	}); err != nil {
		return fmt.Errorf("oscar: send BOS signon: %w", err)
	}

	// 1. HostOnline (server-initiated) tells us which foodgroups are available.
	_, body, err := s.waitFor(wire.OService, wire.OServiceHostOnline)
	if err != nil {
		return fmt.Errorf("oscar: awaiting host-online: %w", err)
	}
	var hostOnline wire.SNAC_0x01_0x03_OServiceHostOnline
	if err := wire.UnmarshalBE(&hostOnline, bytes.NewReader(body)); err != nil {
		return fmt.Errorf("oscar: decode host-online: %w", err)
	}
	s.foodGroups = hostOnline.FoodGroups

	// 2. Declare our foodgroup versions and wait for the echo.
	if err := s.Send(wire.OService, wire.OServiceClientVersions,
		wire.SNAC_0x01_0x17_OServiceClientVersions{Versions: wire.ClientFoodGroupVersions}); err != nil {
		return fmt.Errorf("oscar: send client versions: %w", err)
	}
	if _, _, err := s.waitFor(wire.OService, wire.OServiceHostVersions); err != nil {
		return fmt.Errorf("oscar: awaiting host versions: %w", err)
	}

	// 3. Rate limits. We decode the reply and build a client-side limiter that
	// paces outbound SNACs to the server's advertised thresholds, so a burst is
	// slowed rather than silently dropped. Decoding is only unambiguous because
	// we declared OSERVICE version 1 (no V2Params tail) — see RateParamsSNAC.
	// A decode failure is non-fatal: we sign on without pacing, which is the
	// prior behavior, rather than failing an otherwise-good session.
	if err := s.Send(wire.OService, wire.OServiceRateParamsQuery,
		wire.SNAC_0x01_0x06_OServiceRateParamsQuery{}); err != nil {
		return fmt.Errorf("oscar: send rate params query: %w", err)
	}
	_, rateBody, err := s.waitFor(wire.OService, wire.OServiceRateParamsReply)
	if err != nil {
		return fmt.Errorf("oscar: awaiting rate params: %w", err)
	}
	var rateReply wire.SNAC_0x01_0x07_OServiceRateParamsReply
	if err := wire.UnmarshalBE(&rateReply, bytes.NewReader(rateBody)); err == nil {
		s.rateLimiter = newRateLimiter(rateReply, time.Now)
	}
	return nil
}

// waitFor reads SNACs until one matches fg/sg, skipping unrelated traffic. The
// server interleaves unsolicited SNACs (MOTD, rate-param changes) into the
// handshake by design, so skipping is expected rather than exceptional.
func (s *Session) waitFor(fg, sg uint16) (wire.SNACFrame, []byte, error) {
	for i := 0; i < handshakeSNACBudget; i++ {
		frame, body, err := s.conn.ReadSNAC()
		if err != nil {
			return frame, nil, err
		}
		if frame.FoodGroup == fg && frame.SubGroup == sg {
			return frame, body, nil
		}
		// An error SNAC in the foodgroup we're waiting on is terminal: the reply
		// we want is never coming.
		if frame.FoodGroup == fg && frame.SubGroup == 0x0001 {
			return frame, nil, fmt.Errorf("oscar: server returned an error for foodgroup 0x%04x", fg)
		}
	}
	return wire.SNACFrame{}, nil, fmt.Errorf(
		"oscar: gave up waiting for SNAC(0x%04x,0x%04x) after %d unrelated SNACs", fg, sg, handshakeSNACBudget)
}

// Send writes a client-initiated SNAC with a fresh request ID.
//
// If a rate limiter is active it may pace the send, sleeping just long enough to
// keep this SNAC class's moving average out of the server's drop zone. The sleep
// is abandoned if the session closes, so a sign-off never hangs behind pacing.
func (s *Session) Send(fg, sg uint16, body any) error {
	_, err := s.sendPaced(fg, sg, body)
	return err
}

// sendPaced is Send, but returns the request ID it assigned. Unlike service.go's
// SendReq it applies rate pacing, so it suits edit traffic (buddy adds) that can
// arrive in bursts while still needing its reply correlated by request ID.
func (s *Session) sendPaced(fg, sg uint16, body any) (uint32, error) {
	if s.rateLimiter != nil {
		d, ok := s.rateLimiter.reserve(fg, sg)
		if !ok {
			// Over budget by more than we're willing to wait. Fail loudly instead of
			// transmitting: the server discards over-limit SNACs silently, so sending
			// would lose the message with no error and no acknowledgement.
			return 0, errors.New("oscar: sending too fast — wait a moment and try again")
		}
		if d > 0 {
			t := time.NewTimer(d)
			select {
			case <-t.C:
			case <-s.closed:
				t.Stop()
				return 0, errors.New("oscar: session closed while pacing a send")
			}
		}
	}
	reqID := s.nextReqID()
	if err := s.conn.WriteSNAC(wire.SNACFrame{
		FoodGroup: fg,
		SubGroup:  sg,
		RequestID: reqID,
	}, body); err != nil {
		return 0, err
	}
	return reqID, nil
}

// recordAuthReq remembers that request reqID added screenName, so a later
// FeedbagStatus can be matched to the buddy that may need authorization.
func (s *Session) recordAuthReq(reqID uint32, screenName string) {
	s.authMu.Lock()
	defer s.authMu.Unlock()
	if s.authByReq == nil {
		s.authByReq = make(map[uint32]string)
	}
	s.authByReq[reqID] = screenName
}

// TakeAuthTarget returns and forgets the buddy screen name a buddy-add request
// carried, matched by the request ID the server echoed on its FeedbagStatus.
// The second result is false when this reply was not a tracked buddy add.
func (s *Session) TakeAuthTarget(reqID uint32) (string, bool) {
	s.authMu.Lock()
	defer s.authMu.Unlock()
	name, ok := s.authByReq[reqID]
	if ok {
		delete(s.authByReq, reqID)
	}
	return name, ok
}

// Run drives the session read loop until the connection closes or ctx is
// cancelled, dispatching each inbound SNAC to Handler. It returns the error that
// ended the session: io.EOF or a *SignoffError for a normal peer close,
// context.Canceled / DeadlineExceeded when ctx ended it, anything else for a
// fault.
//
// Run also sends periodic keepalives. It blocks, so callers typically run it in
// its own goroutine.
func (s *Session) Run(ctx context.Context) error {
	go s.keepAlive(ctx)

	// A blocked ReadSNAC can't observe ctx by itself, so a watcher unblocks it by
	// tripping the read deadline. Without this, cancelling ctx would leave Run
	// spinning on the socket until the peer happened to close it.
	stop := make(chan struct{})
	defer close(stop)
	go func() {
		select {
		case <-ctx.Done():
			_ = s.conn.SetReadDeadline(time.Now())
		case <-stop:
		}
	}()

	for {
		frame, body, err := s.conn.ReadSNAC()
		if err != nil {
			// A cancelled context is the reason for the read failure here, so report
			// that rather than the incidental deadline-exceeded from the socket.
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return err
		}
		if s.Handler != nil {
			s.Handler(frame, body)
		}
	}
}

// keepAlive pings the server periodically to keep NAT bindings alive, stopping
// when the session closes or ctx is cancelled.
func (s *Session) keepAlive(ctx context.Context) {
	t := time.NewTicker(keepAliveInterval)
	defer t.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-s.closed:
			return
		case <-t.C:
			if err := s.conn.SendKeepAlive(); err != nil {
				// The read loop will surface the real error; nothing useful to do here.
				return
			}
		}
	}
}

// Close signs off and tears down the connection.
func (s *Session) Close() error {
	select {
	case <-s.closed:
		return nil
	default:
		close(s.closed)
	}
	// Best-effort courtesy signoff; the socket is closing regardless.
	_ = s.conn.SendSignoff()
	return s.conn.Close()
}
