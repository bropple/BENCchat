package main

import (
	"sort"
	"strings"

	"github.com/benco-holdings/benchat/internal/oscar"
	"github.com/benco-holdings/benchat/internal/state"
	"github.com/wailsapp/wails/v2/pkg/runtime"
)

// Consensual buddy connections, app layer.
//
// Adding an AIM buddy needs the other person's authorization before presence
// and messaging flow. Two things arrive unbidden: someone asking to connect to
// us, and the answer to a request we made. This mirrors the room-invite flow
// (app_room_e2ee.go): inbound requests queue for a decision rather than
// interrupting, and events tell the UI to refresh.

// handleConnectionRequest queues an inbound "X wants to connect" and notifies
// the UI. It does not auto-approve: accepting connects the two accounts (and,
// per the mutual-add rule, adds them back), which is the user's call.
func (a *App) handleConnectionRequest(req oscar.ConnectionRequest) {
	key := state.NormalizeScreenName(req.ScreenName)

	a.connReqMu.Lock()
	if a.connReqs == nil {
		a.connReqs = map[string]oscar.ConnectionRequest{}
	}
	a.connReqs[key] = req
	a.connReqMu.Unlock()

	if a.ctx != nil {
		runtime.EventsEmit(a.ctx, "connection:request", map[string]string{
			"screenName": req.ScreenName,
			"reason":     req.Reason,
		})
	}
}

// handleConnectionResponse surfaces the answer to a request we made. The buddy
// list has already been reconciled in the client (pending marker cleared on
// accept); this just tells the user and nudges the UI to refresh.
func (a *App) handleConnectionResponse(res oscar.ConnectionResponse) {
	switch {
	case res.Accepted:
		a.store.Notify(state.NoticeInfo, res.ScreenName+" accepted your connection request.")
	case res.WasPending:
		// A reply to a request we made — the user asked, so tell them the answer.
		a.store.Notify(state.NoticeInfo, res.ScreenName+" declined your connection request.")
	default:
		// They removed us from an established connection. Silent by design: an
		// unsolicited "X removed you" is a small cruelty with no upside, so the
		// buddy just quietly drops off the list (Signal/WhatsApp do the same).
	}
	if a.ctx != nil {
		runtime.EventsEmit(a.ctx, "connection:update", map[string]any{
			"screenName": res.ScreenName,
			"accepted":   res.Accepted,
			"reason":     res.Reason,
		})
	}
}

// ConnectionRequestInfo is one pending inbound request, for the roster's
// requests list.
type ConnectionRequestInfo struct {
	ScreenName string `json:"screenName"`
	Reason     string `json:"reason"`
}

// PendingConnectionRequests lists inbound requests awaiting a decision.
func (a *App) PendingConnectionRequests() []ConnectionRequestInfo {
	a.connReqMu.Lock()
	defer a.connReqMu.Unlock()
	out := make([]ConnectionRequestInfo, 0, len(a.connReqs))
	for _, req := range a.connReqs {
		out = append(out, ConnectionRequestInfo{ScreenName: req.ScreenName, Reason: req.Reason})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ScreenName < out[j].ScreenName })
	return out
}

// ApproveConnectionRequest approves an inbound request by screen name. Per the
// mutual-add rule this also adds the requester back as a buddy. Returns an error
// string (empty on success) for inline display.
func (a *App) ApproveConnectionRequest(screenName string) string {
	screenName = strings.TrimSpace(screenName)
	if screenName == "" {
		return "Enter a screen name."
	}
	if err := a.client.ApproveConnection(screenName); err != nil {
		return err.Error()
	}
	a.forgetConnectionRequest(screenName)
	return ""
}

// DeclineConnectionRequest declines an inbound request by screen name.
func (a *App) DeclineConnectionRequest(screenName string) string {
	screenName = strings.TrimSpace(screenName)
	if screenName == "" {
		return "Enter a screen name."
	}
	if err := a.client.DeclineConnection(screenName); err != nil {
		return err.Error()
	}
	a.forgetConnectionRequest(screenName)
	return ""
}

// forgetConnectionRequest drops a handled request and refreshes the UI list.
func (a *App) forgetConnectionRequest(screenName string) {
	a.connReqMu.Lock()
	delete(a.connReqs, state.NormalizeScreenName(screenName))
	a.connReqMu.Unlock()
	if a.ctx != nil {
		runtime.EventsEmit(a.ctx, "connection:update", map[string]any{
			"screenName": screenName,
			"handled":    true,
		})
	}
}
