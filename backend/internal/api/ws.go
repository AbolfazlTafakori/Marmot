package api

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"github.com/coder/websocket"
)

// statusTickEvery is how often a status.tick event is pushed.
const (
	statusTickEvery = 2 * time.Second
	wsWriteTimeout  = 10 * time.Second
)

// handleWS streams events as JSON messages: status ticks, node events
// (path state, failover, rotation, peer state, config applied) and
// warnings from the log. The browser's Origin must match the host, so
// another site cannot open it with the admin's cookie.
func (s *Server) handleWS(w http.ResponseWriter, r *http.Request, a *authCtx) {
	c, err := websocket.Accept(w, r, nil) // nil options = same-origin only
	if err != nil {
		return
	}
	defer func() { _ = c.CloseNow() }()
	ctx := c.CloseRead(r.Context()) // we only send; this notices the close

	events, stopEvents := s.cfg.Node.Subscribe()
	defer stopEvents()
	var logs <-chan logRecord
	if s.cfg.Logs != nil {
		ch, stop := s.cfg.Logs.Subscribe()
		defer stop()
		logs = ch
	}
	tick := time.NewTicker(statusTickEvery)
	defer tick.Stop()

	send := func(e eventView) bool {
		b, err := json.Marshal(e)
		if err != nil {
			return false
		}
		wctx, cancel := context.WithTimeout(ctx, wsWriteTimeout)
		defer cancel()
		return c.Write(wctx, websocket.MessageText, b) == nil
	}
	tickEvent := func() eventView {
		st := statusView(s.cfg.Node.Snapshot(), s.now())
		var data map[string]any
		b, _ := json.Marshal(st)
		_ = json.Unmarshal(b, &data)
		return eventView{Type: "status.tick", At: s.now(), Data: data}
	}
	if !send(tickEvent()) {
		return
	}
	for {
		select {
		case <-ctx.Done():
			_ = c.Close(websocket.StatusNormalClosure, "")
			return
		case <-tick.C:
			if !send(tickEvent()) {
				return
			}
		case e, ok := <-events:
			if !ok || !send(eventView{Type: e.Type, At: e.At, Data: e.Data}) {
				return
			}
		case l, ok := <-logs:
			if !ok {
				logs = nil
				continue
			}
			data := map[string]any{"level": l.Level, "message": l.Message}
			if len(l.Attrs) > 0 {
				data["attrs"] = l.Attrs
			}
			if !send(eventView{Type: "log", At: l.At, Data: data}) {
				return
			}
		}
	}
}
