package session

import (
	"math"
	"time"
)

// rtt is the smoothed RTT, or the initial guess before any sample.
func (p *mpPath) rtt() time.Duration {
	if !p.hasRTT {
		return initialRTT
	}
	return p.srtt
}

// pto is the probe timeout before backoff (spec §11.4).
func (p *mpPath) pto() time.Duration {
	if !p.hasRTT {
		return 2 * initialRTT
	}
	return p.srtt + max(4*p.rttvar, time.Millisecond) + maxAckDelay
}

// ptoDeadline is when the probe timer fires, if armed: a probe timeout
// after the later of the oldest packet still in flight and the last ACK
// that acknowledged something. Unlike RFC 9002, which counts from the
// last packet sent, a path that keeps sending into a blackhole is still
// caught (ADR-0013 §5).
func (p *mpPath) ptoDeadline() (time.Time, bool) {
	if !p.elicitingInFlight() {
		return time.Time{}, false
	}
	return p.progressBase().Add(p.pto() << min(p.ptoCount, maxPTOBackoff)), true
}

// progressBase is the later of the last ACK progress and the send time of
// the oldest ack-eliciting packet in flight.
func (p *mpPath) progressBase() time.Time {
	base := p.lastProgress
	for _, sp := range p.sent {
		if sp.ackEliciting && !sp.acked && !sp.lost {
			if sp.at.After(base) {
				base = sp.at
			}
			break
		}
	}
	return base
}

func (p *mpPath) elicitingInFlight() bool { return p.elicitCount > 0 }

// track adds a packet that was just sent.
func (p *mpPath) track(sp *sentPacket) {
	p.sent = append(p.sent, sp)
	p.pktsSent++
	p.bytesSent += uint64(sp.size)
	if sp.ackEliciting {
		p.inflight += sp.size
		p.elicitCount++
		p.lastElicit = sp.at
	}
}

// settle takes an acknowledged or lost packet out of flight.
func (p *mpPath) settle(sp *sentPacket) {
	if sp.ackEliciting {
		p.inflight -= sp.size
		p.elicitCount--
	}
}

// observeRTT folds in a sample (RFC 9002 §5).
func (p *mpPath) observeRTT(sample, ackDelay time.Duration) {
	if sample <= 0 {
		return
	}
	p.latestRTT = sample
	if !p.hasRTT {
		p.hasRTT = true
		p.minRTT, p.srtt, p.rttvar = sample, sample, sample/2
		return
	}
	p.minRTT = min(p.minRTT, sample)
	adjusted := sample
	if ackDelay = min(ackDelay, maxAckDelay); sample-ackDelay >= p.minRTT {
		adjusted = sample - ackDelay
	}
	d := p.srtt - adjusted
	if d < 0 {
		d = -d
	}
	p.rttvar = (3*p.rttvar + d) / 4
	p.srtt = (7*p.srtt + adjusted) / 8
}

// lossDelay is the time threshold of loss detection.
func (p *mpPath) lossDelay() time.Duration {
	return max(p.rtt()*9/8, p.latestRTT*9/8, time.Millisecond)
}

// onDelivered records acknowledged bytes and updates the window from the
// delivery rate (ADR-0013 §6).
func (p *mpPath) onDelivered(sp *sentPacket, now time.Time) {
	p.delivered += int64(sp.size)
	p.deliveredAt = now
	if dt := now.Sub(sp.deliveredAt); dt > 0 {
		rate := float64(p.delivered-sp.delivered) / dt.Seconds()
		p.rates[p.rateIdx%len(p.rates)] = rateSample{at: now, rate: rate}
		p.rateIdx++
	}
	p.updateCwnd(now)
}

func (p *mpPath) maxRate(now time.Time) float64 {
	best := 0.0
	for _, r := range p.rates {
		if !r.at.IsZero() && now.Sub(r.at) < rateWindow {
			best = max(best, r.rate)
		}
	}
	return best
}

func (p *mpPath) updateCwnd(now time.Time) {
	rate := p.maxRate(now)
	if rate == 0 || !p.hasRTT {
		return
	}
	bdp := rate * max(p.minRTT, time.Millisecond).Seconds()
	w := 2*bdp*p.lossFactor + float64(minCwnd)
	p.cwnd = int(math.Min(math.Max(w, minCwnd), maxCwnd))
}

// onCongestion answers a loss that FEC did not repair: datagram paths cut
// their window once per round trip. Stream paths lose packets only when
// they die, and their transport already reacts to congestion.
func (p *mpPath) onCongestion(pn uint64, now time.Time) {
	if !p.datagram || pn < p.recoveryPN {
		return
	}
	p.recoveryPN = p.nextPN
	p.lossFactor = max(p.lossFactor*0.7, lossFactorMin)
	p.updateCwnd(now)
}

// sampleLoss updates the smoothed loss rate; called once a second.
func (p *mpPath) sampleLoss() {
	sent, lost := p.pktsSent-p.lastSent, p.pktsLost-p.lastLost
	p.lastSent, p.lastLost = p.pktsSent, p.pktsLost
	if sent == 0 {
		return
	}
	sample := float64(lost) / float64(sent)
	p.lossEWMA = 0.75*p.lossEWMA + 0.25*sample
	if lost == 0 && p.lossFactor < 1 {
		p.lossFactor = min(1, p.lossFactor*1.1)
	}
}

// paceBurst is how many full packets a paced path may send back to back.
const paceBurst = 10

// paceRefill adds the budget earned since the last refill: 1.25 × window
// per smoothed RTT (ADR-0016 §5).
func (p *mpPath) paceRefill(now time.Time) {
	if !p.pace {
		return
	}
	rate := 1.25 * float64(p.cwnd) / max(p.rtt(), time.Millisecond).Seconds()
	p.tokens = math.Min(p.tokens+rate*now.Sub(p.paceAt).Seconds(), float64(paceBurst*p.maxBody))
	p.paceAt = now
}

// paceReady reports whether a full packet may leave now.
func (p *mpPath) paceReady() bool { return !p.pace || p.tokens >= float64(p.maxBody) }

// paceWait is how long until a full packet may leave.
func (p *mpPath) paceWait() time.Duration {
	if p.paceReady() {
		return 0
	}
	rate := 1.25 * float64(p.cwnd) / max(p.rtt(), time.Millisecond).Seconds()
	return time.Duration((float64(p.maxBody) - p.tokens) / rate * float64(time.Second))
}
