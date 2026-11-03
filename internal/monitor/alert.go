package monitor

import (
	"fmt"
	"strings"
	"time"
)

type Severity int

const (
	Info Severity = iota
	Warning
	Critical
)

func (s Severity) String() string {
	switch s {
	case Critical:
		return "critical"
	case Warning:
		return "warning"
	default:
		return "info"
	}
}

func ParseSeverity(s string) (Severity, error) {
	switch strings.ToLower(s) {
	case "", "warning":
		return Warning, nil
	case "info":
		return Info, nil
	case "critical":
		return Critical, nil
	}
	return Info, fmt.Errorf("unknown severity %q (info, warning, critical)", s)
}

// Alert is what sinks deliver. Key identifies the condition so repeated
// reconciler runs alert on change, not on every pass.
type Alert struct {
	Key      string    `json:"key"`
	Severity Severity  `json:"-"`
	Level    string    `json:"severity"`
	Title    string    `json:"title"`
	Detail   string    `json:"detail,omitempty"`
	Source   string    `json:"source"` // "webhook" or "reconcile"
	Resolved bool      `json:"resolved,omitempty"`
	Time     time.Time `json:"time"`
}

func (a Alert) Text() string {
	prefix := strings.ToUpper(a.Severity.String())
	if a.Resolved {
		prefix = "RESOLVED"
	}
	s := fmt.Sprintf("[dnctl %s] %s", prefix, a.Title)
	if a.Detail != "" {
		s += "\n" + a.Detail
	}
	return s
}

// Event is a DartNode webhook payload.
type Event struct {
	ID        string         `json:"id"`
	Type      string         `json:"type"`
	CreatedAt string         `json:"created_at"`
	Data      map[string]any `json:"data"`
}

var eventSeverity = map[string]Severity{
	"service.suspended":      Critical,
	"service.terminated":     Critical,
	"invoice.past_due":       Critical,
	"service.power.off":      Critical,
	"ip.detached":            Critical,
	"service.cancelled":      Warning,
	"service.power.reboot":   Warning,
	"service.power.shutdown": Warning,
	"refund.issued":          Warning,
	"invoice.created":        Info,
	"invoice.paid":           Info,
	"service.provisioned":    Info,
	"service.deployed":       Info,
	"service.unsuspended":    Info,
	"service.power.on":       Info,
	"ip.attached":            Info,
}

// AlertForEvent maps a verified webhook event to an alert. Unknown event types
// are warnings so new DartNode events are noticed, not dropped.
func AlertForEvent(e Event, now time.Time) Alert {
	sev, ok := eventSeverity[e.Type]
	if !ok {
		sev = Warning
	}
	var parts []string
	for _, k := range []string{"hostname", "service_id", "invoice_id", "status", "total", "ip", "address", "region"} {
		if v, ok := e.Data[k]; ok && v != nil {
			parts = append(parts, fmt.Sprintf("%s=%s", k, clip(fmt.Sprint(v), 120)))
		}
	}
	title := "DartNode " + e.Type
	if h, ok := e.Data["hostname"].(string); ok && h != "" {
		title += " on " + clip(h, 120)
	}
	return Alert{
		Key:      "event:" + e.ID,
		Severity: sev,
		Level:    sev.String(),
		Title:    title,
		Detail:   strings.Join(parts, " "),
		Source:   "webhook",
		Time:     now,
	}
}

func clip(s string, n int) string {
	s = strings.Map(func(r rune) rune {
		if r < ' ' || r == 0x7f {
			return ' '
		}
		return r
	}, s)
	if len(s) > n {
		return s[:n] + "..."
	}
	return s
}
