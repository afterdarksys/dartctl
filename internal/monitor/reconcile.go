package monitor

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/afterdarksys/dartctl/internal/api"
)

// Expect describes the account state that counts as healthy.
type Expect struct {
	Hosts         []string `json:"hosts,omitempty"` // every hostname that must exist, run and be active
	AlertNewHosts bool     `json:"alert_new_hosts,omitempty"`
	IPs           []string `json:"ips,omitempty"`         // addresses that must stay attached
	MinCredit     *float64 `json:"min_credit,omitempty"`  // warn when credit falls below this (USD)
	WebhookID     int      `json:"webhook_id,omitempty"`  // the webhook that must stay enabled
	WebhookURL    string   `json:"webhook_url,omitempty"` // or: the receiver URL a webhook must point at
}

// Reconcile reads the account and returns every open finding. Read errors are
// findings too, so a broken token or API outage is reported, not hidden. It
// also returns the key prefixes it could not evaluate this pass; Transition
// keeps their earlier findings open instead of reporting them resolved.
func Reconcile(ctx context.Context, c *api.Client, ex Expect, now time.Time) ([]Alert, []string) {
	var out []Alert
	var unevaluated []string
	add := func(key string, sev Severity, title, detail string) {
		out = append(out, Alert{Key: key, Severity: sev, Level: sev.String(), Title: title, Detail: detail, Source: "reconcile", Time: now})
	}

	instances, err := c.Instances(ctx, "")
	if err != nil {
		add("api:compute", Critical, "DartNode API: cannot list instances", err.Error())
		unevaluated = append(unevaluated, "host:")
	} else {
		byHost := map[string]api.Instance{}
		for _, in := range instances {
			byHost[in.Hostname] = in
		}
		for _, h := range ex.Hosts {
			in, ok := byHost[h]
			switch {
			case !ok:
				add("host:"+h+":missing", Critical, "DartNode instance missing: "+h, "not returned by /v1/compute")
			case in.ServiceStatus != "active":
				add("host:"+h+":service", Critical, fmt.Sprintf("DartNode instance %s is %s", h, in.ServiceStatus), fmt.Sprintf("service_id=%d", in.ID))
			case in.Status != "running":
				add("host:"+h+":power", Critical, fmt.Sprintf("DartNode instance %s is %s", h, in.Status), fmt.Sprintf("service_id=%d", in.ID))
			}
		}
		if ex.AlertNewHosts && len(ex.Hosts) > 0 {
			want := map[string]bool{}
			for _, h := range ex.Hosts {
				want[h] = true
			}
			for _, in := range instances {
				if !want[in.Hostname] {
					add("host:"+in.Hostname+":unexpected", Warning, "Unexpected DartNode instance: "+in.Hostname, fmt.Sprintf("service_id=%d status=%s", in.ID, in.ServiceStatus))
				}
			}
		}
	}

	invoices, err := c.AllInvoices(ctx)
	if err != nil {
		add("api:invoices", Critical, "DartNode API: cannot list invoices", err.Error())
		unevaluated = append(unevaluated, "invoice:")
	} else {
		for _, inv := range invoices {
			if inv.Status == "paid" || inv.Status == "refunded" {
				continue
			}
			sev := Warning
			if inv.Status == "overdue" || pastDue(inv.DueAt, now) {
				sev = Critical
			}
			add(fmt.Sprintf("invoice:%d", inv.ID), sev, fmt.Sprintf("DartNode invoice %d is %s ($%.2f)", inv.ID, inv.Status, inv.Total), fmt.Sprintf("due %s: %s", inv.DueAt, clip(inv.Description, 120)))
		}
	}

	bal, err := c.Balance(ctx)
	if err != nil {
		add("api:balance", Critical, "DartNode API: cannot read balance", err.Error())
		unevaluated = append(unevaluated, "balance:")
	} else {
		credit := -bal.Balance
		if bal.Balance > 0 {
			add("balance:owed", Critical, fmt.Sprintf("DartNode balance owed: $%.2f", bal.Balance), "")
		} else if ex.MinCredit != nil && credit < *ex.MinCredit {
			add("balance:low", Warning, fmt.Sprintf("DartNode credit low: $%.2f (alert below $%.2f)", credit, *ex.MinCredit), "")
		}
	}

	if len(ex.IPs) > 0 {
		ips, err := c.IPs(ctx)
		if err != nil {
			add("api:ips", Critical, "DartNode API: cannot list IPs", err.Error())
			unevaluated = append(unevaluated, "ip:")
		} else {
			have := map[string]bool{}
			for _, ip := range ips {
				if ip.AttachedTo != nil {
					have[ip.Address] = true
				}
			}
			for _, want := range ex.IPs {
				if !have[want] {
					add("ip:"+want, Critical, "DartNode IP not attached: "+want, "")
				}
			}
		}
	}

	if ex.WebhookID == 0 && ex.WebhookURL != "" {
		hooks, err := c.Webhooks(ctx)
		if err != nil {
			add("api:webhook", Warning, "DartNode API: cannot list webhooks", err.Error())
			unevaluated = append(unevaluated, "webhook:")
		} else {
			found := 0
			for _, h := range hooks {
				if h.URL == ex.WebhookURL {
					found++
					if disabled, known := api.WebhookDisabled(h); known && disabled {
						add(fmt.Sprintf("webhook:%d:disabled", h.ID), Critical, fmt.Sprintf("DartNode webhook %d is disabled", h.ID), "DartNode disables a webhook after 10 failed deliveries; fix the receiver, then re-enable it")
					}
				}
			}
			if found == 0 {
				add("webhook:missing", Critical, "No DartNode webhook points at "+ex.WebhookURL, "events are not being delivered; run scripts/setup-webhook.sh")
			}
		}
	}

	if ex.WebhookID > 0 {
		w, err := c.WebhookDetail(ctx, ex.WebhookID)
		switch {
		case api.IsStatus(err, 404):
			add("webhook:missing", Critical, fmt.Sprintf("DartNode webhook %d no longer exists", ex.WebhookID), "events are not being delivered")
		case err != nil:
			add("api:webhook", Warning, "DartNode API: cannot read webhook", err.Error())
			unevaluated = append(unevaluated, "webhook:")
		default:
			if disabled, known := api.WebhookDisabled(w); known && disabled {
				add("webhook:disabled", Critical, fmt.Sprintf("DartNode webhook %d is disabled", ex.WebhookID), "DartNode disables a webhook after 10 failed deliveries; fix the receiver, then re-enable it")
			}
		}
	}

	sort.Slice(out, func(i, j int) bool { return out[i].Key < out[j].Key })
	return out, unevaluated
}

func pastDue(due string, now time.Time) bool {
	t, err := time.Parse(time.RFC3339, due)
	return err == nil && now.After(t)
}

// RemindEvery re-sends a still-open critical finding at most this often.
const RemindEvery = 24 * time.Hour

// Transition compares current findings with the stored ones and returns the
// alerts to send: new findings, severity changes, daily reminders for open
// criticals, and a resolved notice for each finding that cleared. The caller
// saves the returned state only after sending.
func Transition(prev map[string]Finding, current []Alert, unevaluated []string, now time.Time) ([]Alert, map[string]Finding) {
	next := map[string]Finding{}
	var send []Alert
	for _, a := range current {
		f, open := prev[a.Key]
		switch {
		case !open:
			f = Finding{Severity: a.Severity.String(), Title: a.Title, Since: now, Notified: now}
			send = append(send, a)
		case f.Severity != a.Severity.String():
			f.Severity, f.Title, f.Notified = a.Severity.String(), a.Title, now
			send = append(send, a)
		case a.Severity == Critical && now.Sub(f.Notified) >= RemindEvery:
			f.Notified = now
			a.Detail = strings.TrimSpace(a.Detail + fmt.Sprintf(" (open since %s)", f.Since.UTC().Format(time.RFC3339)))
			send = append(send, a)
		}
		next[a.Key] = f
	}
	for key, f := range prev {
		if _, still := next[key]; still {
			continue
		}
		if hasAnyPrefix(key, unevaluated) {
			next[key] = f // could not check this pass: still open, no news
			continue
		}
		sev, _ := ParseSeverity(f.Severity)
		send = append(send, Alert{Key: key, Severity: sev, Level: sev.String(), Title: f.Title, Detail: "cleared", Source: "reconcile", Resolved: true, Time: now})
	}
	return send, next
}

func hasAnyPrefix(key string, prefixes []string) bool {
	for _, p := range prefixes {
		if strings.HasPrefix(key, p) {
			return true
		}
	}
	return false
}
