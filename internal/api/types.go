package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
)

type IP struct {
	Address           string `json:"address"`
	Type              string `json:"type"`
	PTR               string `json:"ptr"`
	ResolvedPTR       string `json:"resolved_ptr,omitempty"`
	IsPrimary         bool   `json:"is_primary"`
	HasDDoSProtection bool   `json:"has_ddos_protection"`
	AttachedTo        *struct {
		ID       int    `json:"id"`
		Hostname string `json:"hostname"`
	} `json:"attached_to,omitempty"`
}

type Instance struct {
	ID            int    `json:"id"`
	Hostname      string `json:"hostname"`
	Status        string `json:"status"`         // power: running, stopped, provisioning, unknown
	ServiceStatus string `json:"service_status"` // billing: active, suspended, terminated
	PrimaryIP     string `json:"primary_ip"`
	IPs           []IP   `json:"ips"`
	CPU           struct {
		Cores        int     `json:"cores"`
		UsagePercent float64 `json:"usage_percent"`
	} `json:"cpu"`
	Memory struct {
		TotalMB      int     `json:"total_mb"`
		UsedMB       int     `json:"used_mb"`
		UsagePercent float64 `json:"usage_percent"`
	} `json:"memory"`
	DiskGB  int    `json:"disk_gb"`
	OS      string `json:"os,omitempty"`
	Region  string `json:"region"`
	Billing *struct {
		Amount      float64 `json:"amount"`
		TermMonths  int     `json:"term_months"`
		NextPayment string  `json:"next_payment"`
	} `json:"billing,omitempty"`
	CreatedAt string `json:"created_at"`
}

type Invoice struct {
	ID            int     `json:"id"`
	Description   string  `json:"description"`
	Status        string  `json:"status"` // paid, unpaid, overdue, refunded
	Total         float64 `json:"total"`
	CreditApplied float64 `json:"credit_applied"`
	DueAt         string  `json:"due_at"`
	PaidAt        string  `json:"paid_at"`
	CreatedAt     string  `json:"created_at"`
}

type Balance struct {
	// Negative means credit: -25.50 is $25.50 of credit.
	Balance  float64 `json:"balance"`
	Currency string  `json:"currency"`
}

// Webhook keeps unknown fields so callers can show whatever DartNode returns
// (for example an enabled flag or recent deliveries).
type Webhook struct {
	ID     int             `json:"id"`
	Name   string          `json:"name"`
	URL    string          `json:"url"`
	Events []string        `json:"events"`
	Raw    json.RawMessage `json:"-"`
}

func decodeAll[T any](items []json.RawMessage) ([]T, error) {
	out := make([]T, 0, len(items))
	for _, raw := range items {
		var v T
		if err := json.Unmarshal(raw, &v); err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, nil
}

func (c *Client) Instances(ctx context.Context, status string) ([]Instance, error) {
	q := url.Values{}
	if status != "" {
		q.Set("status", status)
	}
	items, err := c.ListAll(ctx, "/compute", "services", q)
	if err != nil {
		return nil, err
	}
	return decodeAll[Instance](items)
}

func (c *Client) Instance(ctx context.Context, id int) (Instance, error) {
	var in Instance
	err := c.Do(ctx, http.MethodGet, "/compute/"+strconv.Itoa(id), nil, nil, &in)
	return in, err
}

// AllInvoices returns every invoice. DartNode's status filter is not reliable,
// so filter on the client.
func (c *Client) AllInvoices(ctx context.Context) ([]Invoice, error) {
	items, err := c.ListAll(ctx, "/billing/invoices", "invoices", nil)
	if err != nil {
		return nil, err
	}
	return decodeAll[Invoice](items)
}

func (c *Client) Balance(ctx context.Context) (Balance, error) {
	var b Balance
	err := c.Do(ctx, http.MethodGet, "/billing/balance", nil, nil, &b)
	return b, err
}

func (c *Client) IPs(ctx context.Context) ([]IP, error) {
	var data struct {
		IPs []IP `json:"ips"`
	}
	err := c.Do(ctx, http.MethodGet, "/network/ips", nil, nil, &data)
	return data.IPs, err
}

func (c *Client) Webhooks(ctx context.Context) ([]Webhook, error) {
	var data struct {
		Webhooks []json.RawMessage `json:"webhooks"`
	}
	if err := c.Do(ctx, http.MethodGet, "/webhooks", nil, nil, &data); err != nil {
		return nil, err
	}
	out := make([]Webhook, 0, len(data.Webhooks))
	for _, raw := range data.Webhooks {
		w, err := parseWebhook(raw)
		if err != nil {
			return nil, err
		}
		out = append(out, w)
	}
	return out, nil
}

// WebhookDetail returns one webhook with whatever detail DartNode includes.
func (c *Client) WebhookDetail(ctx context.Context, id int) (Webhook, error) {
	var raw json.RawMessage
	if err := c.Do(ctx, http.MethodGet, "/webhooks/"+strconv.Itoa(id), nil, nil, &raw); err != nil {
		return Webhook{}, err
	}
	// Some APIs wrap the object: {"webhook": {...}}.
	var wrapped map[string]json.RawMessage
	if json.Unmarshal(raw, &wrapped) == nil {
		if inner, ok := wrapped["webhook"]; ok {
			raw = inner
		}
	}
	return parseWebhook(raw)
}

func parseWebhook(raw json.RawMessage) (Webhook, error) {
	var w Webhook
	if err := json.Unmarshal(raw, &w); err != nil {
		return w, fmt.Errorf("decode webhook: %w", err)
	}
	w.Raw = raw
	return w, nil
}

// WebhookDisabled inspects whatever state fields DartNode returns. It reports
// (disabled, known). Unknown schemas return known=false rather than guessing.
func WebhookDisabled(w Webhook) (bool, bool) {
	var m map[string]any
	if json.Unmarshal(w.Raw, &m) != nil {
		return false, false
	}
	for _, k := range []string{"active", "enabled", "is_active", "is_enabled"} {
		if v, ok := m[k].(bool); ok {
			return !v, true
		}
	}
	for _, k := range []string{"status", "state"} {
		if v, ok := m[k].(string); ok {
			switch v {
			case "active", "enabled":
				return false, true
			case "disabled", "inactive", "paused", "failed":
				return true, true
			}
		}
	}
	if v, ok := m["disabled"].(bool); ok {
		return v, true
	}
	return false, false
}
