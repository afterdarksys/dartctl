// Package cli implements the dartctl command line.
package cli

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"text/tabwriter"

	"github.com/afterdarksys/dartctl/internal/api"
	"github.com/afterdarksys/dartctl/internal/secretfile"
)

var Version = "0.1.0-dev"

const usage = `dartctl - unofficial command line and monitor for the DartNode API

Usage: dartctl [global flags] <command> [arguments] [flags]

Read:
  account                               account profile
  compute list [--status S]             instances (status: active, suspended, pending, terminated)
  compute get <id> | config <id>        one instance / its configuration
  ips list | get <ip>                   IP addresses and reverse DNS
  billing invoices [--open] | invoice <id> | balance
  deploy plans | regions | os-templates | estimate <deploy flags>
  webhooks list [--url URL] | get <id> | events

Change (every change needs --yes; destructive ones also --confirm):
  power <id> on|shutdown|reboot-hard|off      off and reboot-hard need --confirm <hostname>
  hostname <id> <new-hostname>
  reinstall <id> --os <template-id>           wipes the disk; --confirm <hostname>
  reset-password <id>                         --confirm <hostname>
  console <id>                                prints a short-lived VNC URL (a live credential)
  rdns set <ip> <fqdn> | rdns clear <ip>      clear needs --confirm <ip>
  deploy create <deploy flags>                charges account credit
  webhooks create --name N --url URL --events a,b|* --secret-out FILE
  webhooks update <id> [--name N] [--url URL] [--events ...]
  webhooks delete <id> --confirm <id>

Monitor:
  monitor check --config FILE           one reconcile pass; exit 3 if a critical finding is open
  monitor serve --config FILE           webhook receiver + reconcile loop
  monitor test-alert --config FILE      send a test alert to every sink
  monitor send-test --secret-file F --url URL [--event T]   signed sample delivery to your receiver

Global flags (before the command):
  --token-file FILE   API token file (mode 600). Without it: $DARTNODE_TOKEN,
                      then $DARTCTL_TOKEN_FILE, then ~/.config/dartctl/token
  --api URL           API base (default https://api.dartnode.net/v1)
  --json              print raw JSON

The token is never accepted as a command-line argument.
`

type env struct {
	out, errw io.Writer
	jsonOut   bool
	tokenFile string
	apiBase   string
	getenv    func(string) string
}

// Main runs dartctl and returns the process exit code.
func Main(args []string, stdout, stderr io.Writer) int {
	e := &env{out: stdout, errw: stderr, getenv: os.Getenv}
	rest, err := e.globals(args)
	if err != nil {
		fmt.Fprintln(stderr, "dartctl:", err)
		return 2
	}
	if len(rest) == 0 || rest[0] == "help" || rest[0] == "-h" || rest[0] == "--help" {
		fmt.Fprint(stdout, usage)
		return 0
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := e.run(ctx, rest[0], rest[1:]); err != nil {
		var ue usageError
		var ex exitError
		switch {
		case errors.As(err, &ex):
			return int(ex)
		case errors.As(err, &ue):
			fmt.Fprintln(stderr, "dartctl:", err)
			return 2
		default:
			fmt.Fprintln(stderr, "dartctl:", err)
			return 1
		}
	}
	return 0
}

type usageError string

func (u usageError) Error() string { return string(u) }

type exitError int

func (e exitError) Error() string { return "exit " + strconv.Itoa(int(e)) }

func usagef(f string, a ...any) error { return usageError(fmt.Sprintf(f, a...)) }

func (e *env) globals(args []string) ([]string, error) {
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "--json":
			e.jsonOut = true
		case a == "--token-file" || a == "--api":
			if i+1 >= len(args) {
				return nil, fmt.Errorf("%s needs a value", a)
			}
			if a == "--token-file" {
				e.tokenFile = args[i+1]
			} else {
				e.apiBase = args[i+1]
			}
			i++
		case strings.HasPrefix(a, "--token-file="):
			e.tokenFile = strings.TrimPrefix(a, "--token-file=")
		case strings.HasPrefix(a, "--api="):
			e.apiBase = strings.TrimPrefix(a, "--api=")
		case a == "--token" || strings.HasPrefix(a, "--token="):
			return nil, errors.New("--token is not accepted: put the token in a mode-600 file and pass --token-file, or set DARTNODE_TOKEN")
		case a == "--version":
			return []string{"version"}, nil
		case strings.HasPrefix(a, "-"):
			return nil, usagef("unknown global flag %s (global flags go before the command)", a)
		default:
			// The command word: everything from here belongs to the command.
			return args[i:], nil
		}
	}
	return nil, nil
}

// client resolves the token: --token-file, then $DARTNODE_TOKEN, then
// $DARTCTL_TOKEN_FILE, then ~/.config/dartctl/token. An explicit flag always wins,
// so a stray environment variable can never redirect a change to another
// account.
func (e *env) client() (*api.Client, error) {
	var tok string
	if e.tokenFile == "" {
		tok = strings.TrimSpace(e.getenv("DARTNODE_TOKEN"))
	}
	if tok == "" {
		path := e.tokenFile
		if path == "" {
			path = e.getenv("DARTCTL_TOKEN_FILE")
		}
		if path == "" {
			home, err := os.UserHomeDir()
			if err != nil {
				return nil, err
			}
			path = filepath.Join(home, ".config", "dartctl", "token")
		}
		var err error
		if tok, err = secretfile.Read(path); err != nil {
			return nil, fmt.Errorf("API token: %w", err)
		}
	}
	return api.New(e.apiBase, tok)
}

// flags parses a subcommand's flags anywhere among its arguments.
type flags struct {
	fs  *flag.FlagSet
	pos []string
}

func newFlags(name string) *flags {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	return &flags{fs: fs}
}

func (f *flags) parse(args []string) error {
	for len(args) > 0 {
		if err := f.fs.Parse(args); err != nil {
			return usageError(err.Error())
		}
		args = f.fs.Args()
		if len(args) > 0 {
			f.pos = append(f.pos, args[0])
			args = args[1:]
		}
	}
	return nil
}

func (f *flags) need(n int, form string) error {
	if len(f.pos) != n {
		return usagef("usage: dartctl %s", form)
	}
	return nil
}

func atoiArg(s, what string) (int, error) {
	n, err := strconv.Atoi(s)
	if err != nil || n <= 0 {
		return 0, usagef("%s must be a positive number", what)
	}
	return n, nil
}

func (e *env) print(v any, table func(w *tabwriter.Writer)) error {
	if e.jsonOut || table == nil {
		enc := json.NewEncoder(e.out)
		enc.SetIndent("", "  ")
		return enc.Encode(v)
	}
	w := tabwriter.NewWriter(e.out, 0, 2, 2, ' ', 0)
	table(w)
	return w.Flush()
}

func (e *env) run(ctx context.Context, cmd string, args []string) error {
	switch cmd {
	case "version":
		fmt.Fprintln(e.out, "dartctl", Version)
		return nil
	case "account":
		return e.raw(ctx, "/account", nil)
	case "compute":
		return e.compute(ctx, args)
	case "ips":
		return e.ips(ctx, args)
	case "billing":
		return e.billing(ctx, args)
	case "deploy":
		return e.deploy(ctx, args)
	case "webhooks":
		return e.webhooks(ctx, args)
	case "power", "hostname", "reinstall", "reset-password", "console":
		return e.serviceChange(ctx, cmd, args)
	case "rdns":
		return e.rdns(ctx, args)
	case "monitor":
		return e.monitor(ctx, args)
	}
	return usagef("unknown command %q (dartctl help)", cmd)
}

func (e *env) raw(ctx context.Context, path string, q url.Values) error {
	c, err := e.client()
	if err != nil {
		return err
	}
	var data json.RawMessage
	if err := c.Do(ctx, "GET", path, q, nil, &data); err != nil {
		return err
	}
	return e.print(data, nil)
}

func (e *env) compute(ctx context.Context, args []string) error {
	if len(args) == 0 {
		return usagef("usage: dartctl compute list|get|config")
	}
	f := newFlags("compute")
	status := f.fs.String("status", "", "")
	if err := f.parse(args[1:]); err != nil {
		return err
	}
	c, err := e.client()
	if err != nil {
		return err
	}
	switch args[0] {
	case "list":
		list, err := c.Instances(ctx, *status)
		if err != nil {
			return err
		}
		return e.print(list, func(w *tabwriter.Writer) {
			fmt.Fprintln(w, "ID\tHOSTNAME\tPOWER\tSERVICE\tIP\tREGION\tCPU\tRAM\tDISK")
			for _, in := range list {
				fmt.Fprintf(w, "%d\t%s\t%s\t%s\t%s\t%s\t%d\t%dG\t%dG\n", in.ID, in.Hostname, in.Status, in.ServiceStatus, in.PrimaryIP, in.Region, in.CPU.Cores, in.Memory.TotalMB/1024, in.DiskGB)
			}
		})
	case "get", "config":
		if err := f.need(1, "compute "+args[0]+" <id>"); err != nil {
			return err
		}
		id, err := atoiArg(f.pos[0], "id")
		if err != nil {
			return err
		}
		path := "/compute/" + strconv.Itoa(id)
		if args[0] == "config" {
			path += "/config"
		}
		return e.raw(ctx, path, nil)
	}
	return usagef("usage: dartctl compute list|get|config")
}

func (e *env) ips(ctx context.Context, args []string) error {
	if len(args) == 0 {
		return usagef("usage: dartctl ips list|get <ip>")
	}
	c, err := e.client()
	if err != nil {
		return err
	}
	switch args[0] {
	case "list":
		list, err := c.IPs(ctx)
		if err != nil {
			return err
		}
		return e.print(list, func(w *tabwriter.Writer) {
			fmt.Fprintln(w, "ADDRESS\tTYPE\tPTR\tATTACHED TO\tDDOS")
			for _, ip := range list {
				host := "-"
				if ip.AttachedTo != nil {
					host = ip.AttachedTo.Hostname
				}
				fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%v\n", ip.Address, ip.Type, ip.PTR, host, ip.HasDDoSProtection)
			}
		})
	case "get":
		if len(args) != 2 || !validIP(args[1]) {
			return usagef("usage: dartctl ips get <ip>")
		}
		return e.raw(ctx, "/network/ips/"+args[1], nil)
	}
	return usagef("usage: dartctl ips list|get <ip>")
}

func validIP(s string) bool {
	if s == "" || len(s) > 45 {
		return false
	}
	for _, r := range s {
		if !(r == '.' || r == ':' || (r >= '0' && r <= '9') || (r >= 'a' && r <= 'f') || (r >= 'A' && r <= 'F')) {
			return false
		}
	}
	return true
}

func (e *env) billing(ctx context.Context, args []string) error {
	if len(args) == 0 {
		return usagef("usage: dartctl billing invoices|invoice <id>|balance")
	}
	f := newFlags("billing")
	open := f.fs.Bool("open", false, "")
	if err := f.parse(args[1:]); err != nil {
		return err
	}
	c, err := e.client()
	if err != nil {
		return err
	}
	switch args[0] {
	case "invoices":
		list, err := c.AllInvoices(ctx)
		if err != nil {
			return err
		}
		if *open {
			kept := list[:0]
			for _, inv := range list {
				if inv.Status != "paid" && inv.Status != "refunded" {
					kept = append(kept, inv)
				}
			}
			list = kept
		}
		return e.print(list, func(w *tabwriter.Writer) {
			fmt.Fprintln(w, "ID\tSTATUS\tTOTAL\tDUE\tDESCRIPTION")
			var sum float64
			for _, inv := range list {
				sum += inv.Total
				fmt.Fprintf(w, "%d\t%s\t%.2f\t%s\t%s\n", inv.ID, inv.Status, inv.Total, short(inv.DueAt), inv.Description)
			}
			fmt.Fprintf(w, "\t%d invoice(s)\t%.2f\t\t\n", len(list), sum)
		})
	case "invoice":
		if err := f.need(1, "billing invoice <id>"); err != nil {
			return err
		}
		id, err := atoiArg(f.pos[0], "invoice id")
		if err != nil {
			return err
		}
		return e.raw(ctx, "/billing/invoices/"+strconv.Itoa(id), nil)
	case "balance":
		b, err := c.Balance(ctx)
		if err != nil {
			return err
		}
		return e.print(b, func(w *tabwriter.Writer) {
			if b.Balance <= 0 {
				fmt.Fprintf(w, "credit\t%.2f %s\n", -b.Balance, b.Currency)
			} else {
				fmt.Fprintf(w, "owed\t%.2f %s\n", b.Balance, b.Currency)
			}
		})
	}
	return usagef("usage: dartctl billing invoices|invoice <id>|balance")
}

func short(ts string) string {
	if len(ts) >= 10 {
		return ts[:10]
	}
	return ts
}

// confirmService fetches the instance and checks --confirm against its hostname.
func confirmService(ctx context.Context, c *api.Client, id int, confirm, action string) (api.Instance, error) {
	in, err := c.Instance(ctx, id)
	if err != nil {
		return in, err
	}
	if confirm == "" {
		return in, usagef("%s on %s (%d) is destructive: add --confirm %s", action, in.Hostname, id, in.Hostname)
	}
	if confirm != in.Hostname {
		return in, usagef("--confirm %q does not match instance %d hostname %q; nothing was changed", confirm, id, in.Hostname)
	}
	return in, nil
}

func (e *env) serviceChange(ctx context.Context, cmd string, args []string) error {
	f := newFlags(cmd)
	yes := f.fs.Bool("yes", false, "")
	confirm := f.fs.String("confirm", "", "")
	osID := f.fs.Int("os", 0, "")
	if err := f.parse(args); err != nil {
		return err
	}
	if len(f.pos) == 0 {
		return usagef("usage: dartctl %s <id> ...", cmd)
	}
	id, err := atoiArg(f.pos[0], "instance id")
	if err != nil {
		return err
	}
	base := "/compute/" + strconv.Itoa(id)
	var method, path string
	var body any
	destructive := false
	switch cmd {
	case "power":
		if len(f.pos) != 2 {
			return usagef("usage: dartctl power <id> on|shutdown|reboot-hard|off --yes")
		}
		action := map[string]string{"on": "on", "shutdown": "shutdown", "off": "off", "reboot-hard": "reset", "reset": "reset"}[f.pos[1]]
		if action == "" {
			return usagef("power action must be on, shutdown, reboot-hard or off")
		}
		destructive = action == "off" || action == "reset"
		method, path, body = "POST", base+"/power", map[string]string{"action": action}
	case "hostname":
		if len(f.pos) != 2 || !validHostname(f.pos[1]) {
			return usagef("usage: dartctl hostname <id> <new-hostname> --yes")
		}
		method, path, body = "PATCH", base+"/hostname", map[string]string{"hostname": f.pos[1]}
	case "reinstall":
		if len(f.pos) != 1 || *osID <= 0 {
			return usagef("usage: dartctl reinstall <id> --os <template-id> --yes --confirm <hostname>")
		}
		destructive = true
		method, path, body = "POST", base+"/reinstall", map[string]int{"os": *osID}
	case "reset-password":
		destructive = true
		method, path = "POST", base+"/reset-password"
	case "console":
		method, path = "POST", base+"/console/vnc"
	}
	if !*yes {
		return usagef("%s changes instance %d: review, then re-run with --yes", cmd, id)
	}
	c, err := e.client()
	if err != nil {
		return err
	}
	if destructive {
		if _, err := confirmService(ctx, c, id, *confirm, cmd); err != nil {
			return err
		}
	}
	var data json.RawMessage
	if err := c.Do(ctx, method, path, nil, body, &data); err != nil {
		return err
	}
	if cmd == "console" {
		fmt.Fprintln(e.errw, "note: this URL holds a live, short-lived console token; do not paste it anywhere")
	}
	return e.print(data, nil)
}

func validHostname(h string) bool {
	if h == "" || len(h) > 253 {
		return false
	}
	for _, r := range h {
		if !(r == '.' || r == '-' || (r >= '0' && r <= '9') || (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z')) {
			return false
		}
	}
	return true
}

func (e *env) rdns(ctx context.Context, args []string) error {
	f := newFlags("rdns")
	yes := f.fs.Bool("yes", false, "")
	confirm := f.fs.String("confirm", "", "")
	if err := f.parse(args); err != nil {
		return err
	}
	if len(f.pos) < 2 || !validIP(f.pos[1]) {
		return usagef("usage: dartctl rdns set <ip> <fqdn> --yes | rdns clear <ip> --yes --confirm <ip>")
	}
	ip := f.pos[1]
	var method string
	var body any
	switch {
	case f.pos[0] == "set" && len(f.pos) == 3 && validHostname(f.pos[2]):
		method, body = "PUT", map[string]string{"value": f.pos[2]}
	case f.pos[0] == "clear" && len(f.pos) == 2:
		if *confirm != ip {
			return usagef("clearing reverse DNS for %s needs --confirm %s", ip, ip)
		}
		method = "DELETE"
	default:
		return usagef("usage: dartctl rdns set <ip> <fqdn> --yes | rdns clear <ip> --yes --confirm <ip>")
	}
	if !*yes {
		return usagef("rdns %s changes %s: re-run with --yes", f.pos[0], ip)
	}
	c, err := e.client()
	if err != nil {
		return err
	}
	var data json.RawMessage
	if err := c.Do(ctx, method, "/network/ips/"+ip+"/rdns", nil, body, &data); err != nil {
		return err
	}
	return e.print(data, nil)
}

func (e *env) deploy(ctx context.Context, args []string) error {
	if len(args) == 0 {
		return usagef("usage: dartctl deploy plans|regions|os-templates|estimate|create")
	}
	switch args[0] {
	case "plans", "regions", "os-templates":
		return e.raw(ctx, "/deploy/"+args[0], nil)
	case "estimate", "create":
	default:
		return usagef("usage: dartctl deploy plans|regions|os-templates|estimate|create")
	}
	f := newFlags("deploy")
	plan := f.fs.Int("plan", 0, "")
	region := f.fs.String("region", "", "")
	host := f.fs.String("hostname", "", "")
	osCat := f.fs.Int("os", 0, "")
	osVer := f.fs.Int("os-version", 0, "")
	ipv4 := f.fs.Int("ipv4", 1, "")
	ipv6 := f.fs.Int("ipv6", 1, "")
	ddos := f.fs.Bool("ddos", false, "")
	backups := f.fs.Bool("backups", false, "")
	cycle := f.fs.Int("cycle", 1, "")
	yes := f.fs.Bool("yes", false, "")
	if err := f.parse(args[1:]); err != nil {
		return err
	}
	if *plan <= 0 || *region == "" || !validHostname(*host) || *osCat <= 0 || *osVer <= 0 || len(f.pos) != 0 {
		return usagef("usage: dartctl deploy %s --plan ID --region CODE --hostname NAME --os ID --os-version ID [--ipv4 N --ipv6 N --ddos --backups --cycle 1|3|6|12]", args[0])
	}
	if *cycle != 1 && *cycle != 3 && *cycle != 6 && *cycle != 12 {
		return usagef("--cycle must be 1, 3, 6 or 12")
	}
	q := url.Values{}
	q.Set("plan_id", strconv.Itoa(*plan))
	q.Set("region", *region)
	q.Set("hostname", *host)
	q.Set("os", strconv.Itoa(*osCat))
	q.Set("os_version", strconv.Itoa(*osVer))
	q.Set("ipv4", strconv.Itoa(*ipv4))
	q.Set("ipv6", strconv.Itoa(*ipv6))
	q.Set("ddos", strconv.FormatBool(*ddos))
	q.Set("backups", strconv.FormatBool(*backups))
	q.Set("cycle", strconv.Itoa(*cycle))
	c, err := e.client()
	if err != nil {
		return err
	}
	var estimate json.RawMessage
	if err := c.Do(ctx, "GET", "/deploy/estimate", q, nil, &estimate); err != nil {
		return err
	}
	if args[0] == "estimate" {
		return e.print(estimate, nil)
	}
	fmt.Fprintln(e.errw, "estimate:")
	e.print(estimate, nil)
	if !*yes {
		return usagef("deploy create charges account credit: review the estimate, then re-run with --yes")
	}
	body := map[string]any{"plan_id": *plan, "region": *region, "hostname": *host, "os": *osCat, "os_version": *osVer, "ipv4": *ipv4, "ipv6": *ipv6, "ddos": *ddos, "backups": *backups, "cycle": *cycle}
	var data json.RawMessage
	if err := c.Do(ctx, "POST", "/deploy", nil, body, &data); err != nil {
		return err
	}
	return e.print(data, nil)
}

// findSecret returns the plain signing secret from a webhook create response:
// data.secret, or data.webhook.secret. It never falls back to a hash field or
// a random nested value, because saving the wrong value makes every delivery
// fail verification until DartNode disables the webhook.
func findSecret(v any) string {
	top, ok := v.(map[string]any)
	if !ok {
		return ""
	}
	for _, obj := range []any{top, top["webhook"]} {
		m, ok := obj.(map[string]any)
		if !ok {
			continue
		}
		for _, k := range []string{"secret", "signing_secret"} {
			if s, ok := m[k].(string); ok && s != "" {
				return s
			}
		}
	}
	return ""
}

func redactSecrets(v any) any {
	switch t := v.(type) {
	case map[string]any:
		out := map[string]any{}
		for k, child := range t {
			if strings.Contains(strings.ToLower(k), "secret") {
				out[k] = "[written to --secret-out]"
				continue
			}
			out[k] = redactSecrets(child)
		}
		return out
	case []any:
		out := make([]any, len(t))
		for i, child := range t {
			out[i] = redactSecrets(child)
		}
		return out
	}
	return v
}

func splitEvents(s string) []string {
	var out []string
	for _, ev := range strings.Split(s, ",") {
		if ev = strings.TrimSpace(ev); ev != "" {
			out = append(out, ev)
		}
	}
	return out
}

func validHookURL(s string) error {
	u, err := url.Parse(s)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil {
		return usagef("--url must be an https URL without credentials")
	}
	return nil
}

func (e *env) webhooks(ctx context.Context, args []string) error {
	if len(args) == 0 {
		return usagef("usage: dartctl webhooks list|get|events|create|update|delete")
	}
	f := newFlags("webhooks")
	name := f.fs.String("name", "", "")
	hookURL := f.fs.String("url", "", "")
	events := f.fs.String("events", "", "")
	secretOut := f.fs.String("secret-out", "", "")
	yes := f.fs.Bool("yes", false, "")
	confirm := f.fs.String("confirm", "", "")
	if err := f.parse(args[1:]); err != nil {
		return err
	}
	switch args[0] {
	case "list":
		c, err := e.client()
		if err != nil {
			return err
		}
		list, err := c.Webhooks(ctx)
		if err != nil {
			return err
		}
		if *hookURL != "" {
			// Exact match on the decoded URL; scripts use this to avoid duplicates.
			kept := list[:0]
			for _, h := range list {
				if h.URL == *hookURL {
					kept = append(kept, h)
				}
			}
			list = kept
		}
		raws := make([]json.RawMessage, len(list))
		for i, w := range list {
			raws[i] = w.Raw
		}
		return e.print(raws, func(w *tabwriter.Writer) {
			fmt.Fprintln(w, "ID\tNAME\tURL\tEVENTS\tSTATE")
			for _, h := range list {
				state := "unknown"
				if disabled, known := api.WebhookDisabled(h); known {
					state = map[bool]string{true: "DISABLED", false: "enabled"}[disabled]
				}
				fmt.Fprintf(w, "%d\t%s\t%s\t%s\t%s\n", h.ID, h.Name, h.URL, strings.Join(h.Events, ","), state)
			}
		})
	case "get":
		if err := f.need(1, "webhooks get <id>"); err != nil {
			return err
		}
		id, err := atoiArg(f.pos[0], "webhook id")
		if err != nil {
			return err
		}
		return e.raw(ctx, "/webhooks/"+strconv.Itoa(id), nil)
	case "events":
		return e.raw(ctx, "/webhooks/events", nil)
	case "create":
		if *name == "" || *events == "" || *secretOut == "" {
			return usagef("usage: dartctl webhooks create --name N --url URL --events a,b|* --secret-out FILE --yes")
		}
		if err := validHookURL(*hookURL); err != nil {
			return err
		}
		// The secret is shown once: make sure it can be saved before asking for it.
		if _, err := os.Stat(*secretOut); err == nil {
			return usagef("%s already exists; choose a new --secret-out path", *secretOut)
		}
		if dir := filepath.Dir(*secretOut); dir != "" {
			if info, err := os.Stat(dir); err != nil || !info.IsDir() {
				return usagef("directory for --secret-out does not exist: %s", dir)
			}
		}
		if !*yes {
			return usagef("webhooks create registers %s for %s: re-run with --yes", *hookURL, *events)
		}
		c, err := e.client()
		if err != nil {
			return err
		}
		var data any
		if err := c.Do(ctx, "POST", "/webhooks", nil, map[string]any{"name": *name, "url": *hookURL, "events": splitEvents(*events)}, &data); err != nil {
			return err
		}
		secret := findSecret(data)
		if secret == "" {
			return errors.New("webhook created, but the response held no plain signing secret (data.secret); check it in the DartNode dashboard, or delete the webhook and report the response shape")
		}
		if err := secretfile.WriteNew(*secretOut, secret); err != nil {
			return fmt.Errorf("webhook created but saving its secret failed (%v); delete the webhook and create it again", err)
		}
		fmt.Fprintf(e.errw, "signing secret written to %s (mode 600)\n", *secretOut)
		return e.print(redactSecrets(data), nil)
	case "update":
		if err := f.need(1, "webhooks update <id> [--name N] [--url URL] [--events a,b] --yes"); err != nil {
			return err
		}
		id, err := atoiArg(f.pos[0], "webhook id")
		if err != nil {
			return err
		}
		body := map[string]any{}
		if *name != "" {
			body["name"] = *name
		}
		if *hookURL != "" {
			if err := validHookURL(*hookURL); err != nil {
				return err
			}
			body["url"] = *hookURL
		}
		if *events != "" {
			body["events"] = splitEvents(*events)
		}
		if len(body) == 0 {
			return usagef("nothing to update: pass --name, --url or --events")
		}
		if !*yes {
			return usagef("webhooks update changes webhook %d: re-run with --yes", id)
		}
		c, err := e.client()
		if err != nil {
			return err
		}
		var data any
		if err := c.Do(ctx, "PATCH", "/webhooks/"+strconv.Itoa(id), nil, body, &data); err != nil {
			return err
		}
		return e.print(redactSecrets(data), nil)
	case "delete":
		if err := f.need(1, "webhooks delete <id> --yes --confirm <id>"); err != nil {
			return err
		}
		id, err := atoiArg(f.pos[0], "webhook id")
		if err != nil {
			return err
		}
		if *confirm != f.pos[0] {
			return usagef("deleting webhook %d needs --confirm %d", id, id)
		}
		if !*yes {
			return usagef("webhooks delete removes webhook %d: re-run with --yes", id)
		}
		c, err := e.client()
		if err != nil {
			return err
		}
		if err := c.Do(ctx, "DELETE", "/webhooks/"+strconv.Itoa(id), nil, nil, nil); err != nil {
			return err
		}
		fmt.Fprintf(e.out, "webhook %d deleted\n", id)
		return nil
	}
	return usagef("usage: dartctl webhooks list|get|events|create|update|delete")
}
