package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"text/tabwriter"

	"marmot/internal/api"
	"marmot/internal/config"
	"marmot/internal/store"
)

const adminUsage = `usage: marmot admin <subcommand> [flags]

subcommands:
  create      -username NAME [-role owner|operator|viewer]   add an administrator
  passwd      -username NAME                                  set a new password
  list                                                        list administrators
  reset-totp  -username NAME                                  turn off two-factor login

All take -config FILE (for api.data_dir). The password is read from the
MARMOT_ADMIN_PASSWORD environment variable, or else from the first line of
standard input.
`

// cmdAdmin manages panel administrators directly in the database. It works
// while the node runs (SQLite allows it) and is the way back in when every
// owner is locked out.
func cmdAdmin(args []string, in io.Reader, out io.Writer) error {
	if len(args) == 0 {
		return usageError(adminUsage)
	}
	sub := args[0]
	fs := flag.NewFlagSet("admin "+sub, flag.ContinueOnError)
	cfgPath := fs.String("config", "/etc/marmot/marmot.toml", "configuration file")
	username := fs.String("username", "", "administrator username")
	role := fs.String("role", "owner", "owner, operator or viewer")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	loaded, err := config.LoadFile(*cfgPath)
	if err != nil {
		return err
	}
	ctx := context.Background()
	st, err := store.Open(ctx, loaded.Config.API.DataDir)
	if err != nil {
		return err
	}
	defer func() { _ = st.Close() }()

	needUser := func() (*store.Admin, error) {
		if *username == "" {
			return nil, errors.New("-username is required")
		}
		a, err := st.AdminByUsername(ctx, *username)
		if errors.Is(err, store.ErrNotFound) {
			return nil, fmt.Errorf("no administrator %q", *username)
		}
		return a, err
	}

	switch sub {
	case "create":
		if *username == "" {
			return errors.New("-username is required")
		}
		r := store.Role(*role)
		if !r.Valid() {
			return fmt.Errorf("invalid role %q", *role)
		}
		hash, err := readPassword(in)
		if err != nil {
			return err
		}
		a := &store.Admin{Username: *username, PasswordHash: hash, Role: r}
		if err := st.CreateAdmin(ctx, a); errors.Is(err, store.ErrDuplicate) {
			return fmt.Errorf("administrator %q already exists", *username)
		} else if err != nil {
			return err
		}
		_ = st.AddAudit(ctx, store.AuditEntry{Admin: "cli", Action: "admin.create", Target: a.Username + " (" + string(r) + ")"})
		fmt.Fprintf(out, "created %s (%s)\n", a.Username, r)
	case "passwd":
		a, err := needUser()
		if err != nil {
			return err
		}
		hash, err := readPassword(in)
		if err != nil {
			return err
		}
		if err := st.SetPassword(ctx, a.ID, hash); err != nil {
			return err
		}
		_ = st.AddAudit(ctx, store.AuditEntry{Admin: "cli", Action: "admin.passwd", Target: a.Username})
		fmt.Fprintf(out, "password changed for %s; their sessions were ended\n", a.Username)
	case "reset-totp":
		a, err := needUser()
		if err != nil {
			return err
		}
		if err := st.DisableTOTP(ctx, a.ID); err != nil {
			return err
		}
		_ = st.AddAudit(ctx, store.AuditEntry{Admin: "cli", Action: "totp.disable", Target: a.Username})
		fmt.Fprintf(out, "two-factor login turned off for %s\n", a.Username)
	case "list":
		list, err := st.ListAdmins(ctx)
		if err != nil {
			return err
		}
		tw := tabwriter.NewWriter(out, 0, 4, 2, ' ', 0)
		fmt.Fprintln(tw, "USERNAME\tROLE\tTOTP\tLAST LOGIN")
		for _, a := range list {
			last := "never"
			if !a.LastLoginAt.IsZero() {
				last = a.LastLoginAt.Format("2006-01-02 15:04")
			}
			fmt.Fprintf(tw, "%s\t%s\t%v\t%s\n", a.Username, a.Role, a.TOTPEnabled(), last)
		}
		return tw.Flush()
	default:
		return fmt.Errorf("unknown admin subcommand %q\n%s", sub, adminUsage)
	}
	return nil
}

// readPassword takes the password from MARMOT_ADMIN_PASSWORD or the first
// line of in, checks its length and returns its hash.
func readPassword(in io.Reader) (string, error) {
	pw := os.Getenv("MARMOT_ADMIN_PASSWORD")
	if pw == "" {
		line, err := bufio.NewReader(in).ReadString('\n')
		if err != nil && !errors.Is(err, io.EOF) {
			return "", err
		}
		pw = strings.TrimRight(line, "\r\n")
	}
	if len(pw) < api.MinPasswordLen {
		return "", fmt.Errorf("password must be at least %d characters", api.MinPasswordLen)
	}
	return api.HashPassword(pw)
}
