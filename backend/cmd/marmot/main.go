// Command marmot runs a Marmot node and provides key and config tooling.
package main

import (
	"flag"
	"fmt"
	"io"
	"os"

	"marmot/internal/config"
	"marmot/internal/crypto"

	_ "marmot/internal/transport/grpc"
	_ "marmot/internal/transport/quic"
	_ "marmot/internal/transport/tcp"
	_ "marmot/internal/transport/tls"
	_ "marmot/internal/transport/udp"
	_ "marmot/internal/transport/ws"
)

// version is set at build time with -ldflags "-X main.version=...".
var version = "dev"

const usage = `usage: marmot <command> [flags]

commands:
  run     -config FILE      run the node
  check   -config FILE      validate a configuration and exit
  keygen  -out FILE         create an identity key and print its public key
  pubkey  -key FILE         print the public key of an identity key
  admin   SUBCOMMAND        manage panel administrators (create, passwd, list, reset-totp)
  health  -config FILE      exit 0 if the running node is ready (container health check)
  version                   print the version
`

func main() {
	if err := dispatch(os.Args[1:], os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "marmot:", err)
		os.Exit(1)
	}
}

// usageError is the help text, returned when the command line is wrong.
type usageError string

func (u usageError) Error() string { return string(u) }

func dispatch(args []string, out io.Writer) error {
	if len(args) == 0 {
		return usageError(usage)
	}
	cmd, rest := args[0], args[1:]
	switch cmd {
	case "run":
		return cmdRun(rest)
	case "check":
		return cmdCheck(rest, out)
	case "keygen":
		return cmdKeygen(rest, out)
	case "pubkey":
		return cmdPubkey(rest, out)
	case "admin":
		return cmdAdmin(rest, os.Stdin, out)
	case "health":
		return cmdHealth(rest, out)
	case "version":
		fmt.Fprintln(out, version)
		return nil
	default:
		return fmt.Errorf("unknown command %q\n%s", cmd, usage)
	}
}

func configFlag(name string, args []string) (string, error) {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	path := fs.String("config", "/etc/marmot/marmot.toml", "configuration file")
	if err := fs.Parse(args); err != nil {
		return "", err
	}
	return *path, nil
}

func cmdCheck(args []string, out io.Writer) error {
	path, err := configFlag("check", args)
	if err != nil {
		return err
	}
	l, err := config.LoadFile(path)
	if err != nil {
		return err
	}
	for _, w := range l.Warnings {
		fmt.Fprintln(out, "warning:", w)
	}
	fmt.Fprintf(out, "%s: ok (version %s)\n", path, l.Version)
	return nil
}

func cmdKeygen(args []string, out io.Writer) error {
	fs := flag.NewFlagSet("keygen", flag.ContinueOnError)
	path := fs.String("out", "/etc/marmot/identity.key", "where to write the identity key")
	if err := fs.Parse(args); err != nil {
		return err
	}
	id, err := crypto.GenerateIdentity()
	if err != nil {
		return err
	}
	if err := id.SaveIdentity(*path); err != nil {
		return err
	}
	fmt.Fprintln(out, config.FormatPublicKey(id.PublicKey()))
	return nil
}

func cmdPubkey(args []string, out io.Writer) error {
	fs := flag.NewFlagSet("pubkey", flag.ContinueOnError)
	path := fs.String("key", "/etc/marmot/identity.key", "identity key file")
	if err := fs.Parse(args); err != nil {
		return err
	}
	id, err := crypto.LoadIdentity(*path)
	if err != nil {
		return err
	}
	fmt.Fprintln(out, config.FormatPublicKey(id.PublicKey()))
	return nil
}
