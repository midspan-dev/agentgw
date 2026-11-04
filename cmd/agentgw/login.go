package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"runtime"
	"strings"

	"github.com/midspan-dev/agentgw/internal/oauth"
	"github.com/midspan-dev/agentgw/pkg/contracts"
)

func init() {
	commands["login"] = loginCmd
	extraUsage = append(extraUsage, "  agentgw login     [--config f] [--no-browser] <server>")
}

// readSecret returns the client secret from secret_env or secret_file, "" when
// neither is set. Errors name the variable or path, never the value.
func readSecret(a contracts.UpstreamAuth) (string, error) {
	switch {
	case a.SecretEnv != "":
		v := os.Getenv(a.SecretEnv)
		if v == "" {
			return "", fmt.Errorf("secret_env $%s is empty or unset", a.SecretEnv)
		}
		return v, nil
	case a.SecretFile != "":
		b, err := os.ReadFile(a.SecretFile)
		if err != nil {
			return "", fmt.Errorf("secret_file %s: %w", a.SecretFile, err)
		}
		v := strings.TrimSuffix(string(b), "\n")
		if v == "" {
			return "", fmt.Errorf("secret_file %s is empty", a.SecretFile)
		}
		return v, nil
	}
	return "", nil
}

func openBrowser(url string) error {
	if runtime.GOOS == "darwin" {
		return exec.Command("open", url).Start()
	}
	return exec.Command("xdg-open", url).Start()
}

func loginCmd(ctx context.Context, args []string, out io.Writer) error {
	fs, cfgPath := flags("login")
	noBrowser := fs.Bool("no-browser", false, "print the URL, do not open a browser")
	if err := fs.Parse(args); err != nil {
		return err
	}
	pos := fs.Args()
	if len(pos) > 1 { // `login docs --no-browser`: parse the flags after the server too
		first := pos[0]
		if err := fs.Parse(pos[1:]); err != nil {
			return err
		}
		pos = append([]string{first}, fs.Args()...)
	}
	if len(pos) != 1 {
		return errUsage
	}
	name := pos[0]
	cfg, err := loadConfig(*cfgPath)
	if err != nil {
		return err
	}
	for _, u := range cfg.Upstreams {
		if u.Name != name {
			continue
		}
		if u.Auth == nil || u.Auth.Kind != contracts.AuthKindAuthorizationCode {
			return fmt.Errorf("login: upstream %s has no authorization_code auth", name)
		}
		secret, err := readSecret(*u.Auth)
		if err != nil {
			return fmt.Errorf("login: %w", err)
		}
		o := oauth.LoginOptions{Upstream: name, URL: u.URL, Auth: *u.Auth, Secret: secret,
			Store: &oauth.Store{Path: u.Auth.TokenFile}, Out: out}
		if !*noBrowser {
			o.Open = openBrowser
		}
		if err := oauth.Login(ctx, o); err != nil {
			return fmt.Errorf("login: %w", err)
		}
		fmt.Fprintf(out, "logged in to %s; tokens in %s\n", name, u.Auth.TokenFile)
		return nil
	}
	return errors.New("login: no upstream " + name)
}
