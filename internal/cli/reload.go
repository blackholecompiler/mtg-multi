package cli

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/mhsanaei/mtg-multi/mtglib"
)

// reloadHostCheckTimeout bounds the DNS lookup of one new hostname after a
// reload.
const reloadHostCheckTimeout = 5 * time.Second

// secretsReloader is the part of *mtglib.Proxy used by the SIGHUP handler. It
// is an interface so that tests do not need a running proxy.
type secretsReloader interface {
	ReloadSecrets() error
	SnapshotSecrets() []mtglib.SecretInfo
}

// hostResolver is the part of *net.Resolver used to check new hostnames. It
// is an interface so that tests do not need a network.
type hostResolver interface {
	LookupIPAddr(ctx context.Context, host string) ([]net.IPAddr, error)
}

// watchReload re-reads the secrets on every signal until ctx is done. It is
// the SIGHUP counterpart of POST /reload: the config file is parsed again and
// its secrets, ad-tags and limits replace the running set (other options are
// not reloaded). On any error the current secrets are kept. Hostnames that
// appear only after the reload are checked with DNS, and a warning is logged
// for each one that does not resolve; the check runs after the swap, so it
// never delays or blocks the new secrets.
func watchReload(
	ctx context.Context,
	signals <-chan os.Signal,
	proxy secretsReloader,
	resolver hostResolver,
	logger mtglib.Logger,
) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-signals:
			before := proxy.SnapshotSecrets()

			if err := proxy.ReloadSecrets(); err != nil {
				if errors.Is(err, mtglib.ErrReloaderNotConfigured) {
					logger.Warning("reload: not supported without a config file, signal ignored")
				} else {
					logger.WarningError("reload: cannot apply secrets, keeping current secrets", err)
				}

				continue
			}

			after := proxy.SnapshotSecrets()

			// Warning, not Info: by default mtg logs warnings only, and an
			// operator needs to see the result of every reload.
			logger.BindInt("secrets", len(after)).Warning("reload: secrets have been updated")

			warnUnresolvedHosts(ctx, resolver, before, after, logger)
		}
	}
}

// warnUnresolvedHosts resolves the hostnames that appear in current but not
// in previous and logs a warning for each one that does not resolve. This is
// the part of the startup SNI-DNS check that catches a typo: a hostname that
// does not resolve is applied anyway (the reload is not blocked), but domain
// fronting to it fails and the SNI does not match any real site. Hostnames
// that were already in use are not checked again.
func warnUnresolvedHosts(
	ctx context.Context,
	resolver hostResolver,
	previous, current []mtglib.SecretInfo,
	logger mtglib.Logger,
) {
	known := make(map[string]struct{}, len(previous))
	for _, info := range previous {
		known[info.Host] = struct{}{}
	}

	usersByHost := map[string][]string{}

	for _, info := range current {
		if _, ok := known[info.Host]; ok || info.Host == "" {
			continue
		}

		usersByHost[info.Host] = append(usersByHost[info.Host], info.Name)
	}

	hosts := make([]string, 0, len(usersByHost))
	for host := range usersByHost {
		hosts = append(hosts, host)
	}

	sort.Strings(hosts)

	for _, host := range hosts {
		users := usersByHost[host]
		sort.Strings(users)

		lookupCtx, cancel := context.WithTimeout(ctx, reloadHostCheckTimeout)
		addrs, err := resolver.LookupIPAddr(lookupCtx, host)

		cancel()

		if err == nil && len(addrs) == 0 {
			err = fmt.Errorf("no known addresses for %s", host)
		}

		if err != nil {
			logger.
				BindStr("hostname", host).
				BindStr("users", strings.Join(users, ",")).
				WarningError("reload: secret hostname does not resolve", err)
		}
	}
}
