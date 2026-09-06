// antinat-agent is the composed Agent process (P10 Story 5).
//
// Flags and environment (all optional; the walking skeleton and real
// deployments set them explicitly):
//
//	-state      ANTINAT_STATE      agent localstate dir (default ./var/agent)
//	-endpoint   ANTINAT_ENDPOINT   controller base URL (required)
//	-node       ANTINAT_NODE       node id (required)
//	-token-file ANTINAT_TOKEN      one-time enrollment token file (0600; omit when already enrolled)
//	-pin        ANTINAT_PIN        pinned controller public key hex (required for enrollment)
//
// SIGINT/SIGTERM trigger an ordered graceful shutdown (control client,
// data plane, store).
package main

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/gxbrave/AntiNAT-Agent/internal/agent"
	"github.com/gxbrave/AntiNAT-Agent/internal/buildinfo"
	"github.com/gxbrave/AntiNAT-Agent/internal/protocol"
)

func main() {
	if len(os.Args) > 1 && os.Args[1] == "version" {
		fmt.Printf("antinat-agent %s\n", buildinfo.Format(buildinfo.Current()))
		return
	}
	stateDir := flag.String("state", envOr("ANTINAT_STATE", filepath.Join("var", "agent")), "agent state dir")
	endpoint := flag.String("endpoint", envOr("ANTINAT_ENDPOINT", ""), "controller base URL")
	nodeID := flag.String("node", envOr("ANTINAT_NODE", ""), "node id")
	tokenFile := flag.String("token-file", envOr("ANTINAT_TOKEN_FILE", ""), "one-time enrollment token file (0600)")
	tokenFD := flag.Int("token-fd", -1, "protected one-time enrollment token file descriptor")
	pinHex := flag.String("pin", envOr("ANTINAT_PIN", ""), "pinned controller public key (hex)")
	stunServers := flag.String("stun-servers", envOr("ANTINAT_STUN_SERVERS", ""), "comma-separated stun+tcp:// endpoints for the stun-only strategy and gateway same-tuple observation")
	autoOrder := flag.String("auto-order", envOr("ANTINAT_AUTO_ORDER", ""), "comma-separated concrete auto strategy order (explicit-gateway,direct-v4,stun-only; manual-static and literal auto are rejected)")
	flag.Parse()

	if *endpoint == "" || *nodeID == "" {
		fmt.Fprintln(os.Stderr, "antinat-agent: --endpoint and --node are required")
		os.Exit(2)
	}
	cfg := agent.Config{
		StateDir:  *stateDir,
		Endpoint:  *endpoint,
		NodeID:    *nodeID,
		Heartbeat: 30 * time.Second,
	}
	cfg.StunServers = splitCommaList(*stunServers)
	if order, err := parseStrategyOrder(*autoOrder); err != nil {
		fmt.Fprintf(os.Stderr, "antinat-agent: %v\n", err)
		os.Exit(2)
	} else if len(order) > 0 {
		cfg.AutoOrder = order
	}
	var tokenInputValue *tokenInput
	if *tokenFile != "" || *tokenFD >= 0 {
		input, err := openTokenInput(*tokenFD, *tokenFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "antinat-agent: token input rejected: %v\n", err)
			os.Exit(1)
		}
		tokenInputValue = input
		defer input.close()
		cfg.Token = input.token
		if *pinHex != "" {
			pin, err := hex.DecodeString(*pinHex)
			if err != nil || len(pin) != ed25519.PublicKeySize {
				fmt.Fprintln(os.Stderr, "antinat-agent: --pin must be a 32-byte hex ed25519 public key")
				os.Exit(2)
			}
			cfg.ControllerPublicKey = ed25519.PublicKey(pin)
		}
	}

	app, enrollmentErr := agent.New(cfg)
	tokenErr := finalizeEnrollmentToken(tokenInputValue, enrollmentErr)
	if enrollmentErr != nil {
		fmt.Fprintf(os.Stderr, "antinat-agent: %v\n", enrollmentErr)
		os.Exit(1)
	}
	if tokenErr != nil {
		fmt.Fprintf(os.Stderr, "antinat-agent: token cleanup failed: %v\n", tokenErr)
		if app != nil {
			_ = app.Shutdown(context.Background())
		}
		os.Exit(1)
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	if err := app.Start(ctx); err != nil {
		fmt.Fprintf(os.Stderr, "antinat-agent: %v\n", err)
		os.Exit(1)
	}
	fmt.Fprintf(os.Stderr, "antinat-agent: control session established for node %s\n", *nodeID)
	if report := app.LastRecoveryReport(); len(report.Quarantined) > 0 ||
		len(report.Journal.Superseded) > 0 || len(report.Journal.Orphaned) > 0 {
		// Repair R1 findings 3/4: surface the startup recovery diagnostic. The
		// applied LKG rows remain durable; the detection job refreshes the
		// profile and a later recovery pass reopens the deferred forwards.
		fmt.Fprintf(os.Stderr, "antinat-agent: startup recovery deferred %d forward(s) pending a fresh detection profile\n", len(report.Quarantined))
		for _, q := range report.Quarantined {
			fmt.Fprintf(os.Stderr, "antinat-agent:   %s: %v\n", q.ForwardID, q.Err)
		}
		fmt.Fprintf(os.Stderr, "antinat-agent: journal replay left %d superseded and %d orphaned record(s)\n",
			len(report.Journal.Superseded), len(report.Journal.Orphaned))
	}

	<-ctx.Done()
	shutCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := app.Shutdown(shutCtx); err != nil {
		fmt.Fprintf(os.Stderr, "antinat-agent: shutdown: %v\n", err)
		os.Exit(1)
	}
}

// finalizeEnrollmentToken couples path cleanup to the enrollment transaction:
// a failed agent.New leaves the original file available for retry, while a
// successful enrollment consumes it before any later session-start failure.
func finalizeEnrollmentToken(input *tokenInput, enrollmentErr error) error {
	if input == nil {
		return enrollmentErr
	}
	if enrollmentErr != nil {
		_ = input.abort()
		return enrollmentErr
	}
	return input.commit()
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

// splitCommaList splits a comma-separated flag value, trimming spaces and
// dropping empty entries.
func splitCommaList(value string) []string {
	if value == "" {
		return nil
	}
	var out []string
	for _, part := range strings.Split(value, ",") {
		if trimmed := strings.TrimSpace(part); trimmed != "" {
			out = append(out, trimmed)
		}
	}
	return out
}

// parseStrategyOrder parses the operator auto-order flag, rejecting unknown
// strategy names, manual-static (never auto-detected) and the literal auto
// (a profile-resolved default, not a concrete probeable order entry; an
// accepted "auto" would silently yield a no-default detection profile).
// An empty value with no error means "leave the production default".
func parseStrategyOrder(value string) ([]protocol.Strategy, error) {
	if value == "" {
		return nil, nil
	}
	var out []protocol.Strategy
	for _, part := range splitCommaList(value) {
		strategy, err := protocol.ParseStrategy(part)
		if err != nil {
			return nil, fmt.Errorf("antinat-agent: --auto-order strategy %q: %w", part, err)
		}
		if strategy == protocol.StrategyManualStaticV4 {
			return nil, fmt.Errorf("antinat-agent: --auto-order must not contain manual-static-v4 (operator-configured only)")
		}
		if strategy == protocol.StrategyAuto {
			return nil, fmt.Errorf("antinat-agent: --auto-order must not contain auto (a profile-resolved default, not a concrete probeable strategy)")
		}
		out = append(out, strategy)
	}
	return out, nil
}
