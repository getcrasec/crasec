package sbomgen

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
)

// IsRemoteGitURL reports whether target looks like a remote git repository
// URL rather than a local filesystem path or container image reference.
func IsRemoteGitURL(target string) bool {
	return strings.HasPrefix(target, "https://") || strings.HasPrefix(target, "http://")
}

// CloneRepo shallow-clones repoURL into a fresh temp directory and returns
// its path. Callers must invoke the returned cleanup func once done with it.
func CloneRepo(ctx context.Context, repoURL string, statusWriter io.Writer) (dir string, cleanup func(), err error) {
	tmpDir, err := os.MkdirTemp("", "crasec-clone-*")
	if err != nil {
		return "", nil, fmt.Errorf("creating temp dir: %w", err)
	}

	cleanup = func() {
		if removeErr := os.RemoveAll(tmpDir); removeErr != nil {
			fmt.Fprintf(statusWriter, "warning: failed to remove temp dir %s: %v\n", tmpDir, removeErr) //nolint:errcheck // best-effort status output
		}
	}

	fmt.Fprintf(statusWriter, "cloning %s...\n", repoURL)                       //nolint:errcheck // best-effort status output
	c := exec.CommandContext(ctx, "git", "clone", "--depth=1", repoURL, tmpDir) // #nosec G204 -- repoURL is a user-supplied CLI argument, not attacker-controlled remote input
	c.Stderr = statusWriter
	if err := c.Run(); err != nil {
		cleanup()
		return "", nil, fmt.Errorf("git clone %s: %w", repoURL, err)
	}

	return tmpDir, cleanup, nil
}
