package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"os/exec"
	"os/user"
	"path"
	"path/filepath"
	"slices"
	"strings"
	"sync"
)

type Policy struct {
	Deny       []string
	AllowRead  []string
	AllowWrite []string
}

var defaultPolicy = Policy{
	Deny: []string{
		"$HOME",
	},
	AllowRead: []string{
		"$HOME/bin",
		"$HOME/.local/bin",
		"$HOME/.gitconfig",
		goEnv()["GOROOT"],
	},
	AllowWrite: []string{
		"$HOME/.amp",
		"$HOME/.bun",
		"$HOME/.cache/amp",
		"$HOME/.cache/uv",
		"$HOME/.local/share/amp",
		"$HOME/.local/share/uv",
		goEnv()["GOCACHE"],
		goEnv()["GOMODCACHE"],
		tmpDir,
		filepath.Join("/private", tmpDir),
	},
}

func main() {
	log.SetPrefix("make-sandbox-policy: ")
	flag.Parse()

	p := defaultPolicy
	p.AllowWrite = append(p.AllowWrite, flag.Args()...)

	profile, err := p.Profile()
	if err != nil {
		log.Fatal(err)
	}
	fmt.Print(profile)
}

func (p *Policy) Profile() (string, error) {
	u, err := user.Current()
	if err != nil {
		return "", err
	}

	deny := cleanPaths(p.Deny, u.HomeDir)
	read := cleanPaths(p.AllowRead, u.HomeDir)
	write := cleanPaths(p.AllowWrite, u.HomeDir)

	// Find any allowed paths that are inside deny paths
	// so that we can add their intermediate parent directories
	// to permit path traversal.
	var parents []string
	for _, d := range deny {
		prefix := d
		if prefix != "/" {
			prefix += "/"
		}
		match := false
		for _, p := range slices.Concat(read, write) {
			if tail, ok := strings.CutPrefix(p, prefix); ok {
				parents = append(parents, parentPaths(prefix, tail)...)
				match = true
			}
		}
		if match {
			parents = append(parents, d)
		}
	}
	parents = dedup(parents)

	deny = dedup(deny)
	// Allow reads to subpaths that allow writes.
	read = dedup(append(read, write...))
	write = dedup(write)

	// Generate the profile.
	var s strings.Builder
	w := func(format string, args ...any) {
		fmt.Fprintf(&s, format+"\n", args...)
	}

	w("(version 1)")
	w("(allow default)")

	w("(deny file-read*")
	for _, p := range deny {
		w("\t(subpath %q)", p)
	}
	w(")")

	w("(allow file-read*")
	for _, p := range read {
		w("\t(subpath %q)", p)
	}
	w("\t; Add parent paths for traversal")
	for _, p := range parents {
		w("\t(literal %q)", p)
	}
	w(")")

	w("(deny file-write*)")
	w("(allow file-write*")
	for _, p := range write {
		w("\t(subpath %q)", p)
	}
	w("\t(literal \"/dev/null\")")
	w("\t(literal \"/dev/ptmx\")")
	w("\t(literal \"/dev/stderr\")")
	w("\t(literal \"/dev/stdout\")")
	w("\t(regex #\"^/dev/ttys[0-9]*$\")")
	w(")")

	return s.String(), nil
}

func cleanPaths(in []string, home string) (out []string) {
	for _, p := range in {
		p = strings.Replace(p, "$HOME", home, -1)
		p = path.Clean(p)
		out = append(out, p)
	}
	return
}

func parentPaths(base string, p string) (out []string) {
	p = filepath.Dir(p)
	for p != "." {
		out = append(out, filepath.Join(base, p))
		p = filepath.Dir(p)
	}
	return
}

func dedup(s []string) []string {
	slices.Sort(s)
	return slices.Compact(s)
}

var tmpDir = filepath.Clean(os.Getenv("TMPDIR"))

var goEnv = sync.OnceValue(func() (m map[string]string) {
	cmd := exec.Command("go", "env", "-json")
	cmd.Stderr = os.Stderr
	out, err := cmd.Output()
	if err != nil {
		log.Fatalf("go env failed: %v", err)
	}
	if err := json.Unmarshal(out, &m); err != nil {
		log.Fatalf("decoding go env output: %v", err)
	}
	return
})
