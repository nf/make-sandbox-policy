package main

import (
	"bytes"
	"flag"
	"fmt"
	"log"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"slices"
	"strings"
)

var allowWrite = []string{
	".amp",
	".bun",
	".cache/amp",
	".cache/uv",
	".local/share/amp",
	".local/share/uv",
}

var allowRead = []string{
	"bin",
	".local/bin",
	".gitconfig",
}

func main() {
	log.SetPrefix("make-sandbox-policy: ")

	flag.Parse()
	root := flag.Arg(0)
	if root == "" {
		fmt.Fprintf(os.Stderr, "usage: make-sandbox-policy <root>\n")
		os.Exit(2)
	}

	profile, err := makeProfile(root)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Print(profile)
}

func makeProfile(root string) (string, error) {
	u, err := user.Current()
	if err != nil {
		return "", err
	}
	home := u.HomeDir

	abs, err := filepath.Abs(root)
	if err != nil {
		return "", err
	}
	root = abs

	tmp := filepath.Clean(os.Getenv("TMPDIR"))

	parents := append(
		parentPaths(home, allowRead...),
		parentPaths(home, allowWrite...)...)

	maybeParents := []string{
		root,
		goEnv("GOROOT"),
		goEnv("GOCACHE"),
		goEnv("GOMODCACHE"),
	}
	for _, p := range maybeParents {
		rel, err := filepath.Rel(home, p)
		if err != nil {
			return "", err
		}
		if !strings.HasPrefix(rel, "..") {
			parents = append(parents, parentPaths(home, rel)...)
		}
	}

	slices.Sort(parents)
	parents = slices.Compact(parents)

	wPaths := []string{
		tmp, filepath.Join("/private", tmp),
		root,
		goEnv("GOCACHE"),
		goEnv("GOMODCACHE"),
	}
	rPaths := []string{
		root,
		goEnv("GOROOT"),
		goEnv("GOCACHE"),
		goEnv("GOMODCACHE"),
	}
	for _, p := range allowRead {
		rPaths = append(rPaths, filepath.Join(home, p))
	}
	for _, p := range allowWrite {
		rPaths = append(rPaths, filepath.Join(home, p))
		wPaths = append(wPaths, filepath.Join(home, p))
	}

	var s strings.Builder

	w := func(format string, args ...any) {
		fmt.Fprintf(&s, format+"\n", args...)
	}

	w("(version 1)")
	w("(allow default)")
	w("(deny file-read* (subpath %q))", home)
	w("(allow file-read*")
	for _, p := range rPaths {
		w("\t(subpath %q)", p)
	}
	w("\t; For path traversal")
	w("\t(literal %q)", home)
	for _, p := range parents {
		w("\t(literal %q)", p)
	}
	w(")")

	w("(deny file-write*)")
	w("(allow file-write*")
	for _, p := range wPaths {
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

func parentPaths(base string, in ...string) (out []string) {
	for _, p := range in {
		p = filepath.Dir(p)
		for p != "." {
			out = append(out, filepath.Join(base, p))
			p = filepath.Dir(p)
		}
	}
	return
}

var goEnvs = make(map[string]string)

func goEnv(v string) string {
	if s, ok := goEnvs[v]; ok {
		return s
	}

	cmd := exec.Command("go", "env", v)
	cmd.Stderr = os.Stderr
	out, err := cmd.Output()
	if err != nil {
		log.Fatalf("go env %s failed: %v", v, err)
	}
	s := string(bytes.TrimSpace(out))

	goEnvs[v] = s
	return s
}
