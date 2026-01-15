package main

import (
	"flag"
	"fmt"
	"log"
	"os"
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

func makeProfile(home, root string) (string, error) {
	tmp := filepath.Clean(os.Getenv("TMPDIR"))

	parents := append(
		parentPaths(home, allowRead...),
		parentPaths(home, allowWrite...)...)

	relRoot, err := filepath.Rel(home, root)
	if err != nil {
		return "", err
	}
	if !strings.HasPrefix(relRoot, "..") {
		parents = append(parents, parentPaths(home, relRoot)...)
	}
	slices.Sort(parents)
	parents = slices.Compact(parents)

	var s strings.Builder

	w := func(format string, args ...any) {
		fmt.Fprintf(&s, format+"\n", args...)
	}

	w("(version 1)")
	w("(allow default)")
	w("(deny file-read* (subpath %q))", home)
	w("(allow file-read*")
	w("	(subpath %q)", root)
	for _, p := range allowRead {
		w("	(subpath %q)", filepath.Join(home, p))
	}
	for _, p := range allowWrite {
		w("	(subpath %q)", filepath.Join(home, p))
	}
	w("	(literal %q)", home)
	for _, p := range parents {
		w("	(literal %q)", p)
	}
	w(")")

	w("(deny file-write*)")
	w("(allow file-write*")
	w("	(subpath %q)", root)
	w("	(subpath %q)", tmp)
	w("	(subpath %q)", filepath.Join("/private", tmp))
	w("	(literal \"/dev/stdout\")")
	w("	(literal \"/dev/stderr\")")
	w("	(literal \"/dev/null\")")
	w("	(literal \"/dev/ptmx\")")
	w("	(regex #\"^/dev/ttys[0-9]*$\")")
	for _, p := range allowWrite {
		w("	(subpath %q)", filepath.Join(home, p))
	}
	w(")")

	return s.String(), nil
}

func do(dir string) error {
	u, err := user.Current()
	if err != nil {
		return err
	}
	profile, err := makeProfile(u.HomeDir, dir)
	if err != nil {
		return err
	}
	fmt.Println(profile)
	return nil
}

func main() {
	flag.Parse()
	if err := do(flag.Arg(0)); err != nil {
		log.Fatal(err)
	}
}
