package main

import (
	"bufio"
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
)

// ---------------------------------------------------------------------------
// Tool lookup
// ---------------------------------------------------------------------------

type toolset struct{ binDir string }

func (t toolset) find(name string) (string, error) {
	if t.binDir != "" {
		p := filepath.Join(t.binDir, name)
		if runtime.GOOS == "windows" {
			p += ".exe"
		}
		if _, err := os.Stat(p); err != nil {
			return "", fmt.Errorf("%s not found in %s", name, t.binDir)
		}
		return p, nil
	}
	p, err := exec.LookPath(name)
	if err != nil {
		return "", fmt.Errorf("%s not found in PATH (install Wireshark/tshark or use --bin-dir)", name)
	}
	return p, nil
}

func logCmd(name string, args []string) {
	var b strings.Builder
	b.WriteString("$ " + filepath.Base(name))
	for _, a := range args {
		if len(a) > 160 {
			a = a[:160] + "...(truncated)"
		}
		if strings.ContainsAny(a, " \t\"'()|&<>") {
			a = "'" + a + "'"
		}
		b.WriteString(" " + a)
	}
	fmt.Fprintln(os.Stderr, b.String())
}

func runCmd(verbose bool, name string, args ...string) error {
	if verbose {
		logCmd(name, args)
	}
	cmd := exec.Command(name, args...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("%s failed: %v: %s", filepath.Base(name), err, tail(stderr.String(), 800))
	}
	return nil
}

func tail(s string, n int) string {
	s = strings.TrimSpace(s)
	if len(s) > n {
		return "..." + s[len(s)-n:]
	}
	return s
}

// ---------------------------------------------------------------------------
// Field catalog: `tshark -G fields` so that unknown field names (differences
// between Wireshark versions) are skipped instead of aborting tshark.
// ---------------------------------------------------------------------------

type catalog struct {
	all   bool
	names map[string]struct{}
}

func loadCatalog(tshark string) *catalog {
	c := &catalog{names: map[string]struct{}{}}
	out, err := exec.Command(tshark, "-G", "fields").Output()
	if err != nil {
		c.all = true // cannot verify; assume everything exists
		return c
	}
	sc := bufio.NewScanner(bytes.NewReader(out))
	sc.Buffer(make([]byte, 1<<20), 16<<20)
	for sc.Scan() {
		p := strings.Split(sc.Text(), "\t")
		if len(p) > 2 && (p[0] == "F" || p[0] == "P") {
			c.names[p[2]] = struct{}{}
		}
	}
	return c
}

func (c *catalog) Has(name string) bool {
	if c.all {
		return true
	}
	_, ok := c.names[name]
	return ok
}

// ---------------------------------------------------------------------------
// Field extraction
// ---------------------------------------------------------------------------

type row struct{ v map[string][]string }

func (r row) first(name string) string {
	if l := r.v[name]; len(l) > 0 {
		return l[0]
	}
	return ""
}

func (r row) all(name string) []string { return r.v[name] }

func splitVals(s string) []string {
	var out []string
	for _, p := range strings.Split(s, "|") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

type tsharkRunner struct {
	bin     string
	extra   []string
	twoPass bool
	verbose bool
}

func (t *tsharkRunner) baseArgs(file string) []string {
	args := []string{"-r", file, "-n"}
	if t.twoPass {
		args = append(args, "-2")
	}
	return append(args, t.extra...)
}

// fields runs tshark with -Y filter and streams each matching packet to fn.
func (t *tsharkRunner) fields(file, filter string, cols []string, fn func(row)) error {
	args := t.baseArgs(file)
	args = append(args, "-Y", filter, "-T", "fields",
		"-E", "separator=/t", "-E", "aggregator=|", "-E", "occurrence=a", "-E", "header=n")
	for _, c := range cols {
		args = append(args, "-e", c)
	}
	if t.verbose {
		logCmd(t.bin, args)
	}
	cmd := exec.Command(t.bin, args...)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		return err
	}
	n := 0
	sc := bufio.NewScanner(stdout)
	sc.Buffer(make([]byte, 1<<20), 64<<20)
	for sc.Scan() {
		parts := strings.Split(sc.Text(), "\t")
		r := row{v: make(map[string][]string, 8)}
		for i, c := range cols {
			if i < len(parts) && parts[i] != "" {
				r.v[c] = splitVals(parts[i])
			}
		}
		n++
		fn(r)
	}
	scErr := sc.Err()
	waitErr := cmd.Wait()
	if scErr != nil {
		return scErr
	}
	if waitErr != nil {
		if n == 0 {
			return fmt.Errorf("tshark failed: %v: %s", waitErr, tail(stderr.String(), 800))
		}
		fmt.Fprintf(os.Stderr, "warning: tshark exited with %v: %s\n", waitErr, tail(stderr.String(), 300))
	}
	return nil
}

// write saves packets matching filter to out (pcapng).
func (t *tsharkRunner) write(file, filter, out string) error {
	args := t.baseArgs(file)
	args = append(args, "-Y", filter, "-F", "pcapng", "-w", out)
	return runCmd(t.verbose, t.bin, args...)
}
