package main

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"
)

const defaultMergedName = "merge_reorder.pcapng"

type options struct {
	imsi, msisdn  string
	dir, file     string
	out, merged   string
	binDir        string
	reuseMerged   bool
	noUserPlane   bool
	noUEIP        bool
	teidOnly      bool
	singlePass    bool
	showFilter    bool
	verbose       bool
	maxRounds     int
	resolveWindow float64
	extra         []string
}

func newUsertrackCmd() *cobra.Command {
	o := &options{}
	cmd := &cobra.Command{
		Use:   "usertrack",
		Short: "Extract all packets of one subscriber (IMSI / MSISDN) from a capture",
		Long: `Extract all packets of one subscriber from a capture using tshark.

Seeds (IMSI / MSISDN) are searched first; the keys found in the matched packets
(S1AP/NGAP UE IDs, GTPv2 F-TEID, Diameter Session-Id, PFCP F-SEID, SIP Call-ID,
UE IP, ...) are then used to expand the filter until no new keys appear.

With --dir, all *.pcap / *.pcapng files are merged (mergecap) and reordered
(reordercap) into <dir>/merge_reorder.pcapng before analysis.`,
		Example: `  gshark usertrack --imsi 440101234567890 --dir ./captures
  gshark usertrack --msisdn 819012345678 --file trace.pcapng -o user.pcapng
  gshark usertrack -i 440101234567890 -f trace.pcapng --no-userplane --show-filter`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := o.validate(); err != nil {
				return err
			}
			cmd.SilenceUsage = true // do not print usage for runtime errors
			if code := runUsertrack(o); code != 0 {
				os.Exit(code)
			}
			return nil
		},
	}
	f := cmd.Flags()
	f.StringVarP(&o.imsi, "imsi", "i", "", "IMSI (14-15 digits, e.g. 440101234567890)")
	f.StringVarP(&o.msisdn, "msisdn", "m", "", "MSISDN in international format without '+' (e.g. 819012345678)")
	f.StringVarP(&o.dir, "dir", "d", "", "directory containing *.pcap / *.pcapng (merged and reordered)")
	f.StringVarP(&o.file, "file", "f", "", "single capture file")
	f.StringVarP(&o.out, "out", "o", "", "output pcapng (default ./gshark_<imsi|msisdn>.pcapng)")
	f.StringVar(&o.merged, "merged", "", "path of the merged file in --dir mode (default <dir>/merge_reorder.pcapng)")
	f.BoolVar(&o.reuseMerged, "reuse-merged", false, "reuse an existing merged file instead of re-merging")
	f.StringVar(&o.binDir, "bin-dir", "", "directory containing tshark / mergecap / reordercap")
	f.BoolVar(&o.noUserPlane, "no-userplane", false, "do not extract GTP-U / UE-IP user-plane packets (IMS SIP on UE IP is still extracted)")
	f.BoolVar(&o.noUEIP, "no-ue-ip", false, "do not match packets by UE IP at the IP layer")
	f.BoolVar(&o.teidOnly, "teid-only", false, "match TEIDs without qualifying by tunnel endpoint IP")
	f.IntVar(&o.maxRounds, "max-rounds", 8, "maximum key-expansion rounds")
	f.Float64Var(&o.resolveWindow, "resolve-window", 5, "seconds allowed to resolve MME/AMF-UE ID after an Initial UE Message")
	f.StringArrayVar(&o.extra, "tshark-arg", nil, "extra argument passed to tshark (repeatable), e.g. --tshark-arg -o --tshark-arg nas-eps.null_decipher:TRUE")
	f.BoolVar(&o.singlePass, "single-pass", false, "do not use tshark -2 (faster, less accurate)")
	f.BoolVar(&o.showFilter, "show-filter", false, "print the complete display filter")
	f.BoolVarP(&o.verbose, "verbose", "v", false, "print executed commands")

	cmd.MarkFlagsOneRequired("imsi", "msisdn")
	cmd.MarkFlagsOneRequired("dir", "file")
	cmd.MarkFlagsMutuallyExclusive("dir", "file")
	return cmd
}

func (o *options) validate() error {
	digits := regexp.MustCompile(`^[0-9]+$`)
	o.msisdn = strings.NewReplacer("+", "", " ", "", "-", "").Replace(o.msisdn)
	if o.imsi != "" && (!digits.MatchString(o.imsi) || len(o.imsi) < 14 || len(o.imsi) > 15) {
		return fmt.Errorf("IMSI must be 14-15 digits: %q", o.imsi)
	}
	if o.msisdn != "" && (!digits.MatchString(o.msisdn) || len(o.msisdn) < 5 || len(o.msisdn) > 15) {
		return fmt.Errorf("MSISDN must be 5-15 digits (international format, no '+'): %q", o.msisdn)
	}
	if o.maxRounds < 1 {
		o.maxRounds = 1
	}
	if o.out == "" {
		id := o.imsi
		if id == "" {
			id = o.msisdn
		}
		o.out = "gshark_" + id + ".pcapng"
	}
	return nil
}

// prepareInput returns the capture file to analyse. In --dir mode all
// pcap/pcapng files are merged with mergecap and reordered with reordercap.
func prepareInput(o *options, tools toolset) (string, int, error) {
	if o.file != "" {
		st, err := os.Stat(o.file)
		if err != nil || st.IsDir() {
			return "", 0, fmt.Errorf("cannot read file: %s", o.file)
		}
		return o.file, 1, nil
	}
	entries, err := os.ReadDir(o.dir)
	if err != nil {
		return "", 0, err
	}
	merged := o.merged
	if merged == "" {
		merged = filepath.Join(o.dir, defaultMergedName)
	}
	skip := map[string]bool{defaultMergedName: true, filepath.Base(merged): true}
	var files []string
	for _, e := range entries {
		name := e.Name()
		l := strings.ToLower(name)
		if e.IsDir() || skip[name] || strings.HasPrefix(name, "gshark_") || strings.HasPrefix(name, ".gshark") {
			continue
		}
		if strings.HasSuffix(l, ".pcap") || strings.HasSuffix(l, ".pcapng") {
			files = append(files, filepath.Join(o.dir, name))
		}
	}
	sort.Strings(files)
	if len(files) == 0 {
		return "", 0, fmt.Errorf("no .pcap/.pcapng files in %s", o.dir)
	}
	if _, err := os.Stat(merged); err == nil && o.reuseMerged {
		fmt.Fprintf(os.Stderr, "reusing %s\n", merged)
		return merged, len(files), nil
	}

	mergecap, err := tools.find("mergecap")
	if err != nil {
		return "", 0, err
	}
	tmp := filepath.Join(filepath.Dir(merged), ".gshark_merge_tmp.pcapng")
	defer os.Remove(tmp)
	fmt.Fprintf(os.Stderr, "merging %d file(s) with mergecap...\n", len(files))
	args := append([]string{"-F", "pcapng", "-w", tmp}, files...)
	if err := runCmd(o.verbose, mergecap, args...); err != nil {
		return "", 0, err
	}
	if reorder, err := tools.find("reordercap"); err == nil {
		fmt.Fprintln(os.Stderr, "reordering with reordercap...")
		if err := runCmd(o.verbose, reorder, tmp, merged); err != nil {
			return "", 0, err
		}
	} else {
		fmt.Fprintln(os.Stderr, "warning: reordercap not found; using mergecap's chronological merge only")
		if err := os.Rename(tmp, merged); err != nil {
			return "", 0, err
		}
	}
	return merged, len(files), nil
}

type roundStats struct {
	count      int
	tmin, tmax float64
	protos     map[string]int
}

var interestingProtos = []string{"s1ap", "nas-eps", "ngap", "nas-5gs", "gtpv2", "gtp", "pfcp",
	"diameter", "sip", "rtp", "rtcp", "dns", "http2"}

func runUsertrack(o *options) int {
	tools := toolset{binDir: o.binDir}
	tsharkBin, err := tools.find("tshark")
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 1
	}
	input, nFiles, err := prepareInput(o, tools)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 1
	}

	cat := loadCatalog(tsharkBin)
	var cols []string
	for _, c := range keyColumns {
		if cat.Has(c) {
			cols = append(cols, c)
		} else if o.verbose {
			fmt.Fprintf(os.Stderr, "note: field %s not supported by this tshark; skipped\n", c)
		}
	}
	tr := &tsharkRunner{bin: tsharkBin, extra: o.extra, twoPass: !o.singlePass, verbose: o.verbose}
	keys := newKeys(o.imsi, o.msisdn, o.resolveWindow)

	var st roundStats
	var filter string
	converged := false
	rounds := 0
	collect := func(r row) {
		st.count++
		if t := parseFloat(r.first("frame.time_epoch")); t > 0 {
			if st.tmin == 0 || t < st.tmin {
				st.tmin = t
			}
			if t > st.tmax {
				st.tmax = t
			}
		}
		seen := map[string]bool{}
		for _, p := range strings.Split(r.first("frame.protocols"), ":") {
			seen[p] = true
		}
		for _, p := range interestingProtos {
			if seen[p] {
				st.protos[p]++
			}
		}
	}
	newStats := func() { st = roundStats{protos: map[string]int{}} }

	for rounds = 1; rounds <= o.maxRounds; rounds++ {
		filter = keys.buildFilter(cat, o)
		if filter == "" {
			fmt.Fprintln(os.Stderr, "error: could not build a filter (required protocol fields missing in this tshark)")
			return 1
		}
		newStats()
		changed := false
		err := tr.fields(input, filter, cols, func(r row) {
			collect(r)
			if keys.ingest(r) {
				changed = true
			}
		})
		if err != nil {
			fmt.Fprintln(os.Stderr, "error:", err)
			return 1
		}
		if keys.promote() {
			changed = true
		}
		fmt.Fprintf(os.Stderr, "round %d: %d packets matched, %s\n", rounds, st.count, keySummary(keys))
		if !changed {
			converged = true
			break
		}
	}
	if !converged {
		rounds = o.maxRounds
		fmt.Fprintf(os.Stderr, "warning: did not converge in %d rounds; result may be incomplete (use --max-rounds)\n", o.maxRounds)
		filter = keys.buildFilter(cat, o)
		newStats()
		if err := tr.fields(input, filter, cols, collect); err != nil {
			fmt.Fprintln(os.Stderr, "error:", err)
			return 1
		}
	}

	if st.count == 0 {
		fmt.Fprintln(os.Stderr, "no packets matched. Check identity format (MSISDN: international format without '+'),")
		fmt.Fprintln(os.Stderr, "or whether NAS is ciphered / the capture contains plain GTPv2, Diameter or SIP carrying the identity.")
		return 1
	}
	if len(filter) > 120000 {
		fmt.Fprintf(os.Stderr, "error: display filter is %d bytes; too long for a command-line argument\n", len(filter))
		return 1
	}

	fmt.Fprintf(os.Stderr, "writing %d packets to %s ...\n", st.count, o.out)
	if err := tr.write(input, filter, o.out); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 1
	}
	filterFile := o.out + ".filter.txt"
	if err := os.WriteFile(filterFile, []byte(filter+"\n"), 0o644); err != nil {
		fmt.Fprintln(os.Stderr, "warning: cannot write filter file:", err)
		filterFile = "(not written)"
	}

	printReport(o, input, nFiles, filterFile, keys, &st, filter, rounds, converged)
	return 0
}

// ---------------------------------------------------------------------------
// Report
// ---------------------------------------------------------------------------

func parseFloat(s string) float64 {
	var f float64
	fmt.Sscanf(s, "%f", &f)
	return f
}

func keySummary(k *Keys) string {
	return fmt.Sprintf("keys: S1AP=%d NGAP=%d TEID=%d Diameter=%d F-SEID=%d SIP=%d UE-IP=%d",
		len(k.s1ap.core), len(k.ngap.core), len(k.tunnels), len(k.diaSess), len(k.seids), len(k.callIDs), len(k.ueIPs))
}

func ts(sec float64) string {
	return time.Unix(int64(sec), int64((sec-float64(int64(sec)))*1e9)).Format("2006-01-02 15:04:05.000 MST")
}

func printReport(o *options, input string, nFiles int, filterFile string, k *Keys, st *roundStats, filter string, rounds int, converged bool) {
	line := strings.Repeat("=", 72)
	sub := func(title string) { fmt.Printf("\n[%s]\n", title) }
	fmt.Println(line)
	fmt.Println(" gshark usertrack result")
	fmt.Println(line)

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	inLabel := input
	if o.dir != "" {
		inLabel = fmt.Sprintf("%s (merged+reordered from %d file(s) in %s)", input, nFiles, o.dir)
	}
	state := "converged"
	if !converged {
		state = "NOT converged"
	}
	fmt.Fprintf(w, "Input\t%s\n", inLabel)
	fmt.Fprintf(w, "Output\t%s\n", o.out)
	fmt.Fprintf(w, "Filter file\t%s\n", filterFile)
	fmt.Fprintf(w, "Rounds\t%d (%s)\n", rounds, state)
	fmt.Fprintf(w, "Packets\t%d\n", st.count)
	if st.tmin > 0 {
		fmt.Fprintf(w, "Time range\t%s  ->  %s\n", ts(st.tmin), ts(st.tmax))
	}
	w.Flush()

	sub("Identity")
	w = tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	idLine := func(label string, s set, auto bool) {
		if len(s) == 0 {
			fmt.Fprintf(w, "%s\t-\n", label)
			return
		}
		note := ""
		if auto {
			note = "  (auto-discovered)"
		}
		fmt.Fprintf(w, "%s\t%s%s\n", label, strings.Join(s.sorted(), ", "), note)
	}
	idLine("IMSI", k.imsi, k.autoIMSI)
	idLine("MSISDN", k.msisdn, k.autoMSISDN)
	w.Flush()

	sub("Packets by protocol (a packet may count for several)")
	w = tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	for _, p := range interestingProtos {
		if n := st.protos[p]; n > 0 {
			fmt.Fprintf(w, "%s\t%d\n", p, n)
		}
	}
	w.Flush()

	for _, u := range []*ueTracker{k.s1ap, k.ngap} {
		if len(u.pairs) == 0 && len(u.core) == 0 {
			continue
		}
		sub(u.name + " UE IDs")
		w = tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		ranName, coreName := "eNB-UE-S1AP-ID", "MME-UE-S1AP-ID"
		if u.name == "NGAP" {
			ranName, coreName = "RAN-UE-NGAP-ID", "AMF-UE-NGAP-ID"
		}
		fmt.Fprintf(w, "SCTP assoc\t%s\t%s\n", ranName, coreName)
		listed := set{}
		for _, p := range u.sortedPairs() {
			fmt.Fprintf(w, "%s\t%s\t%s\n", dash(p[0]), p[1], p[2])
			listed.add(p[2])
		}
		for _, c := range u.core.sorted() {
			if _, ok := listed[c]; !ok {
				fmt.Fprintf(w, "-\t-\t%s\n", c)
			}
		}
		w.Flush()
	}

	if len(k.tunnels) > 0 {
		sub("Tunnel endpoints (GTPv2 F-TEID / S1AP / NGAP / PFCP)")
		w = tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		fmt.Fprintln(w, "Source\tInterface Type\tTEID\tIP")
		for _, t := range k.effectiveTunnels(false) {
			m := k.tunnels[t]
			if m.src == "" {
				m = k.tunnels[tunnel{t.teid, ""}]
			}
			fmt.Fprintf(w, "%s\t%s\t0x%08x\t%s\n", m.src, dash(m.iface), t.teid, dash(t.ip))
		}
		w.Flush()
	}

	if len(k.seids) > 0 {
		sub("PFCP F-SEID")
		w = tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		fmt.Fprintln(w, "SEID\tIP")
		var ss []uint64
		for s := range k.seids {
			ss = append(ss, s)
		}
		sort.Slice(ss, func(i, j int) bool { return ss[i] < ss[j] })
		for _, s := range ss {
			fmt.Fprintf(w, "0x%016x\t%s\n", s, dash(k.seids[s]))
		}
		w.Flush()
	}

	listStrings := func(title string, s set) {
		if len(s) == 0 {
			return
		}
		sub(title)
		for _, v := range s.sorted() {
			fmt.Println("  " + v)
		}
	}
	listStrings("Diameter Session-Id", k.diaSess)
	listStrings("SIP Call-ID", k.callIDs)
	listStrings("UE IP", k.ueIPs)

	sub("Display filter")
	if o.showFilter || len(filter) <= 400 {
		fmt.Println(filter)
	} else {
		fmt.Printf("%s ...\n  (%d bytes; full filter in %s or use --show-filter)\n", filter[:400], len(filter), filterFile)
	}
	fmt.Println(line)
}

func dash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}
