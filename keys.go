package main

import (
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"
)

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

type set map[string]struct{}

func (s set) add(v string) bool {
	if v == "" {
		return false
	}
	if _, ok := s[v]; ok {
		return false
	}
	s[v] = struct{}{}
	return true
}

func (s set) sorted() []string {
	out := make([]string, 0, len(s))
	for v := range s {
		out = append(out, v)
	}
	sortNumericStrings(out)
	return out
}

func sortNumericStrings(out []string) {
	sort.Slice(out, func(i, j int) bool {
		a, ea := strconv.ParseUint(out[i], 10, 64)
		b, eb := strconv.ParseUint(out[j], 10, 64)
		if ea == nil && eb == nil {
			return a < b
		}
		return out[i] < out[j]
	})
}

// parseHex accepts "0x1234", "1234abcd" and "12:34:ab:cd".
func parseHex(s string, bits int) (uint64, bool) {
	s = strings.ToLower(strings.TrimSpace(s))
	s = strings.TrimPrefix(s, "0x")
	s = strings.ReplaceAll(s, ":", "")
	if s == "" {
		return 0, false
	}
	v, err := strconv.ParseUint(s, 16, bits)
	return v, err == nil
}

func qstr(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `"`, `\"`)
	return `"` + s + `"`
}

func qlist(vals []string) string {
	q := make([]string, len(vals))
	for i, v := range vals {
		q[i] = qstr(v)
	}
	return strings.Join(q, " ")
}

// 3GPP TS 29.274 F-TEID Interface Type
var gtpv2Ifaces = map[int]string{
	0: "S1-U eNodeB GTP-U", 1: "S1-U SGW GTP-U", 2: "S12 RNC GTP-U", 3: "S12 SGW GTP-U",
	4: "S5/S8 SGW GTP-U", 5: "S5/S8 PGW GTP-U", 6: "S5/S8 SGW GTP-C", 7: "S5/S8 PGW GTP-C",
	8: "S5/S8 SGW PMIPv6", 9: "S5/S8 PGW PMIPv6", 10: "S11 MME GTP-C", 11: "S11/S4 SGW GTP-C",
	12: "S10/N26 MME GTP-C", 13: "S3 MME GTP-C", 14: "S3 SGSN GTP-C", 15: "S4 SGSN GTP-U",
	16: "S4 SGW GTP-U", 17: "S4 SGSN GTP-C", 18: "S16 SGSN GTP-C", 19: "eNB/gNB GTP-U DL fwd",
	20: "eNB GTP-U UL fwd", 21: "RNC GTP-U fwd", 22: "SGSN GTP-U fwd", 23: "SGW/UPF GTP-U DL fwd",
	24: "Sm MBMS GW GTP-C", 25: "Sn MBMS GW GTP-C", 26: "Sm MME GTP-C", 27: "Sn SGSN GTP-C",
	28: "SGW GTP-U UL fwd", 29: "Sn SGSN GTP-U", 30: "S2b ePDG GTP-C", 31: "S2b-U ePDG GTP-U",
	32: "S2b PGW GTP-C", 33: "S2b-U PGW GTP-U", 34: "S2a TWAN GTP-U", 35: "S2a TWAN GTP-C",
	36: "S2a PGW GTP-C", 37: "S2a PGW GTP-U", 38: "S11 MME GTP-U", 39: "S11 SGW GTP-U",
}

func ifaceName(v string) string {
	n, err := strconv.Atoi(strings.TrimSpace(v))
	if err != nil {
		return v
	}
	if s, ok := gtpv2Ifaces[n]; ok {
		return fmt.Sprintf("%s (%d)", s, n)
	}
	return strconv.Itoa(n)
}

// ---------------------------------------------------------------------------
// S1AP / NGAP UE-ID tracker
//
// MME-UE-S1AP-ID / AMF-UE-NGAP-ID are unique on the core side, so once known
// they are used alone as the key (this also follows handovers to another eNB).
// The first message of a UE (Initial UE Message) only has the eNB-side ID, so
// it is tracked as "pending" with a short time window until the core-side ID
// shows up.
// ---------------------------------------------------------------------------

type pendKey struct {
	assoc, ran string
	t          float64
}

type ueTracker struct {
	name, fAssoc, fRAN, fCore string
	window                    float64
	core                      set
	pairs                     map[[3]string]struct{} // assoc, ran, core
	pending                   map[pendKey]bool       // true = resolved
}

func newUETracker(name, fAssoc, fRAN, fCore string, window float64) *ueTracker {
	return &ueTracker{name: name, fAssoc: fAssoc, fRAN: fRAN, fCore: fCore, window: window,
		core: set{}, pairs: map[[3]string]struct{}{}, pending: map[pendKey]bool{}}
}

func (u *ueTracker) inWindow(p pendKey, t float64) bool {
	return t >= p.t-0.001 && t <= p.t+u.window
}

func (u *ueTracker) ingest(r row, t float64) bool {
	assoc, ran, core := r.first(u.fAssoc), r.first(u.fRAN), r.first(u.fCore)
	changed := false
	if core != "" {
		if u.core.add(core) {
			changed = true
		}
		if ran != "" {
			pk := [3]string{assoc, ran, core}
			if _, ok := u.pairs[pk]; !ok {
				u.pairs[pk] = struct{}{}
				changed = true
			}
			for p, done := range u.pending {
				if !done && p.assoc == assoc && p.ran == ran && u.inWindow(p, t) {
					u.pending[p] = true
					changed = true
				}
			}
		}
		return changed
	}
	if ran != "" {
		for p := range u.pending {
			if p.assoc == assoc && p.ran == ran && u.inWindow(p, t) {
				return false
			}
		}
		u.pending[pendKey{assoc, ran, t}] = false
		changed = true
	}
	return changed
}

func (u *ueTracker) clause(c *catalog) string {
	var ps []string
	if len(u.core) > 0 && c.Has(u.fCore) {
		ps = append(ps, fmt.Sprintf("%s in {%s}", u.fCore, strings.Join(u.core.sorted(), " ")))
	}
	if c.Has(u.fRAN) {
		var pend []pendKey
		for p, done := range u.pending {
			if !done {
				pend = append(pend, p)
			}
		}
		sort.Slice(pend, func(i, j int) bool { return pend[i].t < pend[j].t })
		for _, p := range pend {
			s := fmt.Sprintf("%s == %s && frame.time_epoch >= %.6f && frame.time_epoch <= %.6f",
				u.fRAN, p.ran, p.t-0.001, p.t+u.window)
			if p.assoc != "" && c.Has(u.fAssoc) {
				s = fmt.Sprintf("%s == %s && ", u.fAssoc, p.assoc) + s
			}
			ps = append(ps, "("+s+")")
		}
	}
	return strings.Join(ps, " || ")
}

func (u *ueTracker) sortedPairs() [][3]string {
	out := make([][3]string, 0, len(u.pairs))
	for p := range u.pairs {
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i][0] != out[j][0] {
			return out[i][0] < out[j][0]
		}
		a, _ := strconv.Atoi(out[i][1])
		b, _ := strconv.Atoi(out[j][1])
		return a < b
	})
	return out
}

// ---------------------------------------------------------------------------
// Keys
// ---------------------------------------------------------------------------

type tunnel struct {
	teid uint32
	ip   string // "" = unknown
}

type tunMeta struct{ src, iface string }

type Keys struct {
	imsi, msisdn         set
	autoIMSI, autoMSISDN bool
	seenIMSI, seenMSISDN set

	s1ap, ngap *ueTracker
	tunnels    map[tunnel]tunMeta
	diaSess    set
	seids      map[uint64]string // F-SEID -> IP
	ueIPs      set
	callIDs    set
}

func newKeys(imsi, msisdn string, window float64) *Keys {
	k := &Keys{
		imsi: set{}, msisdn: set{}, seenIMSI: set{}, seenMSISDN: set{},
		s1ap:    newUETracker("S1AP", "sctp.assoc_index", "s1ap.ENB_UE_S1AP_ID", "s1ap.MME_UE_S1AP_ID", window),
		ngap:    newUETracker("NGAP", "sctp.assoc_index", "ngap.RAN_UE_NGAP_ID", "ngap.AMF_UE_NGAP_ID", window),
		tunnels: map[tunnel]tunMeta{}, diaSess: set{}, seids: map[uint64]string{},
		ueIPs: set{}, callIDs: set{},
	}
	k.imsi.add(imsi)
	k.msisdn.add(msisdn)
	return k
}

// columns requested from tshark in every round.
var keyColumns = []string{
	"frame.time_epoch", "frame.protocols",
	"e212.imsi", "e164.msisdn",
	"sctp.assoc_index",
	"s1ap.ENB_UE_S1AP_ID", "s1ap.MME_UE_S1AP_ID", "s1ap.gTP_TEID", "s1ap.transportLayerAddressIPv4",
	"ngap.RAN_UE_NGAP_ID", "ngap.AMF_UE_NGAP_ID", "ngap.gTP_TEID", "ngap.transportLayerAddressIPv4",
	"gtpv2.f_teid_interface_type", "gtpv2.f_teid_teid_gre_key", "gtpv2.f_teid_ipv4",
	"gtpv2.pdn_addr_and_pfx_ipv4",
	"diameter.Session-Id",
	"pfcp.f_seid.seid", "pfcp.f_seid.ipv4", "pfcp.f_teid.teid", "pfcp.f_teid.ipv4_addr", "pfcp.ue_ip_addr_ipv4",
	"sip.Call-ID",
}

func (k *Keys) addTunnel(teidStr, ip, src, iface string) bool {
	v, ok := parseHex(teidStr, 32)
	if !ok || v == 0 {
		return false
	}
	if ip != "" && net.ParseIP(ip) == nil {
		ip = ""
	}
	t := tunnel{uint32(v), ip}
	if _, ok := k.tunnels[t]; ok {
		return false
	}
	k.tunnels[t] = tunMeta{src, iface}
	return true
}

func (k *Keys) ingestTunnels(r row, teidF, ipF, ifF, src string) bool {
	teids, ips, ifs := r.all(teidF), r.all(ipF), r.all(ifF)
	changed := false
	for i, ts := range teids {
		ip, ifc := "", ""
		if len(ips) == len(teids) {
			ip = ips[i]
		}
		if len(ifs) == len(teids) {
			ifc = ifaceName(ifs[i])
		}
		if k.addTunnel(ts, ip, src, ifc) {
			changed = true
		}
	}
	return changed
}

func (k *Keys) addUEIP(ip string) bool {
	p := net.ParseIP(ip)
	if p == nil || p.To4() == nil || p.IsUnspecified() {
		return false
	}
	return k.ueIPs.add(ip)
}

// ingest extracts keys from one matched packet. Returns true if anything new.
func (k *Keys) ingest(r row) bool {
	changed := false
	t, _ := strconv.ParseFloat(r.first("frame.time_epoch"), 64)

	for _, v := range r.all("e212.imsi") {
		k.seenIMSI.add(v)
	}
	for _, v := range r.all("e164.msisdn") {
		k.seenMSISDN.add(v)
	}

	if k.s1ap.ingest(r, t) {
		changed = true
	}
	if k.ngap.ingest(r, t) {
		changed = true
	}

	// GTPv2 F-TEID (Interface Type + TEID + IP)
	if k.ingestTunnels(r, "gtpv2.f_teid_teid_gre_key", "gtpv2.f_teid_ipv4", "gtpv2.f_teid_interface_type", "GTPv2 F-TEID") {
		changed = true
	}
	// PFCP F-TEID / S1AP,NGAP user-plane tunnel info
	if k.ingestTunnels(r, "pfcp.f_teid.teid", "pfcp.f_teid.ipv4_addr", "", "PFCP F-TEID") {
		changed = true
	}
	if k.ingestTunnels(r, "s1ap.gTP_TEID", "s1ap.transportLayerAddressIPv4", "", "S1AP E-RAB") {
		changed = true
	}
	if k.ingestTunnels(r, "ngap.gTP_TEID", "ngap.transportLayerAddressIPv4", "", "NGAP PDU Session") {
		changed = true
	}

	// UE IP
	for _, f := range []string{"gtpv2.pdn_addr_and_pfx_ipv4", "pfcp.ue_ip_addr_ipv4"} {
		for _, ip := range r.all(f) {
			if k.addUEIP(ip) {
				changed = true
			}
		}
	}

	// Diameter Session-Id
	for _, s := range r.all("diameter.Session-Id") {
		if k.diaSess.add(s) {
			changed = true
		}
	}

	// PFCP F-SEID
	ss, sips := r.all("pfcp.f_seid.seid"), r.all("pfcp.f_seid.ipv4")
	for i, s := range ss {
		seid, ok := parseHex(s, 64)
		if !ok || seid == 0 {
			continue
		}
		ip := ""
		if len(sips) == len(ss) {
			ip = sips[i]
		}
		if old, exists := k.seids[seid]; !exists {
			k.seids[seid] = ip
			changed = true
		} else if old == "" && ip != "" {
			k.seids[seid] = ip
		}
	}

	// SIP Call-ID
	for _, s := range r.all("sip.Call-ID") {
		if k.callIDs.add(s) {
			changed = true
		}
	}
	return changed
}

// promote adopts a discovered IMSI/MSISDN as an additional seed when the
// identity given by the user is only one of the two and exactly one value of
// the other kind was observed.
func (k *Keys) promote() bool {
	changed := false
	if len(k.imsi) == 0 && len(k.seenIMSI) == 1 {
		for v := range k.seenIMSI {
			k.imsi.add(v)
		}
		k.autoIMSI, changed = true, true
	}
	if len(k.msisdn) == 0 && len(k.seenMSISDN) == 1 {
		for v := range k.seenMSISDN {
			k.msisdn.add(v)
		}
		k.autoMSISDN, changed = true, true
	}
	return changed
}

// effectiveTunnels drops IP-less duplicates when an IP-qualified entry exists
// (or drops IPs entirely with teidOnly).
func (k *Keys) effectiveTunnels(teidOnly bool) []tunnel {
	withIP := map[uint32]bool{}
	for t := range k.tunnels {
		if t.ip != "" {
			withIP[t.teid] = true
		}
	}
	uniq := map[tunnel]struct{}{}
	for t := range k.tunnels {
		if teidOnly {
			t.ip = ""
		} else if t.ip == "" && withIP[t.teid] {
			continue
		}
		uniq[t] = struct{}{}
	}
	out := make([]tunnel, 0, len(uniq))
	for t := range uniq {
		out = append(out, t)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].teid != out[j].teid {
			return out[i].teid < out[j].teid
		}
		return out[i].ip < out[j].ip
	})
	return out
}

// ---------------------------------------------------------------------------
// Display filter
// ---------------------------------------------------------------------------

func (k *Keys) seedClauses(c *catalog) []string {
	var out []string
	has := c.Has
	for _, v := range k.imsi.sorted() {
		if has("e212.imsi") {
			out = append(out, fmt.Sprintf("e212.imsi == %s", qstr(v)))
		}
		if has("diameter.User-Name") {
			out = append(out, fmt.Sprintf("diameter.User-Name contains %s", qstr(v)))
		}
		if has("diameter.Subscription-Id-Data") {
			out = append(out, fmt.Sprintf("diameter.Subscription-Id-Data contains %s", qstr(v)))
		}
		if has("sip") {
			out = append(out, fmt.Sprintf("sip contains %s", qstr(v)))
		}
	}
	for _, v := range k.msisdn.sorted() {
		if has("e164.msisdn") {
			out = append(out, fmt.Sprintf("e164.msisdn == %s", qstr(v)))
		}
		if has("diameter.Subscription-Id-Data") {
			out = append(out, fmt.Sprintf("diameter.Subscription-Id-Data contains %s", qstr(v)))
		}
		if has("sip") {
			out = append(out, fmt.Sprintf("sip contains %s", qstr(v)))
		}
	}
	return out
}

type contentField struct {
	teid, ip string
	bytes    bool
}

var contentFields = []contentField{
	{"gtpv2.f_teid_teid_gre_key", "gtpv2.f_teid_ipv4", false},
	{"pfcp.f_teid.teid", "pfcp.f_teid.ipv4_addr", false},
	{"s1ap.gTP_TEID", "s1ap.transportLayerAddressIPv4", true},
	{"ngap.gTP_TEID", "ngap.transportLayerAddressIPv4", true},
}

func (k *Keys) buildFilter(c *catalog, o *options) string {
	var parts []string
	add := func(s string) {
		if s != "" {
			parts = append(parts, "("+s+")")
		}
	}

	// 1. identity seeds
	for _, s := range k.seedClauses(c) {
		add(s)
	}

	// 2. S1AP / NGAP UE IDs
	add(k.s1ap.clause(c))
	add(k.ngap.clause(c))

	// 3. TEID in GTPv2-C / GTP-U headers (destination IP-qualified)
	eff := k.effectiveTunnels(o.teidOnly)
	hdr := []string{}
	for _, f := range []string{"gtpv2.teid", "gtp.teid"} {
		if f == "gtp.teid" && o.noUserPlane {
			continue
		}
		if c.Has(f) {
			hdr = append(hdr, f)
		}
	}
	groups := map[string][]string{}
	for _, t := range eff {
		groups[t.ip] = append(groups[t.ip], fmt.Sprintf("0x%08x", t.teid))
	}
	ips := make([]string, 0, len(groups))
	for ip := range groups {
		ips = append(ips, ip)
	}
	sort.Strings(ips)
	if len(hdr) > 0 {
		for _, ip := range ips {
			var ors []string
			for _, f := range hdr {
				ors = append(ors, fmt.Sprintf("%s in {%s}", f, strings.Join(groups[ip], " ")))
			}
			cl := strings.Join(ors, " || ")
			if ip != "" && c.Has("ip.dst") {
				cl = fmt.Sprintf("ip.dst == %s && (%s)", ip, cl)
			}
			add(cl)
		}
	}

	// 4. TEID carried inside control messages (F-TEID IE, E-RAB, PFCP F-TEID)
	for _, t := range eff {
		for _, cf := range contentFields {
			if !c.Has(cf.teid) {
				continue
			}
			var lit string
			if cf.bytes {
				lit = fmt.Sprintf("%02x:%02x:%02x:%02x", t.teid>>24, (t.teid>>16)&0xff, (t.teid>>8)&0xff, t.teid&0xff)
			} else {
				lit = fmt.Sprintf("0x%08x", t.teid)
			}
			term := fmt.Sprintf("%s == %s", cf.teid, lit)
			if t.ip != "" && c.Has(cf.ip) {
				term += fmt.Sprintf(" && %s == %s", cf.ip, t.ip)
			}
			add(term)
		}
	}

	// 5. Diameter Session-Id
	if len(k.diaSess) > 0 && c.Has("diameter.Session-Id") {
		add(fmt.Sprintf("diameter.Session-Id in {%s}", qlist(k.diaSess.sorted())))
	}

	// 6. PFCP SEID (header SEID = peer's F-SEID, so match both)
	if len(k.seids) > 0 {
		var l []string
		keys := make([]uint64, 0, len(k.seids))
		for s := range k.seids {
			keys = append(keys, s)
		}
		sort.Slice(keys, func(i, j int) bool { return keys[i] < keys[j] })
		for _, s := range keys {
			l = append(l, fmt.Sprintf("0x%016x", s))
		}
		lits := strings.Join(l, " ")
		var ors []string
		for _, f := range []string{"pfcp.seid", "pfcp.f_seid.seid"} {
			if c.Has(f) {
				ors = append(ors, fmt.Sprintf("%s in {%s}", f, lits))
			}
		}
		add(strings.Join(ors, " || "))
	}

	// 7. SIP Call-ID
	if len(k.callIDs) > 0 && c.Has("sip.Call-ID") {
		add(fmt.Sprintf("sip.Call-ID in {%s}", qlist(k.callIDs.sorted())))
	}

	// 8. UE IP
	if len(k.ueIPs) > 0 {
		ipl := k.ueIPs.sorted()
		if c.Has("pfcp.ue_ip_addr_ipv4") {
			add(fmt.Sprintf("pfcp.ue_ip_addr_ipv4 in {%s}", strings.Join(ipl, " ")))
		}
		if c.Has("diameter") { // Framed-IP-Address AVP etc. (raw 4 bytes)
			for _, s := range ipl {
				b := net.ParseIP(s).To4()
				add(fmt.Sprintf("diameter contains %02x:%02x:%02x:%02x", b[0], b[1], b[2], b[3]))
			}
		}
		if !o.noUEIP && c.Has("ip.addr") {
			cl := fmt.Sprintf("ip.addr in {%s}", strings.Join(ipl, " "))
			if o.noUserPlane {
				if c.Has("sip") {
					add(cl + " && sip")
				}
			} else {
				add(cl)
			}
		}
	}

	return strings.Join(parts, " || ")
}
