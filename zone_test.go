package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"slices"
	"strings"
	"sync"
	"testing"
)

// 内存里的 Cloudflare：每个 Token 只管自己那个域名，模拟换了账号
type fakeCF struct {
	mu      sync.Mutex
	zones   map[string]string // zone id → 域名
	tokens  map[string]string // token → zone id
	recs    map[string][]cfRecord
	rules   map[string][]map[string]any // zone id + phase
	failPut string                      // 写这个 phase 的规则时报错
	seq     int
}

func newFakeCF() *fakeCF {
	return &fakeCF{
		zones:  map[string]string{"za": "a.test", "zb": "b.test"},
		tokens: map[string]string{"ta": "za", "tb": "zb"},
		recs:   map[string][]cfRecord{},
		rules:  map[string][]map[string]any{},
	}
}

func (f *fakeCF) add(zid string, r DNSRecord) string {
	f.seq++
	id := fmt.Sprintf("r%d", f.seq)
	f.recs[zid] = append(f.recs[zid], cfRecord{ID: id, DNSRecord: r})
	return id
}

func (f *fakeCF) names(zid string) []string {
	var ns []string
	for _, r := range f.recs[zid] {
		ns = append(ns, r.Type+" "+r.Name+" "+r.Content)
	}
	slices.Sort(ns)
	return ns
}

func (f *fakeCF) ruleDescs(zid string) []string {
	var ds []string
	for _, ph := range []string{"http_request_origin", "http_config_settings"} {
		for _, r := range f.rules[zid+"/"+ph] {
			ds = append(ds, ph+" "+r["description"].(string))
		}
	}
	return ds
}

func (f *fakeCF) RoundTrip(req *http.Request) (*http.Response, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	reply := func(status int, result any) (*http.Response, error) {
		b, _ := json.Marshal(map[string]any{"success": status < 300, "result": result,
			"errors": map[bool][]any{true: {}, false: {map[string]any{"code": 9109, "message": "Unauthorized"}}}[status < 300]})
		return &http.Response{StatusCode: status, Body: io.NopCloser(strings.NewReader(string(b))), Header: make(http.Header)}, nil
	}
	own := f.tokens[strings.TrimPrefix(req.Header.Get("Authorization"), "Bearer ")]
	p := strings.TrimPrefix(req.URL.Path, "/client/v4")
	if p == "/zones" {
		if own == "" {
			return reply(403, nil)
		}
		return reply(200, []cfZone{{ID: own, Name: f.zones[own], NS: nil}})
	}
	parts := strings.Split(strings.TrimPrefix(p, "/zones/"), "/")
	zid := parts[0]
	if own == "" || own != zid {
		return reply(403, nil)
	}
	switch {
	case len(parts) == 2 && parts[1] == "dns_records" && req.Method == "GET":
		var out []cfRecord
		for _, r := range f.recs[zid] {
			if r.Name == req.URL.Query().Get("name") {
				out = append(out, r)
			}
		}
		return reply(200, out)
	case len(parts) == 2 && parts[1] == "dns_records" && req.Method == "POST":
		var r DNSRecord
		json.NewDecoder(req.Body).Decode(&r)
		return reply(200, map[string]string{"id": f.add(zid, r)})
	case len(parts) == 3 && parts[1] == "dns_records" && req.Method == "DELETE":
		for i, r := range f.recs[zid] {
			if r.ID == parts[2] {
				f.recs[zid] = slices.Delete(f.recs[zid], i, i+1)
				return reply(200, nil)
			}
		}
		return reply(404, nil)
	case len(parts) == 5 && parts[1] == "rulesets":
		key := zid + "/" + parts[3]
		if req.Method == "PUT" {
			if parts[3] == f.failPut {
				return reply(403, nil)
			}
			var body struct {
				Rules []map[string]any `json:"rules"`
			}
			json.NewDecoder(req.Body).Decode(&body)
			f.rules[key] = body.Rules
			return reply(200, nil)
		}
		if _, ok := f.rules[key]; !ok {
			return reply(404, nil)
		}
		return reply(200, map[string]any{"rules": f.rules[key]})
	case len(parts) == 3 && parts[1] == "settings":
		return reply(200, map[string]any{"value": "on"})
	}
	return reply(404, nil)
}

func zoneState(f *fakeCF) *State {
	st := &State{IP4: "203.0.113.7", Zone: &Zone{ID: "za", Name: "a.test"}, Reality: &Reality{Port: 443}}
	st.TLS = &TLSHost{Host: "n1.m1.a.test", CertName: "*.m1.a.test", RecordID: f.add("za", DNSRecord{Type: "A", Name: "n1.m1.a.test", Content: st.IP4})}
	st.WS = &WS{Host: "w1.a.test", PubPort: 8443, RecordID: f.add("za", DNSRecord{Type: "A", Name: "w1.a.test", Content: st.IP4, Proxied: true}),
		Backup: []DNSRecord{{Type: "CNAME", Name: "w1.a.test", Content: "old.example.org"}}}
	f.rules["za/http_request_origin"] = []map[string]any{{"description": "别人的规则"}, {"description": rulePrefix + "w1.a.test"}}
	f.rules["za/http_config_settings"] = []map[string]any{{"description": rulePrefix + "w1.a.test"}}
	return st
}

// 新域名上写规则失败：新加的解析和规则全撤掉，被覆盖的解析放回去，状态不动
func TestMoveZoneRollback(t *testing.T) {
	f := newFakeCF()
	mockCF(t, f.RoundTrip)
	st := zoneState(f)
	f.add("zb", DNSRecord{Type: "A", Name: "www.b.test", Content: "198.51.100.1"})
	beforeB, beforeA := f.names("zb"), f.names("za")
	f.failPut = "http_config_settings"
	in = bufio.NewReader(strings.NewReader("n2\nwww\ny\n"))
	want := *st
	wantTLS, wantWS := *st.TLS, *st.WS
	err := moveZone(st, &CF{Token: "ta"}, &CF{Token: "tb"}, &Zone{ID: "zb", Name: "b.test"})
	if err == nil || !strings.Contains(err.Error(), "配置规则") {
		t.Fatalf("应该报写配置规则失败：%v", err)
	}
	if got := f.names("zb"); !slices.Equal(got, beforeB) {
		t.Errorf("新域名没还原：%v，原来 %v", got, beforeB)
	}
	if d := f.ruleDescs("zb"); len(d) != 0 {
		t.Errorf("新域名上留下了规则：%v", d)
	}
	if got := f.names("za"); !slices.Equal(got, beforeA) {
		t.Errorf("旧域名被动了：%v", got)
	}
	if st.Zone != want.Zone || st.TLS.Host != wantTLS.Host || st.TLS.RecordID != wantTLS.RecordID ||
		st.WS.Host != wantWS.Host || st.WS.RecordID != wantWS.RecordID {
		t.Errorf("状态被改了：%+v %+v", st.TLS, st.WS)
	}
}

func TestZoneCleanup(t *testing.T) {
	f := newFakeCF()
	mockCF(t, f.RoundTrip)
	st := zoneState(f)
	if left := zoneCleanup(st, &CF{Token: "ta"}, &CF{Token: "tb"}); len(left) != 0 {
		t.Fatalf("旧凭据还能用，不该有剩下的：%v", left)
	}
	if got := f.names("za"); !slices.Equal(got, []string{"CNAME w1.a.test old.example.org"}) {
		t.Errorf("旧域名上应该只剩还原的解析：%v", got)
	}
	if d := f.ruleDescs("za"); !slices.Equal(d, []string{"http_request_origin 别人的规则"}) {
		t.Errorf("规则没删干净，或者删了别人的：%v", d)
	}
}

// 旧凭据失效、新凭据也管不了旧域名：什么都不删，列出来让用户自己处理
func TestZoneCleanupOldCredGone(t *testing.T) {
	f := newFakeCF()
	mockCF(t, f.RoundTrip)
	st := zoneState(f)
	before := f.names("za")
	left := zoneCleanup(st, &CF{Token: "dead"}, &CF{Token: "tb"})
	if len(left) != 3 {
		t.Fatalf("应该列出两条解析和一组规则：%v", left)
	}
	if got := f.names("za"); !slices.Equal(got, before) {
		t.Errorf("没凭据还删了东西：%v", got)
	}
}

func TestClashMicrosoft(t *testing.T) {
	s := subClash(&State{})
	if !strings.Contains(s, "  - name: 微软\n    type: select\n    proxies: [节点选择, 自动选择, DIRECT]") {
		t.Error("微软分组默认应该走代理")
	}
	if !strings.Contains(s, "  - name: 苹果\n    type: select\n    proxies: [DIRECT, 节点选择, 自动选择]") {
		t.Error("苹果分组应该还是直连")
	}
	cn, all := strings.Index(s, "GEOSITE,microsoft@cn,DIRECT"), strings.Index(s, "GEOSITE,microsoft,微软")
	if cn < 0 || all < 0 || cn > all {
		t.Error("microsoft@cn 直连要排在微软分组前面")
	}
}
