package main

import (
	"errors"
	"fmt"
	"os"
)

// ── 换凭据、换域名 ────────────────────────────────────
// 换了 Cloudflare 账号，或者想换个域名：节点域名、证书、CF WS 子域名和它的规则一起搬到新域名上。
// 新域名上的东西都备齐了才切过去，中途哪步失败就把新域名上加的删掉，原来的凭据、状态和证书都不动

func changeCF(st *State) {
	inUse := st.Zone != nil && (st.TLS != nil || st.WS != nil)
	if inUse {
		info("节点现在用的域名是 %s。新凭据管不了它的话，可以把节点搬到新凭据下的域名", st.Zone.Name)
	}
	c := cfAsk()
	if !inUse {
		cfSave(c)
		st.Zone = nil
		st.save()
		return
	}
	zs, err := c.Zones()
	if err != nil {
		warn("读取域名列表失败，凭据没换：%v", err)
		return
	}
	listed := false
	var others []cfZone
	for _, z := range zs {
		if z.ID == st.Zone.ID {
			listed = true
		} else {
			others = append(others, z)
		}
	}
	var target *cfZone
	_, dnsErr := c.DNSList(st.Zone.ID, st.Zone.Name)
	var apiErr *cfAPIError
	switch {
	case dnsErr != nil && !errors.As(dnsErr, &apiErr):
		warn("连不上 Cloudflare，凭据没换：%v", dnsErr)
		return
	case dnsErr == nil:
		if len(others) > 0 {
			info("这份凭据还能管别的域名，节点要换过去吗：")
			opts := []string{"继续用 " + st.Zone.Name}
			for _, z := range others {
				opts = append(opts, "换到 "+z.Name)
			}
			i := choose(opts, 1)
			if i < 0 {
				info("凭据没换")
				return
			}
			if i > 0 {
				target = &others[i-1]
			}
		}
		if target == nil {
			if st.WS != nil && c.Token != "" {
				if err := c.checkWSRules(st.Zone.ID); err != nil {
					warn("%v，凭据没换", err)
					return
				}
			}
			cfSave(c)
			return
		}
	case listed:
		warn("新凭据能看到 %s，但读不了它的解析，凭据没换：%v", st.Zone.Name, dnsErr)
		return
	default:
		warn("新凭据管不了现在的域名 %s", st.Zone.Name)
		if len(others) == 0 {
			warn("新凭据下也没有已激活的域名，凭据没换")
			return
		}
		info("把节点搬到哪个域名：")
		var names []string
		for _, z := range others {
			names = append(names, z.Name)
		}
		i := choose(names, 1)
		if i < 0 {
			info("凭据没换")
			return
		}
		target = &others[i]
	}
	info("节点会搬到 %s：节点域名、证书和 CF WS 的子域名都换新的，订阅地址和链接都会变，客户端要重新导入", target.Name)
	if !confirm("开始搬？", true) {
		info("凭据没换")
		return
	}
	if err := moveZone(st, cfLoad(), c, &Zone{ID: target.ID, Name: target.Name, NS: target.NS}); err != nil {
		warn("没搬成，凭据和节点都还是原来的：%v", err)
		return
	}
	warn("订阅地址和节点链接都换了，客户端里要重新导入")
	showLinks(st)
}

func moveZone(st *State, oldC, c *CF, z *Zone) error {
	ns := *st
	ns.Zone = z
	var undo []func()
	fail := func(err error) error {
		for i := len(undo) - 1; i >= 0; i-- {
			undo[i]()
		}
		return err
	}
	// 子域名先都问完，再动 Cloudflare
	if st.TLS != nil {
		mid := randLabel(5) + "." + z.Name
		host, bk := cfPickHostUnder(&ns, c, "节点域名", mid)
		ns.TLS = &TLSHost{Host: host, CertName: "*." + mid, Backup: bk}
	}
	if st.WS != nil {
		if c.Token != "" {
			if err := c.checkWSRules(z.ID); err != nil {
				return err
			}
		}
		host, bk := cfPickHostUnder(&ns, c, "WS 域名", z.Name)
		w := *st.WS
		w.Host, w.RecordID, w.Backup = host, "", bk
		ns.WS = &w
	}
	if t := ns.TLS; t != nil {
		id, err := dnsPut(&ns, c, t.Host, false)
		if err != nil {
			dnsDrop(&ns, c, t.Host, "", t.Backup)
			return fail(fmt.Errorf("添加解析 %s 失败：%v", t.Host, err))
		}
		t.RecordID = id
		undo = append(undo, func() { dnsDrop(&ns, c, t.Host, t.RecordID, t.Backup) })
		ok("解析 %s → %s（仅 DNS）", t.Host, st.srvAddr())
	}
	if w := ns.WS; w != nil {
		id, err := dnsPut(&ns, c, w.Host, true)
		if err != nil {
			dnsDrop(&ns, c, w.Host, "", w.Backup)
			return fail(fmt.Errorf("添加解析 %s 失败：%v", w.Host, err))
		}
		w.RecordID = id
		undo = append(undo, func() { dnsDrop(&ns, c, w.Host, w.RecordID, w.Backup) })
		ok("解析 %s → %s（CF 代理）", w.Host, st.srvAddr())
		undo = append(undo, func() {
			c.RuleRemove(z.ID, "http_request_origin", rulePrefix+w.Host)
			c.RuleRemove(z.ID, "http_config_settings", rulePrefix+w.Host)
		})
		if err := wsRulesPut(&ns, c); err != nil {
			return fail(err)
		}
		ok("CF 回源规则：%s → 端口 %d，SSL 只对这个子域名用 Flexible", w.Host, w.PubPort)
	}
	var chain, key []byte
	if ns.TLS != nil {
		info("申请证书 %s（DNS 验证，大概半分钟）", ns.TLS.CertName)
		var err error
		if chain, key, err = obtainCert(&ns, c); err != nil {
			return fail(fmt.Errorf("证书申请失败：%v", err))
		}
		ok("证书已签发")
	}
	// 都备齐了，切过去
	prevCur := cfCur
	oldRaw, oldErr := os.ReadFile(cfPath)
	if err := cfWrite(c); err != nil {
		return fail(err)
	}
	if chain != nil {
		if err := saveCert(chain, key); err != nil {
			if oldErr == nil {
				writeFileAtomic(cfPath, oldRaw, 0600)
			} else {
				os.Remove(cfPath)
			}
			cfCur = prevCur
			return fail(fmt.Errorf("证书保存失败：%v", err))
		}
	}
	ok("Cloudflare 凭据已保存")
	old := *st
	st.Zone, st.TLS, st.WS = ns.Zone, ns.TLS, ns.WS
	applyAll(st)
	ok("节点已经搬到 %s", z.Name)
	zoneCleanup(&old, oldC, c)
	return nil
}

// 旧域名上 dun 加的解析和规则删掉，原来被覆盖的解析放回去；凭据管不了旧域名，就列出来让用户自己删
func zoneCleanup(old *State, cs ...*CF) []string {
	var c *CF
	for _, x := range cs {
		if x == nil {
			continue
		}
		if _, err := x.DNSList(old.Zone.ID, old.Zone.Name); err == nil {
			c = x
			break
		}
	}
	var left []string
	if w := old.WS; w != nil {
		if c == nil || c.RuleRemove(old.Zone.ID, "http_request_origin", rulePrefix+w.Host) != nil ||
			c.RuleRemove(old.Zone.ID, "http_config_settings", rulePrefix+w.Host) != nil {
			left = append(left, fmt.Sprintf("回源规则和配置规则「%s」", rulePrefix+w.Host))
		}
		if c == nil || dnsDrop(old, c, w.Host, w.RecordID, w.Backup) != nil {
			left = append(left, "解析 "+w.Host)
		}
	}
	if t := old.TLS; t != nil {
		if c == nil || dnsDrop(old, c, t.Host, t.RecordID, t.Backup) != nil {
			left = append(left, "解析 "+t.Host)
		}
	}
	if len(left) == 0 {
		ok("旧域名 %s 上 dun 加的解析和规则已经删掉", old.Zone.Name)
		return nil
	}
	warn("旧域名 %s 上这些没删掉，要自己去 CF 后台删：", old.Zone.Name)
	for _, l := range left {
		info("%s", l)
	}
	return left
}
