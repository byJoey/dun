package main

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	mrand "math/rand/v2"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"strings"
)

func newUUID() string {
	b := make([]byte, 16)
	rand.Read(b)
	b[6] = b[6]&0x0f | 0x40
	b[8] = b[8]&0x3f | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:])
}

func randLabel(n int) string {
	const cs = "abcdefghijklmnopqrstuvwxyz0123456789"
	b := make([]byte, n)
	rand.Read(b)
	for i := range b {
		b[i] = cs[int(b[i])%len(cs)]
	}
	return string(b)
}

func randHex(n int) string { b := make([]byte, n); rand.Read(b); return hex.EncodeToString(b) }

func realityKeys() (string, string) {
	k, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		die("生成 Reality 密钥失败: %v", err)
	}
	e := base64.RawURLEncoding
	return e.EncodeToString(k.Bytes()), e.EncodeToString(k.PublicKey().Bytes())
}

// 官方默认填充方案人人都用，包长分布本身就成了特征；
// 这里每台机器随机生成一份，由服务端下发给客户端
func randPadding() []string {
	r := func(a, b int) int { return a + mrand.IntN(b-a+1) }
	rng := func(lo, hi, minw, maxw int) string {
		a := r(lo, hi)
		return fmt.Sprintf("%d-%d", a, a+r(minw, maxw))
	}
	stop := r(6, 10)
	lines := []string{
		fmt.Sprintf("stop=%d", stop),
		"0=" + rng(20, 70, 10, 90), // 认证包，官方固定 30，抓包里就是固定的 86 字节
		"1=" + rng(90, 300, 80, 300),
	}
	// 2 号包装着内层 ClientHello，多切几段打散
	segs := []string{rng(300, 600, 100, 300)}
	for i, n := 0, r(2, 4); i < n; i++ {
		segs = append(segs, "c", rng(400, 900, 100, 400))
	}
	lines = append(lines, "2="+strings.Join(segs, ","))
	for i := 3; i < stop; i++ {
		seg := rng(200, 900, 100, 500)
		if mrand.IntN(3) == 0 {
			seg += "," + rng(300, 900, 100, 400)
		}
		lines = append(lines, fmt.Sprintf("%d=%s", i, seg))
	}
	return lines
}

func ensureToken(st *State) {
	if st.Token == "" {
		st.Token = randLabel(16)
	}
}

// ── Cloudflare 域名 ──────────────────────────────────
func cfPickZone(st *State, c *CF) {
	if st.Zone != nil {
		return
	}
	zs, err := c.Zones()
	if err != nil {
		die("读取域名列表失败: %v", err)
	}
	if len(zs) == 0 {
		die("这个 CF 账号下没有已激活的域名，先把域名接入 Cloudflare")
	}
	fmt.Fprintln(os.Stderr)
	info("选一个域名：")
	names := []string{}
	for _, z := range zs {
		names = append(names, z.Name)
	}
	i := choose(names, 1)
	if i < 0 {
		die("已取消")
	}
	st.Zone = &Zone{ID: zs[i].ID, Name: zs[i].Name, NS: zs[i].NS}
	st.save()
	ok("域名: %s", st.Zone.Name)
}

var reLabel = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]*[a-z0-9])?$`)

// 选子域名；已有解析时问一句，覆盖前备份，卸载时还原
func cfPickHost(st *State, c *CF, hint string) (string, []DNSRecord) {
	return cfPickHostUnder(st, c, hint, st.Zone.Name)
}

func cfPickHostUnder(st *State, c *CF, hint, parent string) (string, []DNSRecord) {
	for {
		l := strings.ToLower(ask(hint+" 子域名前缀，回车随机", randLabel(6)))
		l = strings.Split(l, ".")[0]
		if !reLabel.MatchString(l) {
			warn("只能用字母、数字和中划线")
			continue
		}
		host := l + "." + parent
		if (st.TLS != nil && st.TLS.Host == host) || (st.WS != nil && st.WS.Host == host) {
			warn("%s 已经被本脚本用了", host)
			continue
		}
		rs, err := c.DNSList(st.Zone.ID, host)
		if err != nil {
			die("查询解析失败: %v", err)
		}
		var bk []DNSRecord
		if len(rs) > 0 {
			var desc []string
			for _, r := range rs {
				desc = append(desc, r.Type+" "+r.Content)
				bk = append(bk, r.DNSRecord)
			}
			warn("%s 已有 %d 条解析：%s", host, len(rs), strings.Join(desc, ", "))
			if !confirm("覆盖它？卸载时会还原", false) {
				continue
			}
		}
		return host, bk
	}
}

func dnsSet(st *State, c *CF, host string, proxied bool) string {
	id, err := dnsPut(st, c, host, proxied)
	if err != nil {
		die("添加解析失败: %v", err)
	}
	return id
}

// 同名的解析先删掉再加自己的；原来有的已经在选子域名时备份了
func dnsPut(st *State, c *CF, host string, proxied bool) (string, error) {
	if rs, err := c.DNSList(st.Zone.ID, host); err == nil {
		for _, r := range rs {
			c.DNSDelete(st.Zone.ID, r.ID)
		}
	}
	rec := DNSRecord{Type: "A", Name: host, Content: st.IP4, Proxied: proxied, TTL: 1, Comment: "dun"}
	if st.IP4 == "" {
		rec.Type, rec.Content = "AAAA", st.IP6
	}
	return c.DNSCreate(st.Zone.ID, rec)
}

// 删掉自己那条解析，再把原来被覆盖的放回去；那条已经不在了也算删掉
func dnsDrop(st *State, c *CF, host, id string, backup []DNSRecord) error {
	if c == nil || st.Zone == nil {
		warn("没有 CF 凭据，%s 的解析请自己去 CF 后台删", host)
		return errors.New("没有 CF 凭据")
	}
	if id != "" {
		var apiErr *cfAPIError
		if err := c.DNSDelete(st.Zone.ID, id); err != nil && !(errors.As(err, &apiErr) && apiErr.status == http.StatusNotFound) {
			return err
		}
	}
	for _, r := range backup {
		if _, err := c.DNSCreate(st.Zone.ID, r); err == nil {
			info("已还原 %s 原有的 %s 解析", host, r.Type)
		}
	}
	return nil
}

func wsRules(st *State, c *CF) {
	if err := wsRulesPut(st, c); err != nil {
		die("%v。补好权限后用菜单 10 重新应用 WS 端口", err)
	}
}

func wsRulesPut(st *State, c *CF) error {
	host, zid := st.WS.Host, st.Zone.ID
	expr := fmt.Sprintf(`(http.host eq "%s")`, host)
	if err := c.RuleUpsert(zid, "http_request_origin", rulePrefix+host, map[string]any{
		"expression": expr, "action": "route",
		"action_parameters": map[string]any{"origin": map[string]any{"port": st.WS.PubPort}},
	}); err != nil {
		return fmt.Errorf("写回源规则失败，使用 Token 时请检查 Origin Rules 的 Edit 权限：%v", err)
	}
	// 只对这个子域名改 SSL 和安全级别，整个域名的设置不动
	if err := c.RuleUpsert(zid, "http_config_settings", rulePrefix+host, map[string]any{
		"expression": expr, "action": "set_config",
		"action_parameters": map[string]any{"ssl": "flexible", "security_level": "essentially_off", "bic": false},
	}); err != nil {
		return fmt.Errorf("写配置规则失败，使用 Token 时请检查 Config Rules 的 Edit 权限：%v", err)
	}
	setting := c.Setting(zid, "websockets")
	if c.Token != "" && setting == "" {
		info("请在 Cloudflare 域名的「网络」页面确认 WebSockets 已开启")
	} else if setting != "on" {
		if c.SetSetting(zid, "websockets", "on") == nil {
			info("已打开 CF 的 WebSockets 开关")
		} else {
			warn("请在 Cloudflare 域名的「网络」页面手动开启 WebSockets")
		}
	}
	return nil
}

// 偷自己、AnyTLS、Hysteria2 共用一个只解析、不走 CF 代理的子域名。
// 证书签成 *.<随机>.<域名>：证书公开日志里只有通配符，扫描器拿不到真正的节点域名
func pickTLSHost(st *State, c *CF) *TLSHost {
	mid := randLabel(5) + "." + st.Zone.Name
	host, bk := cfPickHostUnder(st, c, "节点域名", mid)
	id := dnsSet(st, c, host, false)
	ok("解析 %s → %s（仅 DNS）", host, st.srvAddr())
	return &TLSHost{Host: host, CertName: "*." + mid, RecordID: id, Backup: bk}
}

func tlsHostEnsure(st *State) {
	c := cfLogin()
	if st.TLS == nil {
		cfPickZone(st, c)
		fmt.Fprintln(os.Stderr)
		info("Reality 偷自己、AnyTLS、Hysteria2 共用一个子域名，只做解析，不开 CF 代理")
		st.TLS = pickTLSHost(st, c)
		st.save()
	}
	if _, has := certExpiry(); has {
		return
	}
	info("申请证书 %s（DNS 验证，大概半分钟）", certLabel(st))
	if err := issueCert(st, c); err != nil {
		die("证书申请失败：%v", err)
	}
	ok("证书已签发")
}

func certLabel(st *State) string {
	if st.TLS.CertName != "" {
		return st.TLS.CertName
	}
	return st.TLS.Host
}

// 节点域名被盯上了，或者从老版本的单域名证书升级上来，就换一个
func changeNodeHost(st *State) {
	if st.TLS == nil {
		warn("还没装用节点域名的协议")
		return
	}
	c := cfLogin()
	old := *st.TLS
	info("现在的节点域名：%s，证书：%s", old.Host, certLabel(st))
	fresh := pickTLSHost(st, c)
	st.TLS = fresh
	info("申请证书 %s", fresh.CertName)
	if err := issueCert(st, c); err != nil {
		c.DNSDelete(st.Zone.ID, fresh.RecordID)
		st.TLS = &old
		st.save()
		die("证书申请失败，没换：%v", err)
	}
	applyAll(st)
	dnsDrop(st, c, old.Host, old.RecordID, old.Backup)
	ok("节点域名已换成 %s，旧的解析删了；订阅会自动更新，单独导入的链接要重新导入", fresh.Host)
}

func tlsHostRelease(st *State) {
	if st.needTLS() || st.TLS == nil {
		return
	}
	dnsDrop(st, cfLoad(), st.TLS.Host, st.TLS.RecordID, st.TLS.Backup)
	os.RemoveAll(certDir)
	ok("已删除 %s 的解析和证书", st.TLS.Host)
	st.TLS = nil
	st.save()
}

func zoneRelease(st *State) {
	if st.TLS == nil && st.WS == nil {
		st.Zone = nil
		st.save()
	}
}

// ── 安装 ─────────────────────────────────────────────
func defPort(st *State, want int) int {
	if o := portOwner(want); o != "" && o != "ours" {
		warn("%d 被 %s 占用", want, o)
		return randPort(st)
	}
	if _, u := st.usedPorts("")[want]; u {
		return randPort(st)
	}
	return want
}

func installReality(st *State) {
	if st.Reality != nil {
		warn("Reality 偷自己已经装过了，改端口、换密钥走管理菜单")
		return
	}
	hr()
	info("安装 VLESS + Vision + Reality（偷自己）")
	port := askPort(st, "Reality 监听端口", defPort(st, 443), "reality")
	pub := askPubPort(st, port)
	tlsHostEnsure(st)
	ensureToken(st)
	priv, pubk := realityKeys()
	st.Reality = &Reality{Port: port, PubPort: pub, Fallback: randPort(st, port), UUID: newUUID(),
		PrivateKey: priv, PublicKey: pubk, ShortID: randHex(8)}
	fwOpen(port)
	applyAll(st)
	ok("Reality 偷自己 安装完成")
}

func installAnyTLS(st *State) {
	if st.AnyTLS != nil {
		warn("AnyTLS 已经装过了，改端口、换密码走管理菜单")
		return
	}
	hr()
	info("安装 AnyTLS")
	port := askPort(st, "AnyTLS 监听端口", defPort(st, 443), "anytls")
	pub := askPubPort(st, port)
	tlsHostEnsure(st)
	st.AnyTLS = &AnyTLS{Port: port, PubPort: pub, Password: newUUID(), Padding: randPadding()}
	fwOpen(port)
	applyAll(st)
	ok("AnyTLS 安装完成，填充方案是这台机器随机生成的")
}

func installWS(st *State) {
	if st.WS != nil {
		warn("CF WS 已经装过了，改端口、换 UUID 走管理菜单")
		return
	}
	hr()
	info("安装 VLESS + WS，走 Cloudflare CDN")
	port := askPort(st, "WS 监听端口（CF 回源到这个端口）", randPort(st), "ws")
	pub := askPubPort(st, port)
	c := cfLogin()
	cfPickZone(st, c)
	fmt.Fprintln(os.Stderr)
	if c.Token != "" {
		if err := c.checkWSRules(st.Zone.ID); err != nil {
			die("%v", err)
		}
	}
	info("CF WS 单独用一个子域名，会开 CF 代理（橙云）")
	host, bk := cfPickHost(st, c, "WS 域名")
	ensureToken(st)
	st.WS = &WS{Host: host, Port: port, PubPort: pub, Inner: randPort(st, port), UUID: newUUID(),
		Path: "/" + randLabel(10), Backup: bk}
	fwOpen(port)
	applyAll(st)
	st.WS.RecordID = dnsSet(st, c, host, true)
	st.save()
	ok("解析 %s → %s（CF 代理）", host, st.srvAddr())
	wsRules(st, c)
	ok("CF 回源规则：%s → 端口 %d，SSL 只对这个子域名用 Flexible", host, pub)
	if n, err := refreshWetest(st); err != nil {
		warn("优选 IP 拉取失败，先只用内置优选域名：%v", err)
	} else {
		ok("拉到 %d 个优选 IP", n)
	}
	ok("CF WS 安装完成，新解析生效可能要一两分钟")
}

func removeReality(st *State) {
	if st.Reality == nil {
		warn("Reality 没装")
		return
	}
	st.Reality = nil
	applyAll(st)
	tlsHostRelease(st)
	zoneRelease(st)
	ok("Reality 已卸载")
}

func removeAnyTLS(st *State) {
	if st.AnyTLS == nil {
		warn("AnyTLS 没装")
		return
	}
	st.AnyTLS = nil
	applyAll(st)
	tlsHostRelease(st)
	zoneRelease(st)
	ok("AnyTLS 已卸载")
}

func removeWS(st *State) {
	if st.WS == nil {
		warn("CF WS 没装")
		return
	}
	w := *st.WS
	if c := cfLoad(); c != nil && st.Zone != nil {
		c.RuleRemove(st.Zone.ID, "http_request_origin", rulePrefix+w.Host)
		c.RuleRemove(st.Zone.ID, "http_config_settings", rulePrefix+w.Host)
		dnsDrop(st, c, w.Host, w.RecordID, w.Backup)
		ok("已清理 %s 的解析和 CF 规则", w.Host)
	} else {
		warn("没有 CF 凭据，%s 的解析和规则请自己去 CF 后台删", w.Host)
	}
	st.WS = nil
	applyAll(st)
	os.Remove(wetestPath)
	zoneRelease(st)
	ok("CF WS 已卸载")
}

// UDP 端口里找一段没人用的
func freeUDPRange(width int) (int, int) {
	busy := map[int]bool{}
	for _, f := range []string{"/proc/net/udp", "/proc/net/udp6"} {
		b, _ := os.ReadFile(f)
		for i, line := range strings.Split(string(b), "\n") {
			fs := strings.Fields(line)
			if i == 0 || len(fs) < 4 {
				continue
			}
			if p, err := strconv.ParseUint(fs[1][strings.LastIndex(fs[1], ":")+1:], 16, 32); err == nil {
				busy[int(p)] = true
			}
		}
	}
	for i := 0; i < 50; i++ {
		a := 20000 + mrand.IntN(45000-width)
		clash := false
		for p := a; p < a+width && !clash; p++ {
			clash = busy[p]
		}
		if !clash {
			return a, a + width - 1
		}
	}
	return 0, 0
}

func askUDPPort(st *State, def int) int {
	for {
		p := askInt("Hysteria2 监听端口（UDP）", def, 1, 65535)
		if o := udpOwner(p); o != "" && o != "ours" {
			warn("UDP %d 被 %s 占用，换一个", p, o)
			continue
		}
		return p
	}
}

func randUDPPort() int {
	for i := 0; i < 100; i++ {
		p := 20000 + mrand.IntN(40000)
		if udpOwner(p) == "" {
			return p
		}
	}
	return 0
}

// 密码、混淆包长、跳跃间隔全部随机，每台机器不一样
func newHy2(port, pub int) *Hy2 {
	r := func(a, b int) int { return a + mrand.IntN(b-a+1) }
	h := &Hy2{Port: port, PubPort: pub, Password: randLabel(32), Obfs: randLabel(24), HopSec: r(12, 40)}
	h.MaxPkt = r(1000, 1250)
	h.MinPkt = r(300, h.MaxPkt-250)
	h.CMaxPkt = r(1000, 1250)
	h.CMinPkt = r(300, h.CMaxPkt-250)
	return h
}

func setHy2Range(h *Hy2, mode string) {
	if mode == portMapped {
		h.HopStart, h.HopEnd = 0, 0
		info("使用服务商分配的 UDP 端口，Hy2 走单端口")
	} else if h.HopStart == 0 {
		if hopUsable() {
			h.HopStart, h.HopEnd = freeUDPRange(r2(2000, 6000))
		} else {
			warn("这台机器加不了 iptables 的端口转发规则，Hy2 走单端口")
		}
	}
}

// 端口跳跃靠 iptables 的 nat 规则把一段 UDP 转到 Hy2 端口。没有 iptables 就先装，Alpine 默认就没有；
// 装不上，或者容器不让加 nat 规则，就别分配跳跃范围，免得订阅里带着跳不过去的端口
var hopUsable = func() bool {
	if !have("iptables") {
		info("端口跳跃要用 iptables，先装上")
		pkgs := []string{"iptables"}
		if pkgMgr == "apk" {
			pkgs = append(pkgs, "ip6tables")
		}
		pkgInstall(pkgs...)
	}
	if !have("iptables") {
		return false
	}
	probe := []string{"-t", "nat", "-A", "PREROUTING", "-p", "udp", "--dport", "1", "-m", "comment", "--comment", hopTag + "-probe", "-j", "REDIRECT", "--to-ports", "2"}
	if run("iptables", probe...) != nil {
		return false
	}
	probe[2] = "-D"
	run("iptables", probe...)
	return true
}

const hy2ClientHint = "v2rayNG 2.3.15 导入 Hy2 链接会使用 salamander，连不上 dun 的 gecko 节点。请用支持 gecko 的客户端，例如 mihomo 1.19.34 或 sing-box 1.14 及以上版本。"

func installHy2(st *State) {
	if st.Hy2 != nil {
		warn("Hysteria2 已经装过了，改端口、换密码走管理菜单")
		return
	}
	hr()
	info("安装 Hysteria2：gecko 混淆 + 端口跳跃，参数每台机器随机")
	port := askUDPPort(st, randUDPPort())
	pub := askPubPort(st, port)
	h := newHy2(port, pub)
	setHy2Range(h, st.PortMode)
	tlsHostEnsure(st)
	st.Hy2 = h
	fwOpenProto(fmt.Sprint(port), "udp")
	if h.HopStart > 0 {
		fwOpenProto(fmt.Sprintf("%d:%d", h.HopStart, h.HopEnd), "udp")
	}
	applyAll(st)
	ok("Hysteria2 安装完成")
	info("%s", hy2ClientHint)
	if h.HopStart > 0 {
		ok("端口跳跃：UDP %d-%d 都转到 %d", h.HopStart, h.HopEnd, port)
	}
	info("甲骨文、谷歌云、AWS 这类机器，云后台的安全组要放行 UDP")
}

func r2(a, b int) int { return a + mrand.IntN(b-a+1) }

func removeHy2(st *State) {
	if st.Hy2 == nil {
		warn("Hysteria2 没装")
		return
	}
	st.Hy2 = nil
	applyAll(st)
	tlsHostRelease(st)
	zoneRelease(st)
	ok("Hysteria2 已卸载")
}
