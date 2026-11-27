package main

import (
	"fmt"
	mrand "math/rand/v2"
	"net"
	"net/http"
	"net/url"
	"os"
	"runtime"
	"strings"
	"time"
)

func protoLabel(k string) string {
	return map[string]string{"reality": "Reality 偷自己", "anytls": "AnyTLS", "ws": "CF WS", "hy2": "Hysteria2"}[k]
}

func pickProto(st *State) string {
	var ks []string
	if st.Reality != nil {
		ks = append(ks, "reality")
	}
	if st.AnyTLS != nil {
		ks = append(ks, "anytls")
	}
	if st.WS != nil {
		ks = append(ks, "ws")
	}
	if st.Hy2 != nil {
		ks = append(ks, "hy2")
	}
	if len(ks) == 0 {
		warn("还没装任何协议")
		return ""
	}
	var ls []string
	for _, k := range ks {
		ls = append(ls, protoLabel(k))
	}
	i := choose(ls, 1)
	if i < 0 {
		return ""
	}
	return ks[i]
}

func showLinks(st *State) {
	if !st.installed() {
		warn("还没装任何协议")
		return
	}
	if st.WS != nil && len(loadWetest().Items) == 0 && !st.CFIP.NoWetest {
		refreshWetest(st)
	}
	var b strings.Builder
	var qrs []string
	if base := subBase(st); base != "" {
		b.WriteString("【订阅】v2rayN / Shadowrocket / NekoBox / 小火箭\n" + base + "/sub\n\n")
		b.WriteString("【订阅】Clash Verge / FlClash / mihomo\n" + base + "/clash\n\n")
		qrs = append(qrs, base+"/sub")
	}
	base := nodeName()
	if st.Reality != nil {
		l := linkReality(st, base+"-Reality")
		b.WriteString("【Reality 偷自己】直连，速度最好\n" + l + "\n\n")
		qrs = append(qrs, l)
	}
	if st.AnyTLS != nil {
		l := linkAnyTLS(st, base+"-AnyTLS")
		b.WriteString("【AnyTLS】直连，客户端要支持 AnyTLS\n" + l + "\n\n")
		qrs = append(qrs, l)
	}
	if st.WS != nil {
		l := linkWS(st, CFAddr{Addr: st.WS.Host, Port: 443, Name: base + "-CF-WS"})
		b.WriteString("【CF WS】走 Cloudflare，IP 被墙也能用\n" + l + "\n")
		b.WriteString(fmt.Sprintf("订阅里另外带了 %d 个优选地址的 CF WS 节点\n\n", len(cfAddrs(st))))
		qrs = append(qrs, l)
	}
	if st.Hy2 != nil {
		l := linkHy2(st, base+"-Hy2")
		if st.Hy2.HopStart > 0 {
			b.WriteString("【Hysteria2】UDP，gecko 混淆 + 端口跳跃，线路差的机器用\n" + l + "\n")
			b.WriteString(fmt.Sprintf("端口跳跃 %d-%d，订阅里已经带上\n", st.Hy2.HopStart, st.Hy2.HopEnd))
		} else {
			b.WriteString("【Hysteria2】UDP，gecko 混淆，单端口，线路差的机器用\n" + l + "\n")
		}
		b.WriteString(hy2ClientHint + "\n")
		b.WriteString("\n")
		qrs = append(qrs, l)
	}

	writeFileAtomic(linksPath, []byte(b.String()), 0600)
	hr()
	fmt.Print(b.String())
	hr()
	if confirm("显示二维码？", false) {
		for _, s := range qrs {
			fmt.Println(s[:min(len(s), 60)] + "…")
			printQR(s)
			fmt.Println()
		}
	}
	info("链接也存在 %s", linksPath)
	if st.PortMode == portMapped {
		info("链接里用的是你填的外网端口")
	}
	info("甲骨文、谷歌云、AWS 这类机器，记得在云后台的安全组也放行端口")
}

func showMihomo(st *State) {
	if !st.installed() {
		warn("还没装任何协议")
		return
	}
	if base := subBase(st); base != "" {
		info("Clash 客户端直接导入订阅更省事：%s/clash", base)
	}
	fmt.Print(subClash(st))
}

func changePort(st *State) {
	k := pickProto(st)
	if k == "" {
		return
	}
	oldPort, oldPub := curPorts(st, k)
	var port int
	if k == "hy2" {
		port = askUDPPort(st, oldPort)
	} else {
		port = askPort(st, protoLabel(k)+" 新端口", oldPort, k)
	}
	addrs, _ := net.InterfaceAddrs()
	st.PortMode = selectPortMode(st, addrs)
	pub := port
	if st.PortMode == portMapped && port == oldPort && oldPub > 0 {
		pub = oldPub
	}
	pub = askPubPort(st, pub)
	switch k {
	case "hy2":
		st.Hy2.Port, st.Hy2.PubPort = port, pub
		fwOpenProto(fmt.Sprint(port), "udp")
		setHy2Range(st.Hy2, st.PortMode)
		if st.Hy2.HopStart > 0 {
			fwOpenProto(fmt.Sprintf("%d:%d", st.Hy2.HopStart, st.Hy2.HopEnd), "udp")
			info("云安全组请放行 UDP %d 和 %d-%d", pub, st.Hy2.HopStart, st.Hy2.HopEnd)
		}
		applyAll(st)
		ok("Hy2 监听 UDP %d，外网端口 %d", port, pub)
		return

	case "reality":
		st.Reality.Port, st.Reality.PubPort = port, pub
	case "anytls":
		st.AnyTLS.Port, st.AnyTLS.PubPort = port, pub
	case "ws":
		st.WS.Port, st.WS.PubPort = port, pub
	}
	fwOpen(port)
	applyAll(st)
	if k == "ws" {
		wsRules(st, cfLogin())
		ok("CF 回源端口已同步成 %d；客户端还是连 CF 的 443，链接不用换", pub)
		return
	}
	ok("端口已改成 %d，订阅会自动更新，单独导入的链接要重新导入", port)
}

func resetSecret(st *State) {
	k := pickProto(st)
	if k == "" {
		return
	}
	switch k {
	case "reality":
		st.Reality.PrivateKey, st.Reality.PublicKey = realityKeys()
		st.Reality.UUID, st.Reality.ShortID = newUUID(), randHex(8)
	case "anytls":
		st.AnyTLS.Password, st.AnyTLS.Padding = newUUID(), randPadding()
	case "ws":
		st.WS.UUID, st.WS.Path = newUUID(), "/"+randLabel(10)
	case "hy2":
		fresh := newHy2(st.Hy2.Port, st.Hy2.PubPort)
		fresh.HopStart, fresh.HopEnd = st.Hy2.HopStart, st.Hy2.HopEnd
		st.Hy2 = fresh
	}
	applyAll(st)
	ok("%s 的凭据已重置，旧链接作废", protoLabel(k))
	showLinks(st)
}

func removeOne(st *State) {
	k := pickProto(st)
	if k == "" || !confirm("确定卸载 "+protoLabel(k)+"？", false) {
		return
	}
	map[string]func(*State){"reality": removeReality, "anytls": removeAnyTLS, "ws": removeWS,
		"hy2": removeHy2}[k](st)
}

func serviceMenu() {
	i := choose([]string{"重启", "停止", "启动", "看最近日志", "实时日志（Ctrl+C 退出）"}, 1)
	switch i {
	case 0, 2:
		for _, s := range activeSvcs() {
			svcDo("restart", s)
		}
		ok("已重启")
	case 1:
		for _, s := range activeSvcs() {
			svcDo("stop", s)
		}
		ok("已停止，开机还会自动启动；要彻底停用就卸载")
	case 3:
		svcLog(80, false)
	case 4:
		svcLog(30, true)
	}
}

func disguiseMenu(st *State) {
	if st.Reality == nil && st.WS == nil {
		warn("伪装站是给 Reality 和 CF WS 用的，先装其中一个")
		return
	}
	cur := "伪装登录页"
	if st.Disguise.Mode == "proxy" {
		cur = "反代 " + st.Disguise.URL
	}
	info("现在：%s", cur)
	info("别人直接打开你的域名，看到的就是这个页面")
	i := choose([]string{"伪装登录页（默认）", "反代一个网站", "换一个登录页样式（重新随机）"}, 1)
	switch i {
	case 0:
		st.Disguise = Disguise{Seed: st.Disguise.Seed}
	case 2:
		st.Disguise = Disguise{Seed: mrand.Uint64() | 1}
	case 1:
		for {
			raw := strings.TrimSpace(ask("要反代的网址，比如 https://www.example.com", ""))
			if !strings.Contains(raw, "://") {
				raw = "https://" + raw
			}
			u, err := url.Parse(raw)
			if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") {
				warn("网址格式不对")
				continue
			}
			raw = u.Scheme + "://" + u.Host
			if u.Path != "" && u.Path != "/" {
				info("只反代整个站点，路径 %s 会去掉", u.Path)
			}
			info("测试能不能打开 %s", raw)
			req, _ := http.NewRequest("GET", raw, nil)
			req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0 Safari/537.36")
			resp, err := (&http.Client{Timeout: 10 * time.Second}).Do(req)
			if err != nil {
				warn("打不开：%v", err)
				if !confirm("还是要用它？", false) {
					continue
				}
			} else {
				resp.Body.Close()
				if resp.StatusCode >= 400 {
					warn("能连上，但对方返回 %d，访客看到的可能也是这个错误页", resp.StatusCode)
				} else {
					ok("能打开，状态码 %d", resp.StatusCode)
				}
			}
			st.Disguise = Disguise{Mode: "proxy", URL: raw, Seed: st.Disguise.Seed}
			break
		}
	default:
		return
	}
	applyAll(st)
	ok("伪装站已切换")
}

func cfipMenu(st *State) {
	if st.WS == nil {
		warn("优选地址是给 CF WS 用的，先装 CF WS")
		return
	}
	for {
		wc := loadWetest()
		onoff := func(b bool) string {
			if b {
				return "开"
			}
			return "关"
		}
		upd := "从没刷新过"
		if !wc.Time.IsZero() {
			upd = wc.Time.Local().Format("01-02 15:04")
		}
		fmt.Fprintf(os.Stderr, "  wetest 优选 IP：%s，%d 个，更新于 %s\n", onoff(!st.CFIP.NoWetest), len(wc.Items), upd)
		nd := len(builtinDomains)
		if wc.Checked {
			nd = len(wc.Domains)
		}
		fmt.Fprintf(os.Stderr, "  内置优选域名：%s，%d/%d 个能用   IPv6 优选：%s   自选：%d 个\n",
			onoff(!st.CFIP.NoDomains), nd, len(builtinDomains), onoff(st.CFIP.V6), len(customAddrs()))
		fmt.Fprintf(os.Stderr, "  订阅里一共 %d 个 CF WS 节点，每 3 小时自动刷新\n", len(cfAddrs(st))+1)
		i := choose([]string{"立即刷新", "查看全部优选地址", "添加自选地址", "清空自选地址",
			"开关 wetest 优选 IP", "开关 内置优选域名", "开关 IPv6 优选 IP", "重置订阅地址（旧订阅失效）"}, 1)
		switch i {
		case -1:
			return
		case 0:
			if n, err := refreshWetest(st); err != nil {
				warn("刷新失败：%v", err)
			} else {
				ok("拉到 %d 个优选 IP", n)
			}
		case 1:
			for _, a := range cfAddrs(st) {
				fmt.Printf("  %-42s %-5d %s\n", a.Addr, a.Port, a.Name)
			}
		case 2:
			info("一行一个，格式：地址[:端口][#备注]，比如 104.16.1.1:2053#家里最快。空行结束")
			info("CF 能用的 HTTPS 端口：443 2053 2083 2087 2096 8443")
			f, _ := os.OpenFile(customPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
			n := 0
			for {
				l := ask("地址", "")
				if l == "" {
					break
				}
				a, good := parseAddr(l)
				if !good {
					warn("格式不对，跳过")
					continue
				}
				if !strings.Contains(" 443 2053 2083 2087 2096 8443 ", fmt.Sprintf(" %d ", a.Port)) {
					warn("端口 %d 不是 CF 的 HTTPS 端口，大概率连不上，还是加上了", a.Port)
				}
				fmt.Fprintln(f, l)
				n++
			}
			f.Close()
			ok("加了 %d 个，订阅马上生效", n)
		case 3:
			os.Remove(customPath)
			ok("已清空")
		case 4:
			st.CFIP.NoWetest = !st.CFIP.NoWetest
			st.save()
		case 5:
			st.CFIP.NoDomains = !st.CFIP.NoDomains
			st.save()
		case 6:
			st.CFIP.V6 = !st.CFIP.V6
			st.save()
			refreshWetest(st)
		case 7:
			st.Token = randLabel(16)
			applyAll(st)
			ok("新订阅地址：%s/sub", subBase(st))
		}
	}
}

func syncIP(st *State) {
	o4, o6 := st.IP4, st.IP6
	detectIP(st)
	info("公网 IP：%s %s", st.IP4, st.IP6)
	if o4 == st.IP4 && o6 == st.IP6 && !confirm("IP 没变，还要重写解析？", false) {
		return
	}
	c := cfLogin()
	if st.TLS != nil {
		st.TLS.RecordID = dnsSet(st, c, st.TLS.Host, false)
		ok("%s 已指向新 IP", st.TLS.Host)
	}
	if st.WS != nil {
		st.WS.RecordID = dnsSet(st, c, st.WS.Host, true)
		ok("%s 已指向新 IP", st.WS.Host)
	}
	st.save()
	showLinks(st)
}

func updateCore(st *State) {
	cur, latest := sbVersion(), ghLatest("SagerNet/sing-box")
	if latest == "" {
		warn("拿不到最新版本号")
		return
	}
	if cur == latest && !confirm("已经是最新 "+cur+"，还要重装？", false) {
		return
	}
	sbInstall(latest)
	if _, n := sbConfig(st); n > 0 {
		out, err := runOut(sbBin, "check", "-c", sbConf)
		if err == nil {
			svcDo("restart", svcBox)
			time.Sleep(2 * time.Second)
		}
		if err != nil || !svcActive(svcBox) {
			warn("新版本跑不起来，回退到 %s\n%s", cur, out)
			os.Rename(sbBin+".old", sbBin)
			svcDo("restart", svcBox)
			return
		}
	}
	os.Remove(sbBin + ".old")
	ok("sing-box 已更新到 %s", latest)
}

func updateSelf() {
	latest := ghLatest(repo)
	if latest == "" {
		warn("拿不到 dun 的最新版本")
		return
	}
	if latest == version && !confirm("已经是最新 "+version+"，还要重装？", false) {
		return
	}
	u := fmt.Sprintf("https://github.com/%s/releases/download/v%s/dun-linux-%s", repo, latest, runtime.GOARCH)
	if err := download(u, selfPath+".new", 0755); err != nil {
		warn("下载失败：%v", err)
		return
	}
	if out, err := runOut(selfPath+".new", "version"); err != nil || !strings.Contains(out, latest) {
		os.Remove(selfPath + ".new")
		warn("新版本跑不起来，没换")
		return
	}
	os.Rename(selfPath+".new", selfPath)
	runTTY(selfPath, "apply")
	ok("dun 已更新到 %s，重新输入 dun 打开", latest)
	os.Exit(0)
}

func uninstallAll(st *State) {
	if !confirm("卸载全部协议，删掉解析、CF 规则、证书和 sing-box？", false) {
		return
	}
	if (st.TLS != nil || st.WS != nil) && cfLoad() == nil {
		warn("没有 CF 凭据，CF 上的解析和规则要自己删")
	}
	if st.Hy2 != nil {
		removeHy2(st)
	}
	if st.WS != nil {
		removeWS(st)
	}
	if st.AnyTLS != nil {
		removeAnyTLS(st)
	}
	if st.Reality != nil {
		removeReality(st)
	}
	for _, o := range st.Outbounds {
		warpUnregister(o)
	}
	for _, s := range []string{svcBox, svcWeb} {
		svcDisable(s)
		os.Remove("/etc/systemd/system/" + s + ".service")
		os.Remove("/etc/init.d/" + s)
		os.Remove("/var/log/" + s + ".log")
	}
	if initSys == "systemd" {
		run("systemctl", "daemon-reload")
	}
	fwCleanup()
	os.RemoveAll(baseDir)
	os.Remove(selfPath)
	ok("已全部卸载，BBR 设置保留")
	os.Exit(0)
}

func statusLine(st *State) {
	run := func(n string) string {
		if svcActive(n) {
			return "\033[32m运行中\033[0m"
		}
		return "\033[33m未运行\033[0m"
	}
	p := func(installed bool, s string) string {
		if installed {
			return s
		}
		return "未装"
	}
	fmt.Printf("  sing-box %s %s   dun 服务 %s\n", sbVersion(), run(svcBox), run(svcWeb))
	r, a, w := "", "", ""
	if st.Reality != nil {
		r = fmt.Sprintf("端口 %d", st.Reality.Port)
	}
	if st.AnyTLS != nil {
		a = fmt.Sprintf("端口 %d", st.AnyTLS.Port)
	}
	if st.WS != nil {
		w = st.WS.Host
	}
	fmt.Printf("  Reality 偷自己: %s   AnyTLS: %s   CF WS: %s\n", p(st.Reality != nil, r), p(st.AnyTLS != nil, a), p(st.WS != nil, w))
	h := ""
	if st.Hy2 != nil {
		h = fmt.Sprintf("UDP %d", st.Hy2.Port)
		if st.Hy2.HopStart > 0 {
			h += fmt.Sprintf("（跳跃 %d-%d）", st.Hy2.HopStart, st.Hy2.HopEnd)
		}
	}
	fmt.Printf("  Hysteria2: %s\n", p(st.Hy2 != nil, h))
	if st.TLS != nil {
		fmt.Printf("  节点域名: %s\n", st.TLS.Host)
	}
	if st.Reality != nil || st.WS != nil {
		d := "伪装登录页"
		if st.Disguise.Mode == "proxy" {
			d = "反代 " + st.Disguise.URL
		}
		fmt.Printf("  伪装站: %s\n", d)
	}
	if len(st.Outbounds) > 0 || len(st.Rules) > 0 {
		var ns []string
		for i, o := range st.Outbounds {
			if i == 3 {
				ns = append(ns, fmt.Sprintf("等 %d 个", len(st.Outbounds)))
				break
			}
			ns = append(ns, o.Name)
		}
		if len(ns) == 0 {
			ns = []string{"无"}
		}
		fmt.Printf("  出站分流: 出站 %s，%d 条规则，其他流量 → %s\n", strings.Join(ns, "、"), len(st.Rules), outLabel(finalOut(st)))
	}
}

func menu(st *State) {
	for {
		fmt.Print("\033[H\033[2J")
		fmt.Printf("════════════════ dun %s ════════════════\n", version)
		statusLine(st)
		fmt.Print(`────────────────────────────────────────────
  1. 安装 Reality 偷自己
  2. 安装 AnyTLS
  3. 安装 CF WS（套 Cloudflare）
  4. 三个一起装
  5. 安装 Hysteria2（UDP，线路差的机器用）
────────────────────────────────────────────
  6. 查看订阅和节点链接
  7. 查看 mihomo / Clash 配置
  8. 优选地址和订阅
  9. 伪装站：登录页 / 反代网站
 10. 修改端口
 11. 重置密码 / UUID
 12. 卸载单个协议
 13. 服务：重启 / 停止 / 日志
 14. 更新 sing-box
 15. 开启 BBR
 16. IP 变了：同步解析
 17. 更换节点域名
 18. 更换 Cloudflare 凭据 / 域名
 19. 更新 dun
 20. 全部卸载
────────────────────────────────────────────
 21. 出站分流：WARP、落地代理
  0. 退出
`)
		switch ask("请选择", "") {
		case "1":
			installReality(st)
			showLinks(st)
		case "2":
			installAnyTLS(st)
			showLinks(st)
		case "3":
			installWS(st)
			showLinks(st)
		case "4":
			installReality(st)
			installAnyTLS(st)
			installWS(st)
			showLinks(st)
		case "5":
			installHy2(st)
			showLinks(st)
		case "6":
			showLinks(st)
		case "7":
			showMihomo(st)
		case "8":
			cfipMenu(st)
		case "9":
			disguiseMenu(st)
		case "10":
			changePort(st)
		case "11":
			resetSecret(st)
		case "12":
			removeOne(st)
		case "13":
			serviceMenu()
		case "14":
			updateCore(st)
		case "15":
			enableBBR()
		case "16":
			syncIP(st)
		case "17":
			changeNodeHost(st)
			showLinks(st)
		case "18":
			changeCF(st)
		case "19":
			updateSelf()
		case "20":
			uninstallAll(st)
		case "21":
			routeMenu(st)
			continue
		case "0", "q":
			return
		default:
			continue
		}
		pause()
	}
}

func activeSvcs() []string {
	st := loadState()
	var ss []string
	if _, n := sbConfig(st); n > 0 {
		ss = append(ss, svcBox)
	}
	if st.installed() {
		ss = append(ss, svcWeb)
	}
	return ss
}
