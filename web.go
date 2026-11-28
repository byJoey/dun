package main

import (
	"crypto/tls"
	_ "embed"
	"fmt"
	"io"
	"log"
	"math/rand/v2"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
)

//go:embed login.html
var loginHTML []byte

var quietLog = log.New(io.Discard, "", 0)

// 证书文件变了就重新读，续期后不用重启
type certHolder struct {
	mu   sync.Mutex
	mod  time.Time
	cert *tls.Certificate
}

func (h *certHolder) get(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	fi, err := os.Stat(certFile)
	if err != nil {
		return nil, err
	}
	if h.cert == nil || !fi.ModTime().Equal(h.mod) {
		c, err := tls.LoadX509KeyPair(certFile, keyFile)
		if err != nil {
			return nil, err
		}
		h.cert, h.mod = &c, fi.ModTime()
	}
	return h.cert, nil
}

func loginHandler(seed uint64) http.Handler {
	pg := buildLogin(seed)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == pg.endpoint && r.Method == http.MethodPost:
			time.Sleep(time.Duration(400+rand.IntN(600)) * time.Millisecond)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(pg.status)
			w.Write(pg.body)
		case r.URL.Path == "/favicon.ico" || r.URL.Path == "/robots.txt":
			http.NotFound(w, r)
		case r.Method != http.MethodGet && r.Method != http.MethodHead:
			w.WriteHeader(http.StatusMethodNotAllowed)
		default:
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.Header().Set("Cache-Control", "no-cache")
			w.Write(pg.html)
		}
	})
}

func proxyHandler(raw string) http.Handler {
	target, err := url.Parse(raw)
	if err != nil || target.Host == "" {
		return loginHandler(0)
	}
	origin := target.Scheme + "://" + target.Host
	return &httputil.ReverseProxy{
		Rewrite: func(r *httputil.ProxyRequest) {
			r.SetURL(target)
			r.Out.Host = target.Host
			if r.Out.Header.Get("Origin") != "" {
				r.Out.Header.Set("Origin", origin)
			}
			r.Out.Header.Del("Referer")
		},
		ModifyResponse: func(resp *http.Response) error {
			if loc := resp.Header.Get("Location"); strings.HasPrefix(loc, origin) {
				loc = strings.TrimPrefix(loc, origin)
				if loc == "" {
					loc = "/"
				}
				resp.Header.Set("Location", loc)
			}
			resp.Header.Del("Alt-Svc")
			return nil
		},
		ErrorLog: quietLog,
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			w.WriteHeader(http.StatusBadGateway)
			io.WriteString(w, "502 Bad Gateway")
		},
	}
}

func siteHandler(st *State, ws bool) http.Handler {
	var dis http.Handler
	if st.Disguise.Mode == "proxy" {
		dis = proxyHandler(st.Disguise.URL)
	} else {
		dis = loginHandler(st.Disguise.Seed)
	}
	var wsProxy http.Handler
	if ws {
		t, _ := url.Parse(fmt.Sprintf("http://127.0.0.1:%d", st.WS.Inner))
		wsProxy = &httputil.ReverseProxy{
			Rewrite:       func(r *httputil.ProxyRequest) { r.SetURL(t); r.Out.Host = r.In.Host },
			FlushInterval: -1,
			ErrorLog:      quietLog,
		}
	}
	subV, subC := "", ""
	if st.Token != "" {
		subV, subC = "/"+st.Token+"/sub", "/"+st.Token+"/clash"
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// CF WS 的回源端口只回应 Cloudflare，别人直连就当没开过：直接断开，不回任何内容
		if ws {
			host, _, _ := net.SplitHostPort(r.RemoteAddr)
			if !isCFIP(host) {
				if hj, ok := w.(http.Hijacker); ok {
					if c, _, err := hj.Hijack(); err == nil {
						c.Close()
						return
					}
				}
				w.WriteHeader(http.StatusNotFound)
				return
			}
		}
		p := r.URL.Path
		switch {
		case ws && p == st.WS.Path:
			wsProxy.ServeHTTP(w, r)
		case subV != "" && p == subV:
			serveSub(w, false)
		case subC != "" && p == subC:
			serveSub(w, true)
		default:
			dis.ServeHTTP(w, r)
		}
	})
}

// 每次请求现读状态，改了优选设置不用重启
func serveSub(w http.ResponseWriter, clash bool) {
	st := loadState()
	h := w.Header()
	h.Set("Content-Type", "text/plain; charset=utf-8")
	h.Set("Cache-Control", "no-store")
	h.Set("Profile-Update-Interval", "6")
	if clash {
		h.Set("Content-Disposition", "attachment; filename*=UTF-8''dun")
		io.WriteString(w, subClash(st))
		return
	}
	io.WriteString(w, subV2ray(st))
}

func serve() {
	detectOS()
	st := loadState()
	errs := make(chan error, 4)
	if st.Reality != nil && st.TLS != nil {
		ch := &certHolder{}
		srv := &http.Server{
			Handler:           siteHandler(st, false),
			TLSConfig:         &tls.Config{GetCertificate: ch.get, MinVersion: tls.VersionTLS12, NextProtos: []string{"h2", "http/1.1"}},
			ReadHeaderTimeout: 15 * time.Second,
			ErrorLog:          quietLog,
		}
		ln, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", st.Reality.Fallback))
		if err != nil {
			log.Fatalf("伪装站监听失败: %v", err)
		}
		go func() { errs <- srv.ServeTLS(ln, "", "") }()
		// 不碰 80：开机时会和 nginx 这类网站抢端口，抢到了网站就起不来
	}
	if st.Hy2 != nil {
		hopApply(st) // 重启机器后 nat 表是空的，这里补上
	}
	if st.WS != nil {
		srv := &http.Server{Handler: siteHandler(st, true), ReadHeaderTimeout: 15 * time.Second, ErrorLog: quietLog}
		ln, err := net.Listen("tcp", fmt.Sprintf(":%d", st.WS.Port))
		if err != nil {
			log.Fatalf("WS 端口监听失败: %v", err)
		}
		go func() { errs <- srv.Serve(ln) }()
		go wetestLoop()
	}
	go renewLoop()
	go rulesLoop()
	if initSys == "openrc" {
		trimLogs() // 先截再打启动日志，这一行不会被截掉
		go logTrimLoop()
	}
	log.Printf("dun %s 已启动", version)
	if st.Reality == nil && st.WS == nil {
		select {}
	}
	log.Fatal(<-errs)
}

func wetestLoop() {
	for {
		st := loadState()
		if time.Since(loadWetest().Time) > 3*time.Hour {
			if n, err := refreshWetest(st); err != nil {
				log.Printf("优选 IP 刷新失败: %v", err)
			} else {
				log.Printf("优选 IP 已刷新，%d 个", n)
			}
		}
		time.Sleep(30 * time.Minute)
	}
}

func renewLoop() {
	time.Sleep(time.Minute)
	for {
		st := loadState()
		if exp, ok := certExpiry(); ok && st.TLS != nil && st.Zone != nil && time.Until(exp) < 30*24*time.Hour {
			c := cfLoad()
			if c == nil {
				log.Printf("证书快到期了，但没有 CF 凭据，续不了")
			} else if err := issueCert(st, c); err != nil {
				log.Printf("证书续期失败，过几个小时再试: %v", err)
			} else {
				log.Printf("证书已续期")
				if st.AnyTLS != nil || st.Hy2 != nil {
					svcDo("restart", svcBox)
				}
			}
		}
		time.Sleep(12 * time.Hour)
	}
}

// 分流用的规则集每天更新；文件被删了也补回来，sing-box 因为缺文件没起来就拉一把
func rulesLoop() {
	time.Sleep(10 * time.Second)
	for {
		st := loadState()
		if sets := usedSets(st); len(sets) > 0 {
			missing := false
			for _, s := range sets {
				if !exists(ruleFile(s[0], s[1])) {
					missing = true
				}
			}
			if missing {
				if err := ensureRuleSets(st); err != nil {
					log.Printf("规则集下载失败: %v", err)
				} else if st.installed() && !svcActive(svcBox) {
					svcDo("restart", svcBox)
				}
			}
			if n, err := refreshRuleSets(st, 20*time.Hour); err != nil {
				log.Printf("规则集更新失败: %v", err)
			} else if n > 0 {
				log.Printf("规则集已更新 %d 个", n)
			}
		}
		time.Sleep(6 * time.Hour)
	}
}
