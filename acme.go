package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"golang.org/x/crypto/acme"
)

func loadOrNewKey(path string) (*ecdsa.PrivateKey, error) {
	if b, err := os.ReadFile(path); err == nil {
		if blk, _ := pem.Decode(b); blk != nil {
			return x509.ParseECPrivateKey(blk.Bytes)
		}
	}
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	der, _ := x509.MarshalECPrivateKey(k)
	return k, writeFileAtomic(path, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der}), 0600)
}

// 直接问域名的权威 NS，免得公共 DNS 缓存了“不存在”
func waitTXT(name, val string, ns []string) {
	deadline := time.Now().Add(90 * time.Second)
	for time.Now().Before(deadline) {
		for _, s := range ns {
			r := &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
				d := net.Dialer{Timeout: 5 * time.Second}
				return d.DialContext(ctx, "udp", net.JoinHostPort(s, "53"))
			}}
			ctx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
			txts, _ := r.LookupTXT(ctx, name)
			cancel()
			for _, t := range txts {
				if t == val {
					time.Sleep(3 * time.Second)
					return
				}
			}
		}
		time.Sleep(3 * time.Second)
	}
	if len(ns) == 0 {
		time.Sleep(20 * time.Second)
	}
}

// 用 Cloudflare DNS 验证向 Let's Encrypt 申请证书
func issueCert(st *State, c *CF) error {
	chain, key, err := obtainCert(st, c)
	if err != nil {
		return err
	}
	return saveCert(chain, key)
}

// 先写私钥再写证书；证书没写成就把旧私钥放回去，免得两边对不上
func saveCert(chain, key []byte) error {
	oldKey, _ := os.ReadFile(keyFile)
	if err := writeFileAtomic(keyFile, key, 0600); err != nil {
		return err
	}
	if err := writeFileAtomic(certFile, chain, 0644); err != nil {
		if oldKey != nil {
			writeFileAtomic(keyFile, oldKey, 0600)
		}
		return err
	}
	return nil
}

// 只签发，不落盘：换域名时新证书要等别的步骤都成功了才换上
func obtainCert(st *State, c *CF) (chain, key []byte, err error) {
	host := st.TLS.Host
	if st.TLS.CertName != "" {
		host = st.TLS.CertName
	}
	zid := st.Zone.ID
	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Minute)
	defer cancel()

	ak, err := loadOrNewKey(acmeKeyPath)
	if err != nil {
		return nil, nil, err
	}
	cl := &acme.Client{Key: ak, DirectoryURL: acme.LetsEncryptURL}
	if _, err := cl.Register(ctx, &acme.Account{}, acme.AcceptTOS); err != nil && !errors.Is(err, acme.ErrAccountAlreadyExists) {
		return nil, nil, fmt.Errorf("注册 ACME 账号失败: %v", err)
	}
	order, err := cl.AuthorizeOrder(ctx, acme.DomainIDs(host))
	if err != nil {
		return nil, nil, fmt.Errorf("创建订单失败: %v", err)
	}
	for _, u := range order.AuthzURLs {
		z, err := cl.GetAuthorization(ctx, u)
		if err != nil {
			return nil, nil, err
		}
		// 通配符证书的验证记录挂在去掉 *. 的那一级上
		txtName := "_acme-challenge." + z.Identifier.Value
		if z.Status == acme.StatusValid {
			continue
		}
		var ch *acme.Challenge
		for _, x := range z.Challenges {
			if x.Type == "dns-01" {
				ch = x
			}
		}
		if ch == nil {
			return nil, nil, errors.New("CA 没给 dns-01 验证方式")
		}
		val, err := cl.DNS01ChallengeRecord(ch.Token)
		if err != nil {
			return nil, nil, err
		}
		if old, err := c.DNSList(zid, txtName); err == nil {
			for _, r := range old {
				if r.Type == "TXT" {
					c.DNSDelete(zid, r.ID)
				}
			}
		}
		rid, err := c.DNSCreate(zid, DNSRecord{Type: "TXT", Name: txtName, Content: val, TTL: 60, Comment: "dun acme"})
		if err != nil {
			return nil, nil, fmt.Errorf("添加验证记录失败: %v", err)
		}
		waitTXT(txtName, val, st.Zone.NS)
		_, err = cl.Accept(ctx, ch)
		if err == nil {
			_, err = cl.WaitAuthorization(ctx, z.URI)
		}
		c.DNSDelete(zid, rid)
		if err != nil {
			return nil, nil, fmt.Errorf("域名验证没通过: %v", err)
		}
	}
	if order, err = cl.WaitOrder(ctx, order.URI); err != nil {
		return nil, nil, fmt.Errorf("订单没完成: %v", err)
	}
	ck, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	csr, _ := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{DNSNames: []string{host}}, ck)
	ders, _, err := cl.CreateOrderCert(ctx, order.FinalizeURL, csr, true)
	if err != nil {
		return nil, nil, fmt.Errorf("签发失败: %v", err)
	}
	var pemChain strings.Builder
	for _, d := range ders {
		pemChain.Write(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: d}))
	}
	kd, _ := x509.MarshalECPrivateKey(ck)
	return []byte(pemChain.String()), pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kd}), nil
}

func certExpiry() (time.Time, bool) {
	b, err := os.ReadFile(certFile)
	if err != nil {
		return time.Time{}, false
	}
	blk, _ := pem.Decode(b)
	if blk == nil {
		return time.Time{}, false
	}
	c, err := x509.ParseCertificate(blk.Bytes)
	if err != nil {
		return time.Time{}, false
	}
	return c.NotAfter, true
}
