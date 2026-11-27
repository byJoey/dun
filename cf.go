package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"slices"
	"strings"
	"time"
)

const cfAPI = "https://api.cloudflare.com/client/v4"

type CF struct {
	Email string `json:"email,omitempty"`
	Key   string `json:"key,omitempty"`
	Token string `json:"token,omitempty"`
}

type cfEnv struct {
	Success bool            `json:"success"`
	Errors  []cfErr         `json:"errors"`
	Result  json.RawMessage `json:"result"`
}

// error_chain 里才是具体原因，比如 6003 只说请求头不对，6103 才说是 Key 的格式不对
type cfErr struct {
	Code    int     `json:"code"`
	Message string  `json:"message"`
	Chain   []cfErr `json:"error_chain"`
}

type cfAPIError struct {
	status  int
	message string
}

func (e *cfAPIError) Error() string { return e.message }

var httpc = &http.Client{Timeout: 30 * time.Second}

func (c *CF) do(method, path string, body any, out any) error {
	var rd *bytes.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	} else {
		rd = bytes.NewReader(nil)
	}
	req, _ := http.NewRequest(method, cfAPI+path, rd)
	if c.Token != "" {
		req.Header.Set("Authorization", "Bearer "+c.Token)
	} else {
		req.Header.Set("X-Auth-Email", c.Email)
		req.Header.Set("X-Auth-Key", c.Key)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := httpc.Do(req)
	if err != nil {
		return fmt.Errorf("连不上 Cloudflare: %v", err)
	}
	defer resp.Body.Close()
	var env cfEnv
	if err := json.NewDecoder(resp.Body).Decode(&env); err != nil {
		return fmt.Errorf("HTTP %d，返回内容解析不了", resp.StatusCode)
	}
	if !env.Success {
		var ms []string
		var codes []int
		for _, e := range env.Errors {
			m := fmt.Sprintf("%d %s", e.Code, e.Message)
			codes = append(codes, e.Code)
			var why []string
			for _, ch := range e.Chain {
				why = append(why, fmt.Sprintf("%d %s", ch.Code, ch.Message))
				codes = append(codes, ch.Code)
			}
			if len(why) > 0 {
				m += "，具体是 " + strings.Join(why, "、")
			}
			ms = append(ms, m)
		}
		if len(ms) == 0 {
			ms = append(ms, fmt.Sprintf("HTTP %d", resp.StatusCode))
		}
		msg := strings.Join(ms, "; ")
		if h := cfHint(codes, c.Token != ""); h != "" {
			msg += "。" + h
		}
		return &cfAPIError{status: resp.StatusCode, message: msg}
	}
	if out != nil && len(env.Result) > 0 {
		return json.Unmarshal(env.Result, out)
	}
	return nil
}

// 常见错误码翻成该怎么改。码是实测出来的：Key 栏贴了 Token 回 6103，邮箱格式不对回 6102，
// Token 栏贴了 Key 或者带了空格回 6111，邮箱和 Key 对不上回 9103，Token 无效回 9109，Token 缺权限回 10000
func cfHint(codes []int, token bool) string {
	has := func(c int) bool { return slices.Contains(codes, c) }
	switch {
	case has(6103):
		return "Global API Key 是 37 位，只有数字和 a 到 f；复制的如果是 API Token，凭据类型选 2"
	case has(6102):
		return "邮箱格式不对，填 Cloudflare 的登录邮箱"
	case has(6111):
		return "API Token 格式不对，看看是不是多复制了空格或别的字符；复制的如果是 Global API Key，凭据类型选 1"
	case has(9103):
		return "邮箱和 Global API Key 对不上：邮箱要填这个账号的登录邮箱，Key 在「查看」后完整复制"
	case token && (has(1000) || has(9109)):
		return "Token 无效或者没有权限：确认 Token 没被删除、没过期、复制完整，区域资源包含节点用的域名"
	case token && (has(10000) || has(10001)):
		return "Token 缺这一步的权限：区域资源要包含节点用的域名，权限要有 Zone Read 和 DNS Edit，装 CF WS 再加 Origin Rules Edit 和 Config Rules Edit"
	case has(10000) || has(10001):
		return "Cloudflare 认得这份凭据，但不让做这一步，确认域名在这个登录邮箱的账号下面"
	}
	return ""
}

func (c *CF) Check() error {
	if c.Token == "" {
		return c.do("GET", "/user", nil, nil)
	}
	// 直接查安装时需要的区域，域名级 Token 不需要读取用户资料。
	zones, err := c.Zones()
	if err != nil {
		return err
	}
	if len(zones) == 0 {
		return errors.New("Token 看不到已激活的域名，请检查指定域名和 Zone Read 权限")
	}
	return nil
}

type cfZone struct {
	ID   string   `json:"id"`
	Name string   `json:"name"`
	NS   []string `json:"name_servers"`
}

func (c *CF) Zones() ([]cfZone, error) {
	var z []cfZone
	err := c.do("GET", "/zones?per_page=50&status=active", nil, &z)
	return z, err
}

type cfRecord struct {
	ID string `json:"id"`
	DNSRecord
}

func (c *CF) DNSList(zid, name string) ([]cfRecord, error) {
	var r []cfRecord
	err := c.do("GET", "/zones/"+zid+"/dns_records?per_page=100&name="+url.QueryEscape(name), nil, &r)
	return r, err
}

func (c *CF) DNSCreate(zid string, rec DNSRecord) (string, error) {
	var r cfRecord
	err := c.do("POST", "/zones/"+zid+"/dns_records", rec, &r)
	return r.ID, err
}

func (c *CF) DNSDelete(zid, id string) error {
	return c.do("DELETE", "/zones/"+zid+"/dns_records/"+id, nil, nil)
}

// 规则集原样读出来，只增删自己那条，别人的规则不碰
func (c *CF) RulesGet(zid, phase string) ([]map[string]any, error) {
	var r struct {
		Rules []map[string]any `json:"rules"`
	}
	err := c.do("GET", "/zones/"+zid+"/rulesets/phases/"+phase+"/entrypoint", nil, &r)
	if err != nil {
		var apiErr *cfAPIError
		if errors.As(err, &apiErr) && apiErr.status == http.StatusNotFound {
			return nil, nil
		}
		return nil, err
	}
	return r.Rules, nil
}

// 先读两个规则集，避免只配了 DNS 的 Token 装到一半才报错。
func (c *CF) checkWSRules(zid string) error {
	for _, rule := range []struct{ phase, permission string }{
		{"http_request_origin", "Origin Rules"},
		{"http_config_settings", "Config Rules"},
	} {
		if _, err := c.RulesGet(zid, rule.phase); err != nil {
			return fmt.Errorf("读取 CF WS 规则失败，请检查目标域名的 %s Edit 权限：%w", rule.permission, err)
		}
	}
	return nil
}

func (c *CF) rulesEdit(zid, phase, desc string, add map[string]any) error {
	rules, err := c.RulesGet(zid, phase)
	if err != nil {
		return err
	}
	kept := []map[string]any{}
	found := false
	for _, r := range rules {
		if d, _ := r["description"].(string); d == desc {
			found = true
			continue
		}
		kept = append(kept, r)
	}
	if add == nil && !found {
		return nil
	}
	if add != nil {
		kept = append(kept, add)
	}
	return c.do("PUT", "/zones/"+zid+"/rulesets/phases/"+phase+"/entrypoint", map[string]any{"rules": kept}, nil)
}

func (c *CF) RuleUpsert(zid, phase, desc string, rule map[string]any) error {
	rule["description"] = desc
	rule["enabled"] = true
	return c.rulesEdit(zid, phase, desc, rule)
}

func (c *CF) RuleRemove(zid, phase, desc string) error { return c.rulesEdit(zid, phase, desc, nil) }

func (c *CF) Setting(zid, name string) string {
	var r struct {
		Value any `json:"value"`
	}
	if c.do("GET", "/zones/"+zid+"/settings/"+name, nil, &r) != nil {
		return ""
	}
	return fmt.Sprint(r.Value)
}

func (c *CF) SetSetting(zid, name string, v any) error {
	return c.do("PATCH", "/zones/"+zid+"/settings/"+name, map[string]any{"value": v}, nil)
}

// ── 凭据 ─────────────────────────────────────────────
var cfCur *CF

func cfLoad() *CF {
	b, err := os.ReadFile(cfPath)
	if err != nil {
		return nil
	}
	c := &CF{}
	if json.Unmarshal(b, c) != nil || !c.valid() {
		return nil
	}
	return c
}

func cfLogin() *CF {
	if cfCur != nil {
		return cfCur
	}
	if c := cfLoad(); c != nil {
		if err := c.Check(); err == nil {
			cfCur = c
			return c
		}
		warn("保存的 CF 账号验证不过了，重新输入一次")
	}
	return cfPrompt(loadState())
}

func (c *CF) valid() bool {
	return c.Token != "" || (c.Email != "" && c.Key != "")
}

var reGlobalKey = regexp.MustCompile(`^[0-9a-fA-F]{37}$`)

// Key 栏贴了 API Token：不像 37 位的 Global API Key，按 Token 又能验证通过，就直接当 Token 用
func cfKeyAsToken(c *CF) (*CF, bool) {
	if c.Key == "" || reGlobalKey.MatchString(c.Key) {
		return c, false
	}
	t := &CF{Token: c.Key}
	if t.Check() != nil {
		return c, false
	}
	return t, true
}

// 问一份凭据，验证通过才返回，不保存
func cfAsk() *CF {
	for {
		info("选择 Cloudflare 凭据：1. 邮箱 + Global API Key   2. API Token")
		c := &CF{}
		if askInt("凭据类型", 1, 1, 2) == 2 {
			info("创建自定义 Token，区域资源只包含节点域名。权限选 Zone → Zone → Read、Zone → DNS → Edit")
			info("安装 CF WS 再加 Zone → Origin Rules → Edit 和 Zone → Config Rules → Edit")
			c.Token = askSecret("API Token（输入时不显示）")
			if reGlobalKey.MatchString(c.Token) {
				info("这串是 37 位的 Global API Key，不是 API Token，再填一下登录邮箱")
				c = &CF{Email: ask("CF 登录邮箱", ""), Key: c.Token}
			}
		} else {
			info("登录 Cloudflare 控制台 https://dash.cloudflare.com/，点右上角头像，再点「设置」。")
			info("在左栏的 User settings 下展开「API 凭据」，点「API 密钥」。")
			info("找到 Global API key 这一行，点右边的「查看」。")
			c.Email = ask("CF 登录邮箱", "")
			c.Key = askSecret("Global API Key（输入时不显示）")
			if t, switched := cfKeyAsToken(c); switched {
				info("这串是 API Token，不是 Global API Key，已经按 Token 用上")
				c = t
			}
		}
		if !c.valid() {
			warn("凭据不能为空")
			continue
		}
		if err := c.Check(); err != nil {
			warn("验证失败：%v。再来一次（Ctrl+C 退出）", err)
			continue
		}
		return c
	}
}

func cfWrite(c *CF) error {
	b, _ := json.Marshal(c)
	if err := writeFileAtomic(cfPath, b, 0600); err != nil {
		return fmt.Errorf("保存 Cloudflare 凭据失败：%v", err)
	}
	cfCur = c
	return nil
}

func cfSave(c *CF) {
	if err := cfWrite(c); err != nil {
		die("%v", err)
	}
	ok("Cloudflare 凭据已保存")
}

// 现有域名要继续用：新凭据管不了它就再问一次
func cfPrompt(st *State) *CF {
	for {
		c := cfAsk()
		if st.Zone != nil && (st.TLS != nil || st.WS != nil) {
			if _, err := c.DNSList(st.Zone.ID, st.Zone.Name); err != nil {
				warn("新凭据无法访问现有域名 %s 的 DNS 记录：%v", st.Zone.Name, err)
				info("换了 Cloudflare 账号、想把节点搬到新账号的域名上，Ctrl+C 退出后进菜单 18")
				continue
			}
			if st.WS != nil && c.Token != "" {
				if err := c.checkWSRules(st.Zone.ID); err != nil {
					warn("%v", err)
					continue
				}
			}
		}
		cfSave(c)
		return c
	}
}
