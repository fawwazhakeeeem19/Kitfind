
package http

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)


type HeaderCheck struct {
	Name     string `json:"name"`
	Present  bool   `json:"present"`
	Value    string `json:"value,omitempty"`
	Status   string `json:"status"` // good | warning | missing | bad
	Message  string `json:"message"`
	Score    int    `json:"score"`
}


type CookieCheck struct {
	Name     string   `json:"name"`
	Secure   bool     `json:"secure"`
	HttpOnly bool     `json:"http_only"`
	SameSite string   `json:"same_site"`
	Issues   []string `json:"issues"`
	Score    int      `json:"score"`
}


type CSPCheck struct {
	Value         string            `json:"value"`
	Directives    map[string]string `json:"directives"`
	HasUnsafeInline bool           `json:"has_unsafe_inline"`
	HasUnsafeEval bool             `json:"has_unsafe_eval"`
	HasWildcard   bool             `json:"has_wildcard"`
	Issues        []string          `json:"issues"`
	Score         int               `json:"score"`
}


type Result struct {
	URL           string        `json:"url"`
	FinalURL      string        `json:"final_url"`
	StatusCode    int           `json:"status_code"`
	Server        string        `json:"server,omitempty"`
	PoweredBy     string        `json:"powered_by,omitempty"`
	ContentType   string        `json:"content_type"`
	ResponseTime  time.Duration `json:"response_time"`
	BodySize      int64         `json:"body_size"`
	RedirectChain []string      `json:"redirect_chain"`
	Headers       http.Header   `json:"raw_headers"`
	Checks        []HeaderCheck `json:"security_checks"`
	Cookies       []CookieCheck `json:"cookies"`
	CSP           *CSPCheck     `json:"csp,omitempty"`
	SecurityScore int           `json:"security_score"`
	ScannedAt     time.Time     `json:"scanned_at"`
	Body          string        `json:"-"` // Not serialised — used internally for fingerprinting
}


func Analyze(ctx context.Context, target string, timeout time.Duration, userAgent string) (*Result, error) {
	if !strings.HasPrefix(target, "http") {
		target = "https://" + target
	}

	start := time.Now()
	res := &Result{URL: target, ScannedAt: start}

	var chain []string
	client := &http.Client{
		Timeout: timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			chain = append(chain, req.URL.String())
			if len(via) >= 10 {
				return fmt.Errorf("too many redirects")
			}
			return nil
		},
	}

	req, err := http.NewRequestWithContext(ctx, "GET", target, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", userAgent)

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 5*1024*1024))
	res.Body = string(body)
	res.BodySize = int64(len(body))
	res.ResponseTime = time.Since(start)
	res.StatusCode = resp.StatusCode
	res.FinalURL = resp.Request.URL.String()
	res.Headers = resp.Header
	res.RedirectChain = chain
	res.Server = resp.Header.Get("Server")
	res.PoweredBy = resp.Header.Get("X-Powered-By")
	res.ContentType = resp.Header.Get("Content-Type")

	res.Checks = analyzeHeaders(resp.Header)

	for _, c := range resp.Cookies() {
		res.Cookies = append(res.Cookies, analyzeCookie(c))
	}

	if csp := resp.Header.Get("Content-Security-Policy"); csp != "" {
		res.CSP = analyzeCSP(csp)
	}

	res.SecurityScore = calcScore(res)
	return res, nil
}

func analyzeHeaders(h http.Header) []HeaderCheck {
	checks := []HeaderCheck{
		checkHSTS(h.Get("Strict-Transport-Security")),
		checkCSPHeader(h.Get("Content-Security-Policy")),
		checkXFrame(h.Get("X-Frame-Options")),
		checkXCTO(h.Get("X-Content-Type-Options")),
		checkReferrer(h.Get("Referrer-Policy")),
		checkPermissions(h.Get("Permissions-Policy")),
		checkXXSS(h.Get("X-XSS-Protection")),
		checkCORS(h.Get("Access-Control-Allow-Origin")),
	}
	return checks
}

func checkHSTS(val string) HeaderCheck {
	h := HeaderCheck{Name: "Strict-Transport-Security"}
	if val == "" {
		h.Status, h.Message, h.Score = "missing", "HSTS not set — site vulnerable to SSL stripping", 0
		return h
	}
	h.Present, h.Value = true, val
	maxAge := 0
	for _, part := range strings.Split(val, ";") {
		part = strings.TrimSpace(part)
		if strings.HasPrefix(part, "max-age=") {
			fmt.Sscanf(part, "max-age=%d", &maxAge)
		}
	}
	if maxAge >= 31536000 {
		h.Status, h.Message, h.Score = "good", "HSTS enabled with long max-age", 100
	} else {
		h.Status, h.Message, h.Score = "warning", fmt.Sprintf("HSTS max-age %d too short (recommend ≥ 1 year)", maxAge), 60
	}
	return h
}

func checkCSPHeader(val string) HeaderCheck {
	h := HeaderCheck{Name: "Content-Security-Policy"}
	if val == "" {
		h.Status, h.Message, h.Score = "missing", "CSP missing — XSS protection not enforced", 0
		return h
	}
	h.Present, h.Value, h.Status, h.Message, h.Score = true, val, "good", "CSP header present", 80
	return h
}

func checkXFrame(val string) HeaderCheck {
	h := HeaderCheck{Name: "X-Frame-Options"}
	if val == "" {
		h.Status, h.Message, h.Score = "missing", "Clickjacking protection not set", 0
		return h
	}
	h.Present, h.Value, h.Status, h.Message, h.Score = true, val, "good", "Clickjacking protection enabled", 100
	return h
}

func checkXCTO(val string) HeaderCheck {
	h := HeaderCheck{Name: "X-Content-Type-Options"}
	if val == "" {
		h.Status, h.Message, h.Score = "missing", "MIME sniffing protection not set", 0
		return h
	}
	if !strings.EqualFold(val, "nosniff") {
		h.Present, h.Value, h.Status, h.Message, h.Score = true, val, "warning", "Should be 'nosniff'", 50
		return h
	}
	h.Present, h.Value, h.Status, h.Message, h.Score = true, val, "good", "MIME sniffing disabled", 100
	return h
}

func checkReferrer(val string) HeaderCheck {
	h := HeaderCheck{Name: "Referrer-Policy"}
	if val == "" {
		h.Status, h.Message, h.Score = "warning", "Referrer-Policy not set — browser default applies", 30
		return h
	}
	h.Present, h.Value, h.Status, h.Message, h.Score = true, val, "good", "Referrer policy configured", 90
	return h
}

func checkPermissions(val string) HeaderCheck {
	h := HeaderCheck{Name: "Permissions-Policy"}
	if val == "" {
		h.Status, h.Message, h.Score = "warning", "Permissions-Policy not configured", 30
		return h
	}
	h.Present, h.Value, h.Status, h.Message, h.Score = true, val, "good", "Feature permissions configured", 90
	return h
}

func checkXXSS(val string) HeaderCheck {
	h := HeaderCheck{Name: "X-XSS-Protection"}
	if val == "" {
		h.Status, h.Message, h.Score = "info", "Legacy header not set (use CSP instead)", 50
		return h
	}
	h.Present, h.Value, h.Status, h.Message, h.Score = true, val, "good", "XSS protection set", 70
	return h
}

func checkCORS(val string) HeaderCheck {
	h := HeaderCheck{Name: "Access-Control-Allow-Origin"}
	if val == "" {
		return h
	}
	h.Present, h.Value = true, val
	if val == "*" {
		h.Status, h.Message, h.Score = "warning", "CORS wildcard — allows any origin", 30
	} else {
		h.Status, h.Message, h.Score = "good", "CORS restricted to specific origin", 90
	}
	return h
}

func analyzeCookie(c *http.Cookie) CookieCheck {
	ck := CookieCheck{Name: c.Name, Secure: c.Secure, HttpOnly: c.HttpOnly, SameSite: sameSiteString(c.SameSite)}
	score := 100
	if !c.Secure {
		ck.Issues = append(ck.Issues, "Missing Secure flag")
		score -= 35
	}
	if !c.HttpOnly {
		ck.Issues = append(ck.Issues, "Missing HttpOnly flag — JS-accessible")
		score -= 25
	}
	if c.SameSite == http.SameSiteDefaultMode {
		ck.Issues = append(ck.Issues, "SameSite not set — CSRF risk")
		score -= 20
	}
	if score < 0 {
		score = 0
	}
	ck.Score = score
	return ck
}

func analyzeCSP(policy string) *CSPCheck {
	csp := &CSPCheck{
		Value:      policy,
		Directives: make(map[string]string),
		Score:      100,
	}
	for _, d := range strings.Split(policy, ";") {
		d = strings.TrimSpace(d)
		if d == "" {
			continue
		}
		parts := strings.SplitN(d, " ", 2)
		key := parts[0]
		val := ""
		if len(parts) > 1 {
			val = parts[1]
		}
		csp.Directives[key] = val
		if strings.Contains(val, "'unsafe-inline'") {
			csp.HasUnsafeInline = true
			csp.Issues = append(csp.Issues, key+": 'unsafe-inline' negates XSS protection")
			csp.Score -= 20
		}
		if strings.Contains(val, "'unsafe-eval'") {
			csp.HasUnsafeEval = true
			csp.Issues = append(csp.Issues, key+": 'unsafe-eval' allows code injection")
			csp.Score -= 15
		}
		if strings.Contains(val, " * ") || strings.HasSuffix(val, " *") || val == "*" {
			csp.HasWildcard = true
			csp.Issues = append(csp.Issues, key+": wildcard allows any source")
			csp.Score -= 10
		}
	}
	if csp.Score < 0 {
		csp.Score = 0
	}
	return csp
}

func calcScore(r *Result) int {
	total, sum := 0, 0
	for _, c := range r.Checks {
		if c.Score > 0 || c.Status == "missing" {
			total += 100
			sum += c.Score
		}
	}
	if total == 0 {
		return 0
	}
	return sum * 100 / total
}


func sameSiteString(s http.SameSite) string {
	switch s {
	case http.SameSiteDefaultMode:
		return "Default"
	case http.SameSiteLaxMode:
		return "Lax"
	case http.SameSiteStrictMode:
		return "Strict"
	case http.SameSiteNoneMode:
		return "None"
	default:
		return "Unknown"
	}
}
