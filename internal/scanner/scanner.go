
package scanner

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/kitfind/kitfind/internal/dns"
	"github.com/kitfind/kitfind/internal/fingerprint"
	httpmod "github.com/kitfind/kitfind/internal/http"
	"github.com/kitfind/kitfind/internal/ssl"
)


const (
	ModDNS         = "dns"
	ModSSL         = "ssl"
	ModHTTP        = "http"
	ModFingerprint = "fingerprint"
	ModAll         = "all"
)


type Options struct {
	Target       string
	Modules      []string
	Timeout      time.Duration
	DNSResolvers []string
	UserAgent    string
	Verbose      bool
}


func DefaultOptions(target string) Options {
	return Options{
		Target:       target,
		Modules:      []string{ModAll},
		Timeout:      30 * time.Second,
		DNSResolvers: []string{"8.8.8.8:53", "1.1.1.1:53"},
		UserAgent:    "KitFind/1.0 (authorized reconnaissance tool)",
	}
}


type Finding struct {
	Severity    string `json:"severity"` // critical | high | medium | low | info
	Category    string `json:"category"`
	Title       string `json:"title"`
	Description string `json:"description"`
	Remediation string `json:"remediation,omitempty"`
}


type Result struct {
	Target      string                    `json:"target"`
	Domain      string                    `json:"domain"`
	StartedAt   time.Time                 `json:"started_at"`
	Duration    time.Duration             `json:"duration"`
	DNS         *dns.Result               `json:"dns,omitempty"`
	SSL         *ssl.Result               `json:"ssl,omitempty"`
	HTTP        *httpmod.Result           `json:"http,omitempty"`
	Fingerprint *fingerprint.Result       `json:"fingerprint,omitempty"`
	Findings    []Finding                 `json:"findings"`
	RiskScore   int                       `json:"risk_score"`   // 0–100 (higher = more risk)
	RiskGrade   string                    `json:"risk_grade"`   // A–F
	Errors      map[string]string         `json:"errors"`
}


type ProgressFn func(module, msg string)


func Run(ctx context.Context, opts Options, progress ProgressFn) (*Result, error) {
	start := time.Now()
	domain := dns.CleanDomain(opts.Target)

	res := &Result{
		Target:    opts.Target,
		Domain:    domain,
		StartedAt: start,
		Findings:  make([]Finding, 0),
		Errors:    make(map[string]string),
	}

	notify := func(module, msg string) {
		if progress != nil {
			progress(module, msg)
		}
	}

	enabled := func(mod string) bool {
		for _, m := range opts.Modules {
			if m == ModAll || m == mod {
				return true
			}
		}
		return false
	}


	if enabled(ModDNS) {
		notify("dns", "Analysing DNS records...")
		a := dns.NewAnalyzer(opts.DNSResolvers, opts.Timeout)
		dnsRes, err := a.Analyze(ctx, domain)
		if err != nil {
			res.Errors["dns"] = err.Error()
			notify("dns", fmt.Sprintf("Error: %s", err))
		} else {
			res.DNS = dnsRes
			notify("dns", fmt.Sprintf("Found %d records, %d nameservers", len(dnsRes.Records), len(dnsRes.Nameservers)))


			if enabled(ModAll) {
				notify("dns", "Enumerating common subdomains...")
				res.DNS.Subdomains = a.EnumerateSubdomains(ctx, domain)
				notify("dns", fmt.Sprintf("Found %d active subdomains", len(res.DNS.Subdomains)))
			}
		}
	}


	if enabled(ModSSL) {
		notify("ssl", "Inspecting SSL/TLS certificate...")
		sslRes, err := ssl.Inspect(ctx, domain, opts.Timeout)
		if err != nil {
			res.Errors["ssl"] = err.Error()
			notify("ssl", fmt.Sprintf("Error: %s", err))
		} else {
			res.SSL = sslRes
			notify("ssl", fmt.Sprintf("TLS %s  Grade: %s  Expires: %d days",
				sslRes.TLSVersion, sslRes.Grade, sslRes.Certificate.DaysUntilExpiry))
			addSSLFindings(res, sslRes)
		}
	}


	if enabled(ModHTTP) {
		notify("http", "Analysing HTTP security headers...")
		httpRes, err := httpmod.Analyze(ctx, opts.Target, opts.Timeout, opts.UserAgent)
		if err != nil {
			res.Errors["http"] = err.Error()
			notify("http", fmt.Sprintf("Error: %s", err))
		} else {
			res.HTTP = httpRes
			notify("http", fmt.Sprintf("Status %d  Score: %d/100  Cookies: %d",
				httpRes.StatusCode, httpRes.SecurityScore, len(httpRes.Cookies)))
			addHTTPFindings(res, httpRes)
		}
	}


	if enabled(ModFingerprint) {
		notify("fingerprint", "Detecting technologies...")
		if res.HTTP != nil {
			headers := make(map[string]string)
			for k, v := range res.HTTP.Headers {
				if len(v) > 0 {
					headers[k] = v[0]
				}
			}
			var cookies []string
			for _, c := range res.HTTP.Cookies {
				cookies = append(cookies, c.Name)
			}
			fp := fingerprint.Detect(headers, res.HTTP.Body, cookies)
			res.Fingerprint = fp
			notify("fingerprint", fmt.Sprintf("Detected %d technologies", len(fp.Technologies)))
		} else {
			notify("fingerprint", "Skipped — HTTP module not available")
		}
	}


	res.RiskScore, res.RiskGrade = calcRisk(res)
	res.Duration = time.Since(start)
	return res, nil
}


func addSSLFindings(res *Result, s *ssl.Result) {
	if s.Certificate == nil {
		return
	}
	if s.Certificate.IsExpired {
		res.Findings = append(res.Findings, Finding{
			Severity:    "critical",
			Category:    "SSL/TLS",
			Title:       "Certificate Expired",
			Description: fmt.Sprintf("Certificate expired on %s", s.Certificate.NotAfter.Format("2006-01-02")),
			Remediation: "Renew the SSL certificate immediately.",
		})
	} else if s.Certificate.IsExpiringSoon {
		res.Findings = append(res.Findings, Finding{
			Severity:    "high",
			Category:    "SSL/TLS",
			Title:       "Certificate Expiring Soon",
			Description: fmt.Sprintf("Certificate expires in %d days", s.Certificate.DaysUntilExpiry),
			Remediation: "Renew the SSL certificate before expiry.",
		})
	}
	for _, v := range s.Vulnerabilities {
		res.Findings = append(res.Findings, Finding{
			Severity:    "high",
			Category:    "SSL/TLS",
			Title:       "TLS Vulnerability",
			Description: v,
			Remediation: "Upgrade to TLS 1.2+ and disable legacy cipher suites.",
		})
	}
}


func addHTTPFindings(res *Result, h *httpmod.Result) {
	missingHeaders := map[string]struct {
		sev, title, fix string
	}{
		"Strict-Transport-Security": {
			"medium",
			"Missing HSTS Header",
			"Add: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",
		},
		"Content-Security-Policy": {
			"medium",
			"Missing Content-Security-Policy",
			"Implement a CSP to prevent XSS attacks.",
		},
		"X-Frame-Options": {
			"low",
			"Missing X-Frame-Options",
			"Add: X-Frame-Options: DENY",
		},
		"X-Content-Type-Options": {
			"low",
			"Missing X-Content-Type-Options",
			"Add: X-Content-Type-Options: nosniff",
		},
	}

	for _, check := range h.Checks {
		if !check.Present {
			if info, ok := missingHeaders[check.Name]; ok {
				res.Findings = append(res.Findings, Finding{
					Severity:    info.sev,
					Category:    "HTTP Security",
					Title:       info.title,
					Description: fmt.Sprintf("%s is not set.", check.Name),
					Remediation: info.fix,
				})
			}
		}
	}


	if h.Server != "" && (strings.Contains(h.Server, "/") || hasVersion(h.Server)) {
		res.Findings = append(res.Findings, Finding{
			Severity:    "low",
			Category:    "Information Disclosure",
			Title:       "Server Version Disclosed",
			Description: fmt.Sprintf("Server header reveals: %s", h.Server),
			Remediation: "Configure server to hide version information.",
		})
	}


	if h.PoweredBy != "" {
		res.Findings = append(res.Findings, Finding{
			Severity:    "info",
			Category:    "Information Disclosure",
			Title:       "Technology Stack Disclosed",
			Description: fmt.Sprintf("X-Powered-By: %s", h.PoweredBy),
			Remediation: "Remove the X-Powered-By header.",
		})
	}


	for _, c := range h.Cookies {
		if len(c.Issues) > 0 {
			res.Findings = append(res.Findings, Finding{
				Severity:    "low",
				Category:    "Cookie Security",
				Title:       fmt.Sprintf("Insecure Cookie: %s", c.Name),
				Description: strings.Join(c.Issues, "; "),
				Remediation: "Set Secure, HttpOnly and SameSite=Strict on all sensitive cookies.",
			})
		}
	}
}

func hasVersion(s string) bool {
	for _, c := range s {
		if c >= '0' && c <= '9' {
			return true
		}
	}
	return false
}


func calcRisk(res *Result) (int, string) {
	risk := 0
	for _, f := range res.Findings {
		switch f.Severity {
		case "critical":
			risk += 30
		case "high":
			risk += 15
		case "medium":
			risk += 8
		case "low":
			risk += 3
		case "info":
			risk += 1
		}
	}

	if res.SSL == nil && res.Errors["ssl"] != "" {
		risk += 15
	}

	if risk > 100 {
		risk = 100
	}


	if res.SSL != nil {
		switch res.SSL.Grade {
		case "F":
			risk += 20
		case "C":
			risk += 10
		}
		if risk > 100 {
			risk = 100
		}
	}

	grade := "A"
	switch {
	case risk >= 80:
		grade = "F"
	case risk >= 60:
		grade = "D"
	case risk >= 40:
		grade = "C"
	case risk >= 20:
		grade = "B"
	}
	return risk, grade
}
