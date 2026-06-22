
package fingerprint

import (
	"regexp"
	"strings"
)


type Tech struct {
	Name       string `json:"name"`
	Version    string `json:"version,omitempty"`
	Category   string `json:"category"`
	Confidence int    `json:"confidence"` // 0-100
	Icon       string `json:"icon,omitempty"`
}


type Result struct {
	Technologies []Tech            `json:"technologies"`
	Summary      map[string][]string `json:"summary"` // category -> names
}

type sig struct {
	name     string
	category string
	patterns []pat
}

type pat struct {
	source  string // "header", "body", "cookie"
	key     string // header name or cookie prefix
	pattern string
}


func Detect(headers map[string]string, body string, cookies []string) *Result {
	bodyL := strings.ToLower(body)
	res := &Result{
		Technologies: make([]Tech, 0),
		Summary:      make(map[string][]string),
	}

	for _, s := range signatures {
		conf := 0
		var evidences []string

		for _, p := range s.patterns {
			var text string
			switch p.source {
			case "header":
				text = strings.ToLower(headers[p.key])
			case "body":
				text = bodyL
			case "cookie":
				for _, c := range cookies {
					if strings.Contains(strings.ToLower(c), p.key) {
						text = strings.ToLower(c)
						break
					}
				}
			}
			if text == "" {
				continue
			}
			re, err := regexp.Compile("(?i)" + p.pattern)
			if err != nil {
				continue
			}
			if re.MatchString(text) {
				conf += 30
				evidences = append(evidences, p.source)
			}
		}

		if conf > 0 {
			if conf > 100 {
				conf = 100
			}
			t := Tech{
				Name:       s.name,
				Category:   s.category,
				Confidence: conf,
			}
			res.Technologies = append(res.Technologies, t)
			res.Summary[s.category] = append(res.Summary[s.category], s.name)
		}
	}

	return res
}

var signatures = []sig{

	{name: "Nginx", category: "Web Server", patterns: []pat{
		{source: "header", key: "server", pattern: `nginx`},
	}},
	{name: "Apache", category: "Web Server", patterns: []pat{
		{source: "header", key: "server", pattern: `apache`},
	}},
	{name: "IIS", category: "Web Server", patterns: []pat{
		{source: "header", key: "server", pattern: `microsoft-iis`},
	}},
	{name: "Caddy", category: "Web Server", patterns: []pat{
		{source: "header", key: "server", pattern: `caddy`},
	}},
	{name: "Cloudflare", category: "CDN", patterns: []pat{
		{source: "header", key: "cf-ray", pattern: `.+`},
		{source: "header", key: "server", pattern: `cloudflare`},
	}},
	{name: "Fastly", category: "CDN", patterns: []pat{
		{source: "header", key: "x-served-by", pattern: `cache-`},
	}},
	{name: "AWS CloudFront", category: "CDN", patterns: []pat{
		{source: "header", key: "x-amz-cf-id", pattern: `.+`},
	}},

	{name: "WordPress", category: "CMS", patterns: []pat{
		{source: "body", pattern: `wp-content`},
		{source: "body", pattern: `wp-includes`},
		{source: "cookie", key: "wordpress_", pattern: `wordpress_`},
	}},
	{name: "Drupal", category: "CMS", patterns: []pat{
		{source: "body", pattern: `drupal`},
		{source: "header", key: "x-generator", pattern: `drupal`},
	}},
	{name: "Joomla", category: "CMS", patterns: []pat{
		{source: "body", pattern: `/media/jui/`},
	}},
	{name: "Ghost", category: "CMS", patterns: []pat{
		{source: "header", key: "x-ghost-cache-status", pattern: `.+`},
		{source: "body", pattern: `ghost\.org`},
	}},

	{name: "Shopify", category: "E-commerce", patterns: []pat{
		{source: "header", key: "x-shopid", pattern: `.+`},
		{source: "body", pattern: `cdn\.shopify\.com`},
	}},
	{name: "WooCommerce", category: "E-commerce", patterns: []pat{
		{source: "body", pattern: `woocommerce`},
	}},
	{name: "Magento", category: "E-commerce", patterns: []pat{
		{source: "cookie", key: "mage-", pattern: `mage-`},
		{source: "body", pattern: `mage/`},
	}},

	{name: "React", category: "JS Framework", patterns: []pat{
		{source: "body", pattern: `__reactfiber|react\.production\.min\.js|data-reactroot`},
	}},
	{name: "Vue.js", category: "JS Framework", patterns: []pat{
		{source: "body", pattern: `vue\.min\.js|__vue__|v-bind:`},
	}},
	{name: "Angular", category: "JS Framework", patterns: []pat{
		{source: "body", pattern: `ng-version|angular\.min\.js`},
	}},
	{name: "Next.js", category: "JS Framework", patterns: []pat{
		{source: "body", pattern: `_next/static`},
		{source: "header", key: "x-powered-by", pattern: `next\.js`},
	}},
	{name: "Nuxt.js", category: "JS Framework", patterns: []pat{
		{source: "body", pattern: `__nuxt`},
	}},
	{name: "Svelte", category: "JS Framework", patterns: []pat{
		{source: "body", pattern: `__svelte`},
	}},

	{name: "Laravel", category: "Framework", patterns: []pat{
		{source: "cookie", key: "laravel_session", pattern: `laravel_session`},
	}},
	{name: "Django", category: "Framework", patterns: []pat{
		{source: "cookie", key: "csrftoken", pattern: `csrftoken`},
	}},
	{name: "Ruby on Rails", category: "Framework", patterns: []pat{
		{source: "header", key: "x-runtime", pattern: `\d+\.\d+`},
		{source: "header", key: "x-powered-by", pattern: `phusion passenger`},
	}},
	{name: "Express.js", category: "Framework", patterns: []pat{
		{source: "header", key: "x-powered-by", pattern: `express`},
	}},

	{name: "PHP", category: "Language", patterns: []pat{
		{source: "header", key: "x-powered-by", pattern: `php`},
	}},
	{name: "ASP.NET", category: "Language", patterns: []pat{
		{source: "header", key: "x-powered-by", pattern: `asp\.net`},
		{source: "header", key: "x-aspnet-version", pattern: `.+`},
	}},

	{name: "Google Analytics", category: "Analytics", patterns: []pat{
		{source: "body", pattern: `google-analytics\.com|gtag\(|ga\('create'`},
	}},
	{name: "Google Tag Manager", category: "Analytics", patterns: []pat{
		{source: "body", pattern: `googletagmanager\.com`},
	}},

	{name: "jQuery", category: "JS Library", patterns: []pat{
		{source: "body", pattern: `jquery(?:\.min)?\.js|jquery-\d`},
	}},
	{name: "Bootstrap", category: "CSS Framework", patterns: []pat{
		{source: "body", pattern: `bootstrap(?:\.min)?\.css`},
	}},
	{name: "Tailwind CSS", category: "CSS Framework", patterns: []pat{
		{source: "body", pattern: `tailwindcss|tailwind\.min\.css`},
	}},

	{name: "reCAPTCHA", category: "Security", patterns: []pat{
		{source: "body", pattern: `recaptcha\.net|google\.com/recaptcha`},
	}},
}
