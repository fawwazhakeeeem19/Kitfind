
package dns

import (
	"context"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	mdns "github.com/miekg/dns"
)


type RecordType string

const (
	TypeA     RecordType = "A"
	TypeAAAA  RecordType = "AAAA"
	TypeMX    RecordType = "MX"
	TypeNS    RecordType = "NS"
	TypeTXT   RecordType = "TXT"
	TypeCNAME RecordType = "CNAME"
	TypeSOA   RecordType = "SOA"
	TypeCAA   RecordType = "CAA"
)


type Record struct {
	Type     RecordType `json:"type"`
	Name     string     `json:"name"`
	Value    string     `json:"value"`
	TTL      uint32     `json:"ttl"`
	Priority uint16     `json:"priority,omitempty"`
}


type SubdomainResult struct {
	Subdomain string   `json:"subdomain"`
	IPs       []string `json:"ips"`
	Status    string   `json:"status"`
}


type PropagationNode struct {
	Resolver string   `json:"resolver"`
	Location string   `json:"location"`
	IPs      []string `json:"ips"`
	Status   string   `json:"status"`
	RTT      float64  `json:"rtt_ms"`
}


type Result struct {
	Domain      string            `json:"domain"`
	Records     []Record          `json:"records"`
	Subdomains  []SubdomainResult `json:"subdomains"`
	Nameservers []string          `json:"nameservers"`
	SPF         string            `json:"spf,omitempty"`
	DMARC       string            `json:"dmarc,omitempty"`
	DKIM        string            `json:"dkim,omitempty"`
	Propagation []PropagationNode `json:"propagation,omitempty"`
	ScannedAt   time.Time         `json:"scanned_at"`
	Duration    time.Duration     `json:"duration"`
}


type Analyzer struct {
	nameservers []string
	timeout     time.Duration
	client      *mdns.Client
}


func NewAnalyzer(nameservers []string, timeout time.Duration) *Analyzer {
	if len(nameservers) == 0 {
		nameservers = []string{"8.8.8.8:53", "1.1.1.1:53"}
	}
	return &Analyzer{
		nameservers: nameservers,
		timeout:     timeout,
		client:      &mdns.Client{Timeout: timeout, Net: "udp"},
	}
}


func (a *Analyzer) Analyze(ctx context.Context, domain string) (*Result, error) {
	start := time.Now()
	domain = CleanDomain(domain)

	result := &Result{
		Domain:    domain,
		Records:   make([]Record, 0),
		ScannedAt: start,
	}


	qtypes := []uint16{
		mdns.TypeA, mdns.TypeAAAA, mdns.TypeMX, mdns.TypeNS,
		mdns.TypeTXT, mdns.TypeCNAME, mdns.TypeSOA, mdns.TypeCAA,
	}

	var mu sync.Mutex
	var wg sync.WaitGroup

	for _, qt := range qtypes {
		wg.Add(1)
		go func(t uint16) {
			defer wg.Done()
			recs, _ := a.query(ctx, domain, t)
			mu.Lock()
			result.Records = append(result.Records, recs...)
			mu.Unlock()
		}(qt)
	}
	wg.Wait()


	for _, rec := range result.Records {
		switch rec.Type {
		case TypeNS:
			result.Nameservers = append(result.Nameservers, rec.Value)
		case TypeTXT:
			v := rec.Value
			if strings.HasPrefix(v, "v=spf1") {
				result.SPF = v
			}
		}
	}


	dmarcRecs, _ := a.query(ctx, "_dmarc."+domain, mdns.TypeTXT)
	for _, r := range dmarcRecs {
		if strings.HasPrefix(r.Value, "v=DMARC1") {
			result.DMARC = r.Value
		}
	}

	result.Duration = time.Since(start)
	return result, nil
}


func (a *Analyzer) EnumerateSubdomains(ctx context.Context, domain string) []SubdomainResult {
	wordlist := []string{
		"www", "mail", "ftp", "smtp", "pop", "imap", "webmail",
		"blog", "shop", "dev", "staging", "test", "api", "app",
		"m", "mobile", "admin", "portal", "vpn", "cdn", "static",
		"media", "assets", "secure", "ns1", "ns2", "dns", "git",
		"docs", "wiki", "support", "help", "status", "monitor",
		"dashboard", "beta", "demo", "sandbox", "auth", "sso",
		"login", "billing", "account", "forum", "community",
	}

	var wg sync.WaitGroup
	var mu sync.Mutex
	results := make([]SubdomainResult, 0)
	sem := make(chan struct{}, 30)

	for _, sub := range wordlist {
		wg.Add(1)
		go func(s string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			fqdn := s + "." + domain
			addrs, err := net.DefaultResolver.LookupHost(ctx, fqdn)
			if err != nil {
				return
			}
			mu.Lock()
			results = append(results, SubdomainResult{Subdomain: fqdn, IPs: addrs, Status: "active"})
			mu.Unlock()
		}(sub)
	}
	wg.Wait()
	return results
}


func (a *Analyzer) CheckPropagation(ctx context.Context, domain string) []PropagationNode {
	resolvers := []struct{ addr, loc string }{
		{"8.8.8.8:53", "Google (US)"},
		{"1.1.1.1:53", "Cloudflare (US)"},
		{"9.9.9.9:53", "Quad9 (EU)"},
		{"208.67.222.222:53", "OpenDNS (US)"},
		{"77.88.8.8:53", "Yandex (RU)"},
		{"114.114.114.114:53", "114DNS (CN)"},
		{"8.26.56.26:53", "Comodo (US)"},
	}

	var wg sync.WaitGroup
	nodes := make([]PropagationNode, len(resolvers))

	for i, r := range resolvers {
		wg.Add(1)
		go func(idx int, addr, loc string) {
			defer wg.Done()
			node := PropagationNode{Resolver: addr, Location: loc}
			start := time.Now()
			c := &mdns.Client{Timeout: 5 * time.Second}
			m := new(mdns.Msg)
			m.SetQuestion(mdns.Fqdn(domain), mdns.TypeA)
			resp, _, err := c.ExchangeContext(ctx, m, addr)
			node.RTT = float64(time.Since(start).Milliseconds())
			if err != nil {
				node.Status = "timeout"
			} else if resp == nil || len(resp.Answer) == 0 {
				node.Status = "no_record"
			} else {
				node.Status = "resolved"
				for _, ans := range resp.Answer {
					if a, ok := ans.(*mdns.A); ok {
						node.IPs = append(node.IPs, a.A.String())
					}
				}
			}
			nodes[idx] = node
		}(i, r.addr, r.loc)
	}
	wg.Wait()
	return nodes
}


func (a *Analyzer) query(ctx context.Context, domain string, qtype uint16) ([]Record, error) {
	m := new(mdns.Msg)
	m.SetQuestion(mdns.Fqdn(domain), qtype)
	m.RecursionDesired = true

	var resp *mdns.Msg
	var err error
	for _, ns := range a.nameservers {
		resp, _, err = a.client.ExchangeContext(ctx, m, ns)
		if err == nil && resp != nil {
			break
		}
	}
	if err != nil || resp == nil {
		return nil, err
	}

	var records []Record
	for _, ans := range resp.Answer {
		r := rrToRecord(ans)
		if r != nil {
			records = append(records, *r)
		}
	}
	return records, nil
}

func rrToRecord(rr mdns.RR) *Record {
	hdr := rr.Header()
	rec := &Record{Name: strings.TrimSuffix(hdr.Name, "."), TTL: hdr.Ttl}
	switch v := rr.(type) {
	case *mdns.A:
		rec.Type, rec.Value = TypeA, v.A.String()
	case *mdns.AAAA:
		rec.Type, rec.Value = TypeAAAA, v.AAAA.String()
	case *mdns.MX:
		rec.Type, rec.Value, rec.Priority = TypeMX, strings.TrimSuffix(v.Mx, "."), v.Preference
	case *mdns.NS:
		rec.Type, rec.Value = TypeNS, strings.TrimSuffix(v.Ns, ".")
	case *mdns.TXT:
		rec.Type, rec.Value = TypeTXT, strings.Join(v.Txt, " ")
	case *mdns.CNAME:
		rec.Type, rec.Value = TypeCNAME, strings.TrimSuffix(v.Target, ".")
	case *mdns.SOA:
		rec.Type = TypeSOA
		rec.Value = fmt.Sprintf("ns=%s email=%s serial=%d", v.Ns, v.Mbox, v.Serial)
	case *mdns.CAA:
		rec.Type = TypeCAA
		rec.Value = fmt.Sprintf("%d %s %q", v.Flag, v.Tag, v.Value)
	default:
		return nil
	}
	return rec
}


func CleanDomain(domain string) string {
	domain = strings.TrimPrefix(domain, "https://")
	domain = strings.TrimPrefix(domain, "http://")
	domain = strings.Split(domain, "/")[0]
	domain = strings.Split(domain, ":")[0]
	return strings.ToLower(strings.TrimSpace(domain))
}
