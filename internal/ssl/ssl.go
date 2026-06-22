
package ssl

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"strings"
	"time"
)


type CertSubject struct {
	CommonName   string   `json:"common_name"`
	Organization []string `json:"organization"`
	Country      []string `json:"country"`
}


type ChainEntry struct {
	Subject  string    `json:"subject"`
	Issuer   string    `json:"issuer"`
	NotAfter time.Time `json:"not_after"`
	IsCA     bool      `json:"is_ca"`
}


type CertInfo struct {
	Subject            CertSubject  `json:"subject"`
	Issuer             CertSubject  `json:"issuer"`
	SerialNumber       string       `json:"serial_number"`
	NotBefore          time.Time    `json:"not_before"`
	NotAfter           time.Time    `json:"not_after"`
	DaysUntilExpiry    int          `json:"days_until_expiry"`
	IsExpired          bool         `json:"is_expired"`
	IsExpiringSoon     bool         `json:"is_expiring_soon"`
	SANs               []string     `json:"sans"`
	IsWildcard         bool         `json:"is_wildcard"`
	SignatureAlgorithm string       `json:"signature_algorithm"`
	KeyAlgorithm       string       `json:"key_algorithm"`
	OCSPServers        []string     `json:"ocsp_servers"`
	Chain              []ChainEntry `json:"chain"`
}


type Result struct {
	Host            string    `json:"host"`
	Port            string    `json:"port"`
	TLSVersion      string    `json:"tls_version"`
	CipherSuite     string    `json:"cipher_suite"`
	Certificate     *CertInfo `json:"certificate"`
	Vulnerabilities []string  `json:"vulnerabilities"`
	Grade           string    `json:"grade"`
	ScannedAt       time.Time `json:"scanned_at"`
	Duration        time.Duration `json:"duration"`
}


func Inspect(ctx context.Context, host string, timeout time.Duration) (*Result, error) {
	start := time.Now()


	host = strings.TrimPrefix(host, "https://")
	host = strings.TrimPrefix(host, "http://")
	host = strings.Split(host, "/")[0]

	hostname := host
	port := "443"
	if strings.Contains(host, ":") {
		parts := strings.SplitN(host, ":", 2)
		hostname, port = parts[0], parts[1]
	}

	addr := hostname + ":" + port

	dialer := &net.Dialer{Timeout: timeout}
	conn, err := tls.DialWithDialer(dialer, "tcp", addr, &tls.Config{
		ServerName: hostname,
	})
	if err != nil {

		conn, err = tls.DialWithDialer(dialer, "tcp", addr, &tls.Config{
			ServerName:         hostname,
			InsecureSkipVerify: true, //nolint:gosec // intentional for recon
		})
		if err != nil {
			return nil, fmt.Errorf("TLS connect failed: %w", err)
		}
	}
	defer conn.Close()

	state := conn.ConnectionState()
	res := &Result{
		Host:        hostname,
		Port:        port,
		TLSVersion:  tlsVersionStr(state.Version),
		CipherSuite: tls.CipherSuiteName(state.CipherSuite),
		ScannedAt:   start,
	}

	res.Vulnerabilities = detectVulns(state.Version, state.CipherSuite)

	if len(state.PeerCertificates) > 0 {
		res.Certificate = parseCert(state.PeerCertificates[0])
		for _, c := range state.PeerCertificates[1:] {
			res.Certificate.Chain = append(res.Certificate.Chain, ChainEntry{
				Subject:  c.Subject.CommonName,
				Issuer:   c.Issuer.CommonName,
				NotAfter: c.NotAfter,
				IsCA:     c.IsCA,
			})
		}
	}

	res.Grade = grade(res)
	res.Duration = time.Since(start)
	return res, nil
}

func parseCert(cert *x509.Certificate) *CertInfo {
	now := time.Now()
	days := int(cert.NotAfter.Sub(now).Hours() / 24)

	isWild := false
	for _, n := range cert.DNSNames {
		if strings.HasPrefix(n, "*.") {
			isWild = true
			break
		}
	}

	sans := cert.DNSNames
	for _, ip := range cert.IPAddresses {
		sans = append(sans, ip.String())
	}

	return &CertInfo{
		Subject:            CertSubject{cert.Subject.CommonName, cert.Subject.Organization, cert.Subject.Country},
		Issuer:             CertSubject{cert.Issuer.CommonName, cert.Issuer.Organization, cert.Issuer.Country},
		SerialNumber:       cert.SerialNumber.String(),
		NotBefore:          cert.NotBefore,
		NotAfter:           cert.NotAfter,
		DaysUntilExpiry:    days,
		IsExpired:          now.After(cert.NotAfter),
		IsExpiringSoon:     days > 0 && days <= 30,
		SANs:               sans,
		IsWildcard:         isWild,
		SignatureAlgorithm: cert.SignatureAlgorithm.String(),
		KeyAlgorithm:       cert.PublicKeyAlgorithm.String(),
		OCSPServers:        cert.OCSPServer,
		Chain:              make([]ChainEntry, 0),
	}
}

func tlsVersionStr(v uint16) string {
	switch v {
	case tls.VersionTLS10:
		return "TLS 1.0"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS13:
		return "TLS 1.3"
	default:
		return fmt.Sprintf("Unknown(0x%04x)", v)
	}
}

func detectVulns(version uint16, cipher uint16) []string {
	var v []string
	if version <= tls.VersionTLS10 {
		v = append(v, "TLS 1.0 deprecated — vulnerable to POODLE/BEAST")
	}
	if version == tls.VersionTLS11 {
		v = append(v, "TLS 1.1 deprecated — upgrade to TLS 1.2+")
	}
	weakCiphers := map[uint16]string{
		tls.TLS_RSA_WITH_RC4_128_SHA:      "RC4 cipher is cryptographically broken",
		tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA: "3DES cipher vulnerable to SWEET32",
	}
	if msg, ok := weakCiphers[cipher]; ok {
		v = append(v, msg)
	}
	return v
}

func grade(r *Result) string {
	if r.Certificate != nil && r.Certificate.IsExpired {
		return "F"
	}
	score := 100
	switch r.TLSVersion {
	case "TLS 1.0":
		score -= 50
	case "TLS 1.1":
		score -= 30
	}
	score -= len(r.Vulnerabilities) * 15
	if r.Certificate != nil && r.Certificate.IsExpiringSoon {
		score -= 10
	}
	if r.TLSVersion == "TLS 1.3" {
		score += 5
	}
	switch {
	case score >= 100:
		return "A+"
	case score >= 90:
		return "A"
	case score >= 80:
		return "B"
	case score >= 60:
		return "C"
	default:
		return "F"
	}
}
