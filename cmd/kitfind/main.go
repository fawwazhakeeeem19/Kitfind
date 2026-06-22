
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/briandowns/spinner"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/fatih/color"
	"github.com/spf13/cobra"

	dnsmod "github.com/kitfind/kitfind/internal/dns"
	"github.com/kitfind/kitfind/internal/fingerprint"
	httpmod "github.com/kitfind/kitfind/internal/http"
	"github.com/kitfind/kitfind/internal/output"
	"github.com/kitfind/kitfind/internal/report"
	"github.com/kitfind/kitfind/internal/scanner"
	"github.com/kitfind/kitfind/internal/ssl"
	"github.com/kitfind/kitfind/internal/tui"
)

var (
	flagTimeout    int
	flagJSON       bool
	flagQuiet      bool
	flagPortRange  string
	flagReportFmt  string
	flagOutDir     string
	flagModules    []string
)

func main() {
	root := buildRoot()
	if err := root.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func buildRoot() *cobra.Command {
	root := &cobra.Command{
		Use:   "kitfind",
		Short: "KitFind — Security Reconnaissance Tool",
		Long:  banner(),
		PersistentPreRun: func(cmd *cobra.Command, args []string) {
			if cmd.Use == "tui" || cmd.Use == "version" {
				return
			}
			if !flagQuiet && cmd.Use != "version" {
				output.Banner()
			}
		},
	}

	root.PersistentFlags().IntVar(&flagTimeout, "timeout", 30, "Per-module timeout in seconds")
	root.PersistentFlags().BoolVar(&flagJSON, "json", false, "Output raw JSON")
	root.PersistentFlags().BoolVar(&flagQuiet, "quiet", false, "Suppress banner and informational output")

	root.AddCommand(
		cmdScan(),
		cmdDNS(),
		cmdSSL(),
		cmdHTTP(),
		cmdTech(),
		cmdReport(),
		cmdTUI(),
		cmdVersion(),
	)
	return root
}



func cmdScan() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "scan <target>",
		Short: "Run a full security scan (DNS + SSL + HTTP + Tech)",
		Example: `  kitfind scan example.com
  kitfind scan example.com --timeout 60
  kitfind scan example.com --json`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			target := args[0]
			return runFullScan(target)
		},
	}
	cmd.Flags().StringSliceVar(&flagModules, "modules", []string{"all"}, "Modules to run: dns,ssl,http,fingerprint")
	return cmd
}

func runFullScan(target string) error {
	sp := newSpinner(fmt.Sprintf("Scanning %s...", target))
	sp.Start()

	opts := scanner.DefaultOptions(target)
	opts.Timeout = time.Duration(flagTimeout) * time.Second

	ctx := context.Background()
	result, err := scanner.Run(ctx, opts, func(module, msg string) {
		sp.Suffix = fmt.Sprintf("  [%s] %s", module, msg)
	})
	sp.Stop()

	if err != nil {
		return fmt.Errorf("scan failed: %w", err)
	}

	if flagJSON {
		return printJSON(result)
	}

	renderFullResult(result)
	return nil
}

func renderFullResult(r *scanner.Result) {
	output.PrintScanMeta(r.Target, r.StartedAt)


	if r.DNS != nil {
		output.SectionHeader("DNS RECORDS")
		rows := make([][]string, 0)
		for _, rec := range r.DNS.Records {
			rows = append(rows, []string{string(rec.Type), rec.Name, truncate(rec.Value, 50), fmt.Sprintf("%d", rec.TTL)})
		}
		output.Table([]string{"TYPE", "NAME", "VALUE", "TTL"}, rows)

		if r.DNS.SPF != "" {
			output.KV("SPF", truncate(r.DNS.SPF, 80))
		}
		if r.DNS.DMARC != "" {
			output.KV("DMARC", truncate(r.DNS.DMARC, 80))
		}

		if len(r.DNS.Subdomains) > 0 {
			fmt.Println()
			output.SectionHeader(fmt.Sprintf("SUBDOMAINS (%d FOUND)", len(r.DNS.Subdomains)))
			for _, s := range r.DNS.Subdomains {
				output.Green.Printf("  ✓ %-40s  %s\n", s.Subdomain, strings.Join(s.IPs, ", "))
			}
		}
	}


	if r.SSL != nil {
		output.SectionHeader("SSL/TLS")
		gradeColour := output.Green
		switch r.SSL.Grade {
		case "C", "D":
			gradeColour = output.Yellow
		case "F":
			gradeColour = output.Red
		}
		output.KVColour("Grade", r.SSL.Grade, gradeColour)
		output.KV("TLS Version", r.SSL.TLSVersion)
		output.KV("Cipher Suite", r.SSL.CipherSuite)
		if r.SSL.Certificate != nil {
			c := r.SSL.Certificate
			output.KV("Common Name", c.Subject.CommonName)
			output.KV("Issuer", c.Issuer.CommonName)
			output.KV("Expires", fmt.Sprintf("%s (%d days)", c.NotAfter.Format("2006-01-02"), c.DaysUntilExpiry))
			if c.IsExpired {
				output.Error("Certificate is EXPIRED")
			} else if c.IsExpiringSoon {
				output.Warning("Certificate expiring soon!")
			}
		}
		for _, v := range r.SSL.Vulnerabilities {
			output.Error(v)
		}
	}


	if r.HTTP != nil {
		output.SectionHeader("HTTP SECURITY HEADERS")
		rows := make([][]string, 0)
		for _, check := range r.HTTP.Checks {
			status := output.StatusBadge(check.Status)
			score := fmt.Sprintf("%d/100", check.Score)
			rows = append(rows, []string{check.Name, status, score, truncate(check.Message, 50)})
		}
		output.Table([]string{"HEADER", "STATUS", "SCORE", "NOTES"}, rows)

		if r.HTTP.Server != "" {
			output.KV("Server", r.HTTP.Server)
		}
		if r.HTTP.PoweredBy != "" {
			output.Warning("X-Powered-By: " + r.HTTP.PoweredBy + " (consider removing)")
		}
	}


	if r.Fingerprint != nil && len(r.Fingerprint.Technologies) > 0 {
		output.SectionHeader("TECHNOLOGY STACK")
		rows := make([][]string, 0)
		for _, t := range r.Fingerprint.Technologies {
			bar := strings.Repeat("█", t.Confidence/10) + strings.Repeat("░", 10-t.Confidence/10)
			rows = append(rows, []string{t.Name, t.Category, bar, fmt.Sprintf("%d%%", t.Confidence)})
		}
		output.Table([]string{"TECHNOLOGY", "CATEGORY", "CONFIDENCE", "%"}, rows)
	}


	if len(r.Findings) > 0 {
		output.SectionHeader(fmt.Sprintf("FINDINGS (%d)", len(r.Findings)))
		for i, f := range r.Findings {
			badge := output.SeverityBadge(f.Severity)
			fmt.Printf("\n  [%d] %s  %s\n", i+1, badge, color.New(color.Bold).Sprint(f.Title))
			output.Dim.Printf("       Category   : %s\n", f.Category)
			output.Dim.Printf("       Description: %s\n", f.Description)
			if f.Remediation != "" {
				output.Dim.Printf("       Fix        : %s\n", f.Remediation)
			}
		}
		fmt.Println()
	}


	output.RiskGradeBanner(r.RiskScore, r.RiskGrade)
	output.PrintDuration(r.Duration)
}



func cmdDNS() *cobra.Command {
	var flagSubdomains bool
	var flagPropagation bool

	cmd := &cobra.Command{
		Use:     "dns <target>",
		Short:   "DNS records, subdomains & propagation analysis",
		Example: `  kitfind dns example.com`,
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			target := args[0]
			sp := newSpinner("Analysing DNS...")
			sp.Start()

			a := dnsmod.NewAnalyzer([]string{"8.8.8.8:53", "1.1.1.1:53"}, time.Duration(flagTimeout)*time.Second)
			ctx := context.Background()
			result, err := a.Analyze(ctx, target)
			if err != nil {
				sp.Stop()
				return err
			}

			if flagSubdomains {
				sp.Suffix = "  Enumerating subdomains..."
				result.Subdomains = a.EnumerateSubdomains(ctx, result.Domain)
			}
			if flagPropagation {
				sp.Suffix = "  Checking propagation..."
				result.Propagation = a.CheckPropagation(ctx, result.Domain)
			}
			sp.Stop()

			if flagJSON {
				return printJSON(result)
			}

			output.SectionHeader("DNS RECORDS — " + result.Domain)
			rows := make([][]string, 0)
			for _, r := range result.Records {
				pri := ""
				if r.Priority > 0 {
					pri = fmt.Sprintf("%d", r.Priority)
				}
				rows = append(rows, []string{string(r.Type), r.Name, truncate(r.Value, 55), fmt.Sprintf("%d", r.TTL), pri})
			}
			output.Table([]string{"TYPE", "NAME", "VALUE", "TTL", "PRI"}, rows)

			if result.SPF != "" {
				output.KV("SPF", truncate(result.SPF, 80))
			}
			if result.DMARC != "" {
				output.KV("DMARC", truncate(result.DMARC, 80))
			}

			if len(result.Subdomains) > 0 {
				fmt.Println()
				output.SectionHeader(fmt.Sprintf("SUBDOMAINS (%d FOUND)", len(result.Subdomains)))
				for _, s := range result.Subdomains {
					output.Green.Printf("  ✓ %-40s  %s\n", s.Subdomain, strings.Join(s.IPs, ", "))
				}
			}

			if len(result.Propagation) > 0 {
				fmt.Println()
				output.SectionHeader("DNS PROPAGATION")
				rows = make([][]string, 0)
				for _, p := range result.Propagation {
					rows = append(rows, []string{
						p.Resolver, p.Location, p.Status,
						strings.Join(p.IPs, ", "), fmt.Sprintf("%.0fms", p.RTT),
					})
				}
				output.Table([]string{"RESOLVER", "LOCATION", "STATUS", "IPs", "RTT"}, rows)
			}

			output.PrintDuration(result.Duration)
			return nil
		},
	}

	cmd.Flags().BoolVar(&flagSubdomains, "subdomains", false, "Enumerate common subdomains")
	cmd.Flags().BoolVar(&flagPropagation, "propagation", false, "Check DNS propagation across global resolvers")
	return cmd
}



func cmdSSL() *cobra.Command {
	return &cobra.Command{
		Use:     "ssl <target>",
		Short:   "TLS certificate and cipher suite analysis",
		Example: `  kitfind ssl example.com`,
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			target := args[0]
			sp := newSpinner("Inspecting SSL/TLS...")
			sp.Start()

			ctx := context.Background()
			result, err := ssl.Inspect(ctx, target, time.Duration(flagTimeout)*time.Second)
			sp.Stop()
			if err != nil {
				return err
			}

			if flagJSON {
				return printJSON(result)
			}

			output.SectionHeader("SSL/TLS — " + result.Host)

			gradeC := output.Green
			switch result.Grade {
			case "C", "D":
				gradeC = output.Yellow
			case "F":
				gradeC = output.Red
			}
			output.KVColour("Grade", result.Grade, gradeC)
			output.KV("TLS Version", result.TLSVersion)
			output.KV("Cipher Suite", result.CipherSuite)

			if len(result.Vulnerabilities) > 0 {
				fmt.Println()
				output.SectionHeader("VULNERABILITIES")
				for _, v := range result.Vulnerabilities {
					output.Error(v)
				}
			}

			if result.Certificate != nil {
				c := result.Certificate
				fmt.Println()
				output.SectionHeader("CERTIFICATE")
				output.KV("Common Name", c.Subject.CommonName)
				output.KV("Issuer", c.Issuer.CommonName)
				output.KV("Not Before", c.NotBefore.Format("2006-01-02"))
				output.KV("Not After", c.NotAfter.Format("2006-01-02"))

				if c.IsExpired {
					output.KVColour("Status", "EXPIRED", output.Red)
				} else if c.IsExpiringSoon {
					output.KVColour("Days Until Expiry", fmt.Sprintf("%d (EXPIRING SOON)", c.DaysUntilExpiry), output.Yellow)
				} else {
					output.KVColour("Days Until Expiry", fmt.Sprintf("%d", c.DaysUntilExpiry), output.Green)
				}

				output.KV("Signature Algo", c.SignatureAlgorithm)
				output.KV("Key Algorithm", c.KeyAlgorithm)
				output.KV("Wildcard", fmt.Sprintf("%v", c.IsWildcard))

				if len(c.SANs) > 0 {
					fmt.Println()
					output.SectionHeader("SUBJECT ALTERNATIVE NAMES")
					for _, san := range c.SANs {
						output.InfoLine(san)
					}
				}

				if len(c.Chain) > 0 {
					fmt.Println()
					output.SectionHeader("CERTIFICATE CHAIN")
					for i, ch := range c.Chain {
						fmt.Printf("  [%d] %s → %s  (CA: %v)\n", i+1, ch.Subject, ch.Issuer, ch.IsCA)
					}
				}
			}

			output.PrintDuration(result.Duration)
			return nil
		},
	}
}



func cmdHTTP() *cobra.Command {
	return &cobra.Command{
		Use:     "http <target>",
		Short:   "HTTP security headers, cookies, and CSP analysis",
		Example: `  kitfind http example.com`,
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			target := args[0]
			sp := newSpinner("Analysing HTTP headers...")
			sp.Start()

			ctx := context.Background()
			result, err := httpmod.Analyze(ctx, target,
				time.Duration(flagTimeout)*time.Second,
				"KitFind/1.0 (authorized reconnaissance tool)")
			sp.Stop()
			if err != nil {
				return err
			}

			if flagJSON {
				return printJSON(result)
			}

			output.SectionHeader("HTTP ANALYSIS — " + result.URL)
			output.KV("Status Code", fmt.Sprintf("%d", result.StatusCode))
			output.KV("Final URL", result.FinalURL)
			output.KV("Security Score", fmt.Sprintf("%d/100", result.SecurityScore))
			output.KV("Response Time", result.ResponseTime.String())
			output.KV("Body Size", fmt.Sprintf("%d bytes", result.BodySize))
			if result.Server != "" {
				output.KV("Server", result.Server)
			}
			if result.PoweredBy != "" {
				output.KV("X-Powered-By", result.PoweredBy)
			}

			fmt.Println()
			output.SectionHeader("SECURITY HEADERS")
			rows := make([][]string, 0)
			for _, check := range result.Checks {
				status := output.StatusBadge(check.Status)
				val := truncate(check.Value, 40)
				rows = append(rows, []string{check.Name, status, fmt.Sprintf("%d", check.Score), val})
			}
			output.Table([]string{"HEADER", "STATUS", "SCORE", "VALUE"}, rows)

			if len(result.Cookies) > 0 {
				fmt.Println()
				output.SectionHeader("COOKIE ANALYSIS")
				rows = make([][]string, 0)
				for _, c := range result.Cookies {
					issues := strings.Join(c.Issues, "; ")
					rows = append(rows, []string{
						c.Name,
						fmt.Sprintf("%v", c.Secure),
						fmt.Sprintf("%v", c.HttpOnly),
						c.SameSite,
						fmt.Sprintf("%d", c.Score),
						truncate(issues, 40),
					})
				}
				output.Table([]string{"NAME", "SECURE", "HTTPONLY", "SAMESITE", "SCORE", "ISSUES"}, rows)
			}

			if result.CSP != nil {
				fmt.Println()
				output.SectionHeader("CONTENT SECURITY POLICY")
				output.KV("CSP Score", fmt.Sprintf("%d/100", result.CSP.Score))
				output.KV("unsafe-inline", fmt.Sprintf("%v", result.CSP.HasUnsafeInline))
				output.KV("unsafe-eval", fmt.Sprintf("%v", result.CSP.HasUnsafeEval))
				output.KV("Wildcard", fmt.Sprintf("%v", result.CSP.HasWildcard))
				if len(result.CSP.Issues) > 0 {
					for _, issue := range result.CSP.Issues {
						output.Warning(issue)
					}
				}
			}

			output.PrintDuration(result.ResponseTime)
			return nil
		},
	}
}



func cmdTech() *cobra.Command {
	return &cobra.Command{
		Use:     "tech <target>",
		Short:   "Technology stack fingerprinting",
		Example: `  kitfind tech example.com`,
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			target := args[0]
			sp := newSpinner("Fingerprinting technologies...")
			sp.Start()

			ctx := context.Background()
			httpResult, err := httpmod.Analyze(ctx, target,
				time.Duration(flagTimeout)*time.Second,
				"KitFind/1.0 (authorized reconnaissance tool)")
			sp.Stop()
			if err != nil {
				return err
			}

			headers := make(map[string]string)
			for k, v := range httpResult.Headers {
				if len(v) > 0 {
					headers[k] = v[0]
				}
			}
			var cookies []string
			for _, c := range httpResult.Cookies {
				cookies = append(cookies, c.Name)
			}
			result := fingerprint.Detect(headers, httpResult.Body, cookies)

			if flagJSON {
				return printJSON(result)
			}

			output.SectionHeader(fmt.Sprintf("TECHNOLOGY FINGERPRINT — %s (%d found)", target, len(result.Technologies)))

			rows := make([][]string, 0)
			for _, t := range result.Technologies {
				bar := strings.Repeat("█", t.Confidence/10) + strings.Repeat("░", 10-t.Confidence/10)
				version := t.Version
				if version == "" {
					version = "—"
				}
				rows = append(rows, []string{t.Name, t.Category, version, bar, fmt.Sprintf("%d%%", t.Confidence)})
			}
			output.Table([]string{"TECHNOLOGY", "CATEGORY", "VERSION", "CONFIDENCE", "%"}, rows)

			fmt.Println()
			output.SectionHeader("STACK SUMMARY")
			for cat, names := range result.Summary {
				output.KV(cat, strings.Join(names, ", "))
			}
			return nil
		},
	}
}



func cmdReport() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "report <target>",
		Short: "Scan and generate a report file",
		Example: `  kitfind report example.com -f html
  kitfind report example.com -f json -o ./reports`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			target := args[0]

			sp := newSpinner(fmt.Sprintf("Scanning %s for report...", target))
			sp.Start()

			opts := scanner.DefaultOptions(target)
			opts.Timeout = time.Duration(flagTimeout) * time.Second
			ctx := context.Background()
			result, err := scanner.Run(ctx, opts, func(module, msg string) {
				sp.Suffix = fmt.Sprintf("  [%s] %s", module, msg)
			})
			sp.Stop()
			if err != nil {
				return err
			}

			format := report.Format(flagReportFmt)
			outDir := flagOutDir
			if outDir == "" {
				outDir = "./kitfind-reports"
			}

			path, err := report.Generate(result, format, outDir)
			if err != nil {
				return fmt.Errorf("report generation failed: %w", err)
			}

			output.SectionHeader("REPORT GENERATED")
			output.OK("Format : " + flagReportFmt)
			output.OK("File   : " + path)
			output.RiskGradeBanner(result.RiskScore, result.RiskGrade)
			return nil
		},
	}

	cmd.Flags().StringVarP(&flagReportFmt, "format", "f", "html", "Report format: json, csv, html, txt")
	cmd.Flags().StringVarP(&flagOutDir, "output", "o", "", "Output directory (default: ./kitfind-reports)")
	return cmd
}



func cmdTUI() *cobra.Command {
	return &cobra.Command{
		Use:   "tui",
		Short: "Launch the interactive terminal UI",
		RunE: func(cmd *cobra.Command, args []string) error {
			m := tui.New()
			p := tea.NewProgram(m, tea.WithAltScreen(), tea.WithMouseCellMotion())
			_, err := p.Run()
			return err
		},
	}
}



func cmdVersion() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print version information",
		Run: func(cmd *cobra.Command, args []string) {
			color.New(color.FgCyan, color.Bold).Println("KitFind v1.0.0")
			fmt.Println("Security Reconnaissance Tool")
			fmt.Println("Go 1.22  ·  Authorized Use Only")
		},
	}
}



func banner() string {
	return `
 ██╗  ██╗██╗████████╗███████╗██╗███╗   ██╗██████╗
 ██║ ██╔╝██║╚══██╔══╝██╔════╝██║████╗  ██║██╔══██╗
 █████╔╝ ██║   ██║   █████╗  ██║██╔██╗ ██║██║  ██║
 ██╔═██╗ ██║   ██║   ██╔══╝  ██║██║╚██╗██║██║  ██║
 ██║  ██╗██║   ██║   ██║     ██║██║ ╚████║██████╔╝
 ╚═╝  ╚═╝╚═╝   ╚═╝   ╚═╝     ╚═╝╚═╝  ╚═══╝╚═════╝

 Security Reconnaissance Tool v1.0.0
 Authorized use only — for sys admins, bug bounty hunters, pentesters`
}

func newSpinner(suffix string) *spinner.Spinner {
	sp := spinner.New(spinner.CharSets[14], 80*time.Millisecond)
	sp.Color("cyan", "bold")
	sp.Suffix = "  " + suffix
	sp.FinalMSG = color.CyanString("  ✓ Done\n")
	return sp
}

func printJSON(v interface{}) error {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n-3] + "..."
}
