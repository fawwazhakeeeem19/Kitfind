
package tui

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/spinner"
	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/kitfind/kitfind/internal/scanner"
)


type Screen int

const (
	ScreenHome Screen = iota
	ScreenScan
	ScreenScanning
	ScreenResults
	ScreenDNS
	ScreenSSL
	ScreenHTTP
	ScreenFingerprint
	ScreenHistory
	ScreenSettings
	ScreenHelp
)


type menuItem struct {
	key    string
	label  string
	screen Screen
	icon   string
}


type scanDoneMsg struct {
	result *scanner.Result
	err    error
}


type progressMsg struct {
	module string
	msg    string
}


type Model struct {
	screen      Screen
	width       int
	height      int
	cursor      int
	menuItems   []menuItem
	targetInput textinput.Model
	spinner     spinner.Model
	scanning    bool
	scanLog     []string
	result      *scanner.Result
	scanErr     string
	history     []histEntry
}

type histEntry struct {
	target    string
	timestamp time.Time
	grade     string
	score     int
}


var (
	colBG      = lipgloss.Color("#0d0d0d")
	colSurface = lipgloss.Color("#111118")
	colBorder  = lipgloss.Color("#2a2a3a")
	colCyan    = lipgloss.Color("#00d4ff")
	colGreen   = lipgloss.Color("#00ff88")
	colYellow  = lipgloss.Color("#ffd700")
	colRed     = lipgloss.Color("#ff4444")
	colDim     = lipgloss.Color("#555566")
	colWhite   = lipgloss.Color("#e0e0e0")
	colMagenta = lipgloss.Color("#cc66ff")

	styleBox = lipgloss.NewStyle().
			BorderStyle(lipgloss.NormalBorder()).
			BorderForeground(colBorder).
			Background(colSurface)

	styleSidebar = lipgloss.NewStyle().
			Width(22).
			BorderStyle(lipgloss.NormalBorder()).
			BorderForeground(colCyan).
			Padding(1, 1).
			Background(colSurface)

	styleTitle = lipgloss.NewStyle().
			Foreground(colCyan).
			Bold(true).
			Padding(0, 0, 1, 0)

	styleMenuActive = lipgloss.NewStyle().
			Foreground(colCyan).
			Bold(true).
			Background(lipgloss.Color("#001a28")).
			Width(18).
			Padding(0, 1)

	styleMenuInactive = lipgloss.NewStyle().
				Foreground(colDim).
				Width(18).
				Padding(0, 1)

	styleHeader = lipgloss.NewStyle().
			Foreground(colCyan).
			Bold(true).
			BorderStyle(lipgloss.NormalBorder()).
			BorderBottom(true).
			BorderForeground(colBorder).
			Width(100).
			Padding(0, 1)

	styleContent = lipgloss.NewStyle().
			Padding(1, 2)

	styleLabel = lipgloss.NewStyle().
			Foreground(colDim).
			Width(24)

	styleValue = lipgloss.NewStyle().
			Foreground(colWhite)

	styleGood    = lipgloss.NewStyle().Foreground(colGreen).Bold(true)
	styleWarn    = lipgloss.NewStyle().Foreground(colYellow).Bold(true)
	styleBad     = lipgloss.NewStyle().Foreground(colRed).Bold(true)
	styleMuted   = lipgloss.NewStyle().Foreground(colDim)
	styleCyan    = lipgloss.NewStyle().Foreground(colCyan)
	styleMagenta = lipgloss.NewStyle().Foreground(colMagenta)
)


func New() Model {
	ti := textinput.New()
	ti.Placeholder = "e.g. example.com"
	ti.CharLimit = 256
	ti.Width = 50

	sp := spinner.New()
	sp.Spinner = spinner.Points
	sp.Style = lipgloss.NewStyle().Foreground(colCyan)

	menu := []menuItem{
		{"s", "Scan", ScreenScan, "◆"},
		{"d", "DNS Analysis", ScreenDNS, "◉"},
		{"l", "SSL Review", ScreenSSL, "🔒"},
		{"h", "HTTP Headers", ScreenHTTP, "⊞"},
		{"t", "Tech Fingerprint", ScreenFingerprint, "⊛"},
		{"r", "History", ScreenHistory, "≡"},
		{"?", "Help", ScreenHelp, "?"},
	}

	return Model{
		screen:      ScreenHome,
		menuItems:   menu,
		targetInput: ti,
		spinner:     sp,
	}
}


func (m Model) Init() tea.Cmd {
	return m.spinner.Tick
}


func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {

	case tea.WindowSizeMsg:
		m.width, m.height = msg.Width, msg.Height

	case tea.KeyMsg:
		return m.handleKey(msg)

	case spinner.TickMsg:
		var cmd tea.Cmd
		m.spinner, cmd = m.spinner.Update(msg)
		return m, cmd

	case progressMsg:
		m.scanLog = append(m.scanLog, fmt.Sprintf("[%s] %s", msg.module, msg.msg))
		if len(m.scanLog) > 20 {
			m.scanLog = m.scanLog[len(m.scanLog)-20:]
		}
		return m, m.spinner.Tick

	case scanDoneMsg:
		m.scanning = false
		if msg.err != nil {
			m.scanErr = msg.err.Error()
			m.screen = ScreenScan
		} else {
			m.result = msg.result
			m.screen = ScreenResults
			m.history = append(m.history, histEntry{
				target:    msg.result.Target,
				timestamp: time.Now(),
				grade:     msg.result.RiskGrade,
				score:     msg.result.RiskScore,
			})
		}
		return m, nil
	}

	if m.screen == ScreenScan && !m.scanning {
		var cmd tea.Cmd
		m.targetInput, cmd = m.targetInput.Update(msg)
		return m, cmd
	}

	return m, nil
}

func (m Model) handleKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "ctrl+c", "q":
		if m.screen == ScreenHome {
			return m, tea.Quit
		}
		m.screen = ScreenHome
		m.scanning = false

	case "esc":
		m.screen = ScreenHome

	case "up", "k":
		if m.cursor > 0 {
			m.cursor--
		}

	case "down", "j":
		if m.cursor < len(m.menuItems)-1 {
			m.cursor++
		}

	case "enter":
		if m.screen == ScreenHome {
			m.screen = m.menuItems[m.cursor].screen
			if m.screen == ScreenScan {
				m.targetInput.Focus()
			}
		} else if m.screen == ScreenScan && !m.scanning {
			target := strings.TrimSpace(m.targetInput.Value())
			if target != "" {
				m.scanning = true
				m.scanLog = nil
				m.scanErr = ""
				m.screen = ScreenScanning
				return m, tea.Batch(m.spinner.Tick, runScan(target))
			}
		}


	case "s":
		m.screen = ScreenScan
		m.targetInput.Focus()
	case "d":
		m.screen = ScreenDNS
	case "l":
		m.screen = ScreenSSL
	case "h":
		m.screen = ScreenHTTP
	case "t":
		m.screen = ScreenFingerprint
	case "r":
		m.screen = ScreenHistory
	case "?":
		m.screen = ScreenHelp
	}
	return m, nil
}


func (m Model) View() string {
	if m.width == 0 {
		return "Loading KitFind..."
	}

	sidebar := m.renderSidebar()
	content := m.renderContent()


	return lipgloss.JoinHorizontal(lipgloss.Top, sidebar, content)
}

func (m Model) renderSidebar() string {
	var b strings.Builder


	logo := styleTitle.Render("╔══════════════╗\n║   KITFIND   ║\n╚══════════════╝")
	b.WriteString(logo)
	b.WriteString("\n\n")

	for i, item := range m.menuItems {
		label := fmt.Sprintf("%s  %s", item.icon, item.label)
		var row string
		if i == m.cursor && m.screen == ScreenHome {
			row = styleMenuActive.Render("▶ " + label)
		} else {
			row = styleMenuInactive.Render("  " + label)
		}
		b.WriteString(row + "\n")
	}

	b.WriteString("\n")
	b.WriteString(styleMuted.Render("  ──────────────────\n"))
	b.WriteString(styleMuted.Render("  ↑↓ navigate\n"))
	b.WriteString(styleMuted.Render("  Enter  select\n"))
	b.WriteString(styleMuted.Render("  q/Esc  back\n"))

	return styleSidebar.Render(b.String())
}

func (m Model) renderContent() string {
	width := m.width - 26
	if width < 40 {
		width = 40
	}

	switch m.screen {
	case ScreenHome:
		return m.renderHome(width)
	case ScreenScan:
		return m.renderScanInput(width)
	case ScreenScanning:
		return m.renderScanning(width)
	case ScreenResults:
		return m.renderResults(width)
	case ScreenDNS:
		return m.renderDNSDetails(width)
	case ScreenSSL:
		return m.renderSSLDetails(width)
	case ScreenHTTP:
		return m.renderHTTPDetails(width)
	case ScreenFingerprint:
		return m.renderFingerprintDetails(width)
	case ScreenHistory:
		return m.renderHistory(width)
	case ScreenHelp:
		return m.renderHelp(width)
	}
	return m.renderHome(width)
}

func (m Model) renderHome(width int) string {
	banner := styleCyan.Render(`
 ██╗  ██╗██╗████████╗███████╗██╗███╗   ██╗██████╗
 ██║ ██╔╝██║╚══██╔══╝██╔════╝██║████╗  ██║██╔══██╗
 █████╔╝ ██║   ██║   █████╗  ██║██╔██╗ ██║██║  ██║
 ██╔═██╗ ██║   ██║   ██╔══╝  ██║██║╚██╗██║██║  ██║
 ██║  ██╗██║   ██║   ██║     ██║██║ ╚████║██████╔╝
 ╚═╝  ╚═╝╚═╝   ╚═╝   ╚═╝     ╚═╝╚═╝  ╚═══╝╚═════╝`)

	tagline := styleMuted.Render("  Security Reconnaissance Tool  v1.0.0\n  Authorized Use Only\n")

	modules := styleCyan.Render("  Available Modules:") + "\n"
	mods := []struct{ icon, name, desc string }{
		{"◆", "scan", "Full security scan (DNS + SSL + HTTP + Tech)"},
		{"◉", "dns", "DNS records, subdomains, propagation"},
		{"🔒", "ssl", "TLS certificate & cipher analysis"},
		{"⊞", "http", "Security headers & cookie audit"},
		{"⊛", "fingerprint", "Technology stack detection"},
	}
	for _, mod := range mods {
		modules += fmt.Sprintf("  %s  %-14s  %s\n",
			mod.icon,
			styleCyan.Render(mod.name),
			styleMuted.Render(mod.desc),
		)
	}

	return styleContent.Render(banner + "\n\n" + tagline + "\n" + modules +
		"\n" + styleMuted.Render("  Select a module from the sidebar or press a shortcut key."))
}

func (m Model) renderScanInput(width int) string {
	title := styleHeader.Render("◆  FULL SECURITY SCAN")
	desc := styleMuted.Render("\n  Enter a target domain or IP address to begin reconnaissance.\n  All modules will run: DNS, SSL, HTTP, Fingerprint.\n")

	disclaimer := styleWarn.Render("\n  ⚠  Only scan systems you own or have written permission to scan.\n")

	inputLabel := styleCyan.Render("\n  Target:")
	input := "\n  " + m.targetInput.View()

	hint := styleMuted.Render("\n\n  Press Enter to start · Esc to go back\n")

	if m.scanErr != "" {
		return title + desc + disclaimer + inputLabel + input +
			"\n\n" + styleBad.Render("  Error: "+m.scanErr) + hint
	}
	return title + desc + disclaimer + inputLabel + input + hint
}

func (m Model) renderScanning(width int) string {
	title := styleHeader.Render("◆  SCANNING...")
	header := styleCyan.Render("\n  " + m.spinner.View() + "  Scanning " + m.targetInput.Value() + "...\n")

	var log strings.Builder
	for _, line := range m.scanLog {
		log.WriteString(styleMuted.Render("  "+line) + "\n")
	}

	return title + header + "\n" + log.String()
}

func (m Model) renderResults(width int) string {
	if m.result == nil {
		return styleContent.Render("No results yet. Run a scan first.")
	}
	r := m.result
	title := styleHeader.Render("◆  SCAN RESULTS: " + r.Target)


	riskColour := styleGood
	switch {
	case r.RiskScore >= 60:
		riskColour = styleBad
	case r.RiskScore >= 30:
		riskColour = styleWarn
	}
	risk := "\n" + styleLabel.Render("  Risk Score") + riskColour.Render(fmt.Sprintf("%d/100  Grade: %s", r.RiskScore, r.RiskGrade))
	dur := "\n" + styleLabel.Render("  Duration") + styleValue.Render(r.Duration.Round(time.Millisecond).String())

	var sections strings.Builder
	sections.WriteString(risk)
	sections.WriteString(dur)
	sections.WriteString("\n\n")


	sevCounts := map[string]int{}
	for _, f := range r.Findings {
		sevCounts[f.Severity]++
	}
	sections.WriteString(styleCyan.Render("  Findings:") + "\n")
	for _, sev := range []string{"critical", "high", "medium", "low", "info"} {
		if n := sevCounts[sev]; n > 0 {
			c := styleGood
			switch sev {
			case "critical":
				c = styleBad
			case "high":
				c = styleBad
			case "medium":
				c = styleWarn
			}
			sections.WriteString(fmt.Sprintf("    %-10s  %s\n", sev, c.Render(fmt.Sprintf("%d", n))))
		}
	}

	sections.WriteString("\n" + styleMuted.Render("  Navigate with sidebar keys for details (d/l/h/t)\n"))
	sections.WriteString(styleMuted.Render("  Run 'kitfind report' to export a full report.\n"))

	return title + sections.String()
}

func (m Model) renderDNSDetails(width int) string {
	title := styleHeader.Render("◉  DNS ANALYSIS")
	if m.result == nil || m.result.DNS == nil {
		return title + "\n\n" + styleMuted.Render("  No DNS data. Run a scan first.")
	}
	dns := m.result.DNS
	var b strings.Builder
	b.WriteString(fmt.Sprintf("\n  Domain:     %s\n", styleCyan.Render(dns.Domain)))
	b.WriteString(fmt.Sprintf("  Records:    %d\n", len(dns.Records)))
	b.WriteString(fmt.Sprintf("  Subdomains: %d found\n", len(dns.Subdomains)))
	b.WriteString(fmt.Sprintf("  Duration:   %s\n\n", dns.Duration))

	b.WriteString(styleCyan.Render("  DNS Records:\n"))
	for _, r := range dns.Records {
		b.WriteString(fmt.Sprintf("    %-8s  %-36s  TTL=%d\n",
			string(r.Type), truncate(r.Value, 36), r.TTL))
	}

	if dns.SPF != "" {
		b.WriteString("\n" + styleCyan.Render("  Email Security:\n"))
		b.WriteString("    SPF   " + styleMuted.Render(truncate(dns.SPF, 60)) + "\n")
	}
	if dns.DMARC != "" {
		b.WriteString("    DMARC " + styleMuted.Render(truncate(dns.DMARC, 60)) + "\n")
	}

	if len(dns.Subdomains) > 0 {
		b.WriteString("\n" + styleCyan.Render("  Subdomains:\n"))
		for _, s := range dns.Subdomains {
			b.WriteString(fmt.Sprintf("    %s  →  %s\n", styleGood.Render("◆"), s.Subdomain))
		}
	}
	return title + b.String()
}

func (m Model) renderSSLDetails(width int) string {
	title := styleHeader.Render("🔒  SSL/TLS REVIEW")
	if m.result == nil || m.result.SSL == nil {
		return title + "\n\n" + styleMuted.Render("  No SSL data. Run a scan first.")
	}
	s := m.result.SSL
	var b strings.Builder

	gc := styleGood
	switch s.Grade {
	case "C", "D":
		gc = styleWarn
	case "F":
		gc = styleBad
	}

	b.WriteString(fmt.Sprintf("\n  %-22s %s\n", styleMuted.Render("Grade"), gc.Render(s.Grade)))
	b.WriteString(fmt.Sprintf("  %-22s %s\n", styleMuted.Render("TLS Version"), s.TLSVersion))
	b.WriteString(fmt.Sprintf("  %-22s %s\n", styleMuted.Render("Cipher Suite"), truncate(s.CipherSuite, 45)))

	if s.Certificate != nil {
		c := s.Certificate
		b.WriteString("\n" + styleCyan.Render("  Certificate:\n"))
		b.WriteString(fmt.Sprintf("  %-22s %s\n", styleMuted.Render("Common Name"), c.Subject.CommonName))
		b.WriteString(fmt.Sprintf("  %-22s %s\n", styleMuted.Render("Issuer"), c.Issuer.CommonName))
		b.WriteString(fmt.Sprintf("  %-22s %s\n", styleMuted.Render("Not Before"), c.NotBefore.Format("2006-01-02")))
		b.WriteString(fmt.Sprintf("  %-22s %s\n", styleMuted.Render("Not After"), c.NotAfter.Format("2006-01-02")))

		expStyle := styleGood
		expMsg := fmt.Sprintf("%d days", c.DaysUntilExpiry)
		if c.IsExpired {
			expStyle = styleBad
			expMsg = "EXPIRED"
		} else if c.IsExpiringSoon {
			expStyle = styleWarn
			expMsg += " (expiring soon!)"
		}
		b.WriteString(fmt.Sprintf("  %-22s %s\n", styleMuted.Render("Days Until Expiry"), expStyle.Render(expMsg)))
		b.WriteString(fmt.Sprintf("  %-22s %v\n", styleMuted.Render("Wildcard"), c.IsWildcard))

		if len(c.SANs) > 0 {
			b.WriteString("\n" + styleCyan.Render("  SANs:\n"))
			for _, san := range c.SANs {
				b.WriteString("    " + styleMuted.Render("◆ ") + san + "\n")
			}
		}
	}

	if len(s.Vulnerabilities) > 0 {
		b.WriteString("\n" + styleBad.Render("  Vulnerabilities:\n"))
		for _, v := range s.Vulnerabilities {
			b.WriteString("    ⚠ " + styleWarn.Render(v) + "\n")
		}
	}

	return title + b.String()
}

func (m Model) renderHTTPDetails(width int) string {
	title := styleHeader.Render("⊞  HTTP SECURITY HEADERS")
	if m.result == nil || m.result.HTTP == nil {
		return title + "\n\n" + styleMuted.Render("  No HTTP data. Run a scan first.")
	}
	h := m.result.HTTP
	var b strings.Builder

	b.WriteString(fmt.Sprintf("\n  %-22s %d\n", styleMuted.Render("Status Code"), h.StatusCode))
	b.WriteString(fmt.Sprintf("  %-22s %d/100\n", styleMuted.Render("Security Score"), h.SecurityScore))
	if h.Server != "" {
		b.WriteString(fmt.Sprintf("  %-22s %s\n", styleMuted.Render("Server"), h.Server))
	}
	if h.PoweredBy != "" {
		b.WriteString(fmt.Sprintf("  %-22s %s\n", styleMuted.Render("X-Powered-By"), h.PoweredBy))
	}

	b.WriteString("\n" + styleCyan.Render("  Security Header Checks:\n\n"))
	for _, check := range h.Checks {
		var status string
		switch check.Status {
		case "good":
			status = styleGood.Render("✓ OK     ")
		case "warning":
			status = styleWarn.Render("⚠ WARN   ")
		case "missing":
			status = styleBad.Render("✗ MISSING")
		default:
			status = styleMuted.Render("  INFO   ")
		}
		b.WriteString(fmt.Sprintf("  %s  %-36s  %d\n", status, check.Name, check.Score))
		if check.Message != "" {
			b.WriteString(styleMuted.Render(fmt.Sprintf("           %s\n", check.Message)))
		}
	}

	if len(h.Cookies) > 0 {
		b.WriteString("\n" + styleCyan.Render("  Cookies:\n"))
		for _, c := range h.Cookies {
			issueStr := ""
			if len(c.Issues) > 0 {
				issueStr = styleWarn.Render("  ⚠ " + strings.Join(c.Issues, ", "))
			}
			b.WriteString(fmt.Sprintf("  %-30s score=%d%s\n", c.Name, c.Score, issueStr))
		}
	}

	return title + b.String()
}

func (m Model) renderFingerprintDetails(width int) string {
	title := styleHeader.Render("⊛  TECHNOLOGY FINGERPRINT")
	if m.result == nil || m.result.Fingerprint == nil {
		return title + "\n\n" + styleMuted.Render("  No fingerprint data. Run a scan first.")
	}
	fp := m.result.Fingerprint
	var b strings.Builder
	b.WriteString(fmt.Sprintf("\n  Detected %d technologies\n\n", len(fp.Technologies)))


	for cat, names := range fp.Summary {
		b.WriteString(styleCyan.Render("  "+cat+":\n"))
		for _, name := range names {
			b.WriteString(fmt.Sprintf("    ◆  %s\n", name))
		}
		b.WriteString("\n")
	}

	b.WriteString(styleCyan.Render("  Full List:\n"))
	for _, t := range fp.Technologies {
		bar := strings.Repeat("█", t.Confidence/10) + strings.Repeat("░", 10-t.Confidence/10)
		b.WriteString(fmt.Sprintf("  %-24s  %-18s  %s %d%%\n",
			t.Name, styleMuted.Render(t.Category), styleCyan.Render(bar), t.Confidence))
	}
	return title + b.String()
}

func (m Model) renderHistory(width int) string {
	title := styleHeader.Render("≡  SCAN HISTORY")
	if len(m.history) == 0 {
		return title + "\n\n" + styleMuted.Render("  No scans yet.")
	}
	var b strings.Builder
	b.WriteString("\n")
	for i, h := range m.history {
		gc := styleGood
		if h.score >= 60 {
			gc = styleBad
		} else if h.score >= 30 {
			gc = styleWarn
		}
		b.WriteString(fmt.Sprintf("  [%d]  %-30s  %s  Risk: %s\n",
			i+1, h.target, styleMuted.Render(h.timestamp.Format("15:04:05")),
			gc.Render(fmt.Sprintf("%d/100 (Grade %s)", h.score, h.grade))))
	}
	return title + b.String()
}

func (m Model) renderHelp(width int) string {
	title := styleHeader.Render("?  HELP & SHORTCUTS")
	help := `
  KEYBOARD SHORTCUTS
  ──────────────────────────────────────────────────
  ↑ / k          Move cursor up
  ↓ / j          Move cursor down
  Enter          Select menu item / confirm input
  q / Esc        Go back / quit

  QUICK KEYS (from anywhere)
  ──────────────────────────────────────────────────
  s              Open Scan screen
  d              DNS Analysis view
  l              SSL Review view
  h              HTTP Headers view
  t              Technology Fingerprint view
  r              Scan history
  ? / F1         This help screen
  Ctrl+C         Exit KitFind

  CLI COMMANDS (run outside TUI)
  ──────────────────────────────────────────────────
  kitfind scan example.com         Full scan
  kitfind dns example.com          DNS only
  kitfind ssl example.com          SSL only
  kitfind tech example.com         Tech fingerprint
  kitfind report example.com -f html  Generate report
  kitfind tui                      Open this TUI

  DISCLAIMER
  ──────────────────────────────────────────────────
  Only scan systems you own or have written
  permission to assess. Unauthorized scanning
  is illegal and unethical.
`
	return title + styleMuted.Render(help)
}


func runScan(target string) tea.Cmd {
	return func() tea.Msg {
		opts := scanner.DefaultOptions(target)
		ctx := context.Background()
		result, err := scanner.Run(ctx, opts, nil)
		return scanDoneMsg{result: result, err: err}
	}
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n-3] + "..."
}
