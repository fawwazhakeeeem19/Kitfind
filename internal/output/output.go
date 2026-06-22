

package output

import (
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/fatih/color"
	"github.com/olekukonko/tablewriter"
)


var (
	Cyan    = color.New(color.FgCyan, color.Bold)
	Green   = color.New(color.FgGreen, color.Bold)
	Yellow  = color.New(color.FgYellow, color.Bold)
	Red     = color.New(color.FgRed, color.Bold)
	Magenta = color.New(color.FgMagenta, color.Bold)
	White   = color.New(color.FgWhite, color.Bold)
	Dim     = color.New(color.Faint)

	Info    = color.New(color.FgCyan)
	Success = color.New(color.FgGreen)
	Warn    = color.New(color.FgYellow)
	Danger  = color.New(color.FgRed)
)

const (
	boxH  = "─"
	boxV  = "│"
	boxTL = "╔"
	boxTR = "╗"
	boxBL = "╚"
	boxBR = "╝"
	boxLT = "╠"
	boxRT = "╣"
	boxHD = "═"
	bullet = "◆"
	arrow  = "→"
	check  = "✓"
	cross  = "✗"
	warn   = "⚠"
	info   = "ℹ"
)


func Banner() {
	Cyan.Println(`
 ██╗  ██╗██╗████████╗███████╗██╗███╗   ██╗██████╗
 ██║ ██╔╝██║╚══██╔══╝██╔════╝██║████╗  ██║██╔══██╗
 █████╔╝ ██║   ██║   █████╗  ██║██╔██╗ ██║██║  ██║
 ██╔═██╗ ██║   ██║   ██╔══╝  ██║██║╚██╗██║██║  ██║
 ██║  ██╗██║   ██║   ██║     ██║██║ ╚████║██████╔╝
 ╚═╝  ╚═╝╚═╝   ╚═╝   ╚═╝     ╚═╝╚═╝  ╚═══╝╚═════╝`)
	Dim.Printf("                     v1.0.0  %s\n\n", time.Now().Format("2006-01-02"))
	Dim.Println(" Security Reconnaissance Tool — Authorized Use Only")
	fmt.Println()
}


func SectionHeader(title string) {
	width := 60
	line := strings.Repeat(boxHD, width-2)
	Cyan.Printf("\n╔%s╗\n", line)
	padding := width - 2 - len(title) - 2
	left := padding / 2
	right := padding - left
	Cyan.Printf("║ %s%s%s ║\n", strings.Repeat(" ", left), title, strings.Repeat(" ", right))
	Cyan.Printf("╚%s╝\n", line)
}


func Progress(module, msg string) {
	Cyan.Printf("  %s %-14s", bullet, "["+module+"]")
	fmt.Println(msg)
}


func OK(msg string) {
	Green.Printf("  %s %s\n", check, msg)
}


func Warning(msg string) {
	Yellow.Printf("  %s %s\n", warn, msg)
}


func Error(msg string) {
	Red.Printf("  %s %s\n", cross, msg)
}


func InfoLine(msg string) {
	Dim.Printf("  %s %s\n", info, msg)
}


func KV(key, value string) {
	White.Printf("  %-28s", key+":")
	fmt.Println(value)
}


func KVColour(key string, value string, c *color.Color) {
	White.Printf("  %-28s", key+":")
	c.Println(value)
}


func Table(headers []string, rows [][]string) {
	t := tablewriter.NewWriter(os.Stdout)
	t.SetHeader(headers)
	t.SetBorder(true)
	t.SetCenterSeparator("┼")
	t.SetColumnSeparator("│")
	t.SetRowSeparator("─")
	t.SetHeaderColor(
		tablewriter.Colors{tablewriter.Bold, tablewriter.FgCyanColor},
		tablewriter.Colors{tablewriter.Bold, tablewriter.FgCyanColor},
		tablewriter.Colors{tablewriter.Bold, tablewriter.FgCyanColor},
	)
	t.SetHeaderLine(true)
	t.SetAutoWrapText(false)
	t.AppendBulk(rows)
	t.Render()
}


func TableWriter(w io.Writer, headers []string) *tablewriter.Table {
	t := tablewriter.NewWriter(w)
	t.SetHeader(headers)
	t.SetBorder(true)
	t.SetCenterSeparator("┼")
	t.SetColumnSeparator("│")
	t.SetRowSeparator("─")
	t.SetHeaderLine(true)
	return t
}


func SeverityColour(sev string) *color.Color {
	switch strings.ToLower(sev) {
	case "critical":
		return color.New(color.FgRed, color.Bold, color.BgBlack)
	case "high":
		return color.New(color.FgRed)
	case "medium":
		return color.New(color.FgYellow)
	case "low":
		return color.New(color.FgBlue)
	default:
		return Dim
	}
}


func SeverityBadge(sev string) string {
	c := SeverityColour(sev)
	return c.Sprintf("%-8s", strings.ToUpper(sev))
}


func StatusBadge(status string) string {
	switch strings.ToLower(status) {
	case "good":
		return Green.Sprint("✓ GOOD   ")
	case "warning":
		return Yellow.Sprint("⚠ WARNING")
	case "missing", "bad":
		return Red.Sprint("✗ MISSING")
	default:
		return Dim.Sprint("  INFO   ")
	}
}


func RiskGradeBanner(score int, grade string) {
	var c *color.Color
	switch grade {
	case "A":
		c = Green
	case "B":
		c = color.New(color.FgGreen)
	case "C":
		c = Yellow
	case "D":
		c = color.New(color.FgRed)
	case "F":
		c = Danger
	default:
		c = Dim
	}

	fmt.Println()
	SectionHeader("RISK ASSESSMENT")
	fmt.Printf("\n  Risk Score:  ")
	c.Printf("%d / 100\n", score)
	fmt.Printf("  Risk Grade:  ")
	c.Printf("%s\n", grade)

	bar := riskBar(score)
	fmt.Printf("  Risk Level:  %s\n\n", bar)
}

func riskBar(score int) string {
	width := 40
	filled := score * width / 100
	var c *color.Color
	switch {
	case score >= 70:
		c = Danger
	case score >= 40:
		c = Yellow
	default:
		c = Green
	}
	bar := c.Sprint(strings.Repeat("█", filled))
	empty := Dim.Sprint(strings.Repeat("░", width-filled))
	return "[" + bar + empty + "]"
}


func Divider() {
	Dim.Println("  " + strings.Repeat("─", 60))
}


func PrintScanMeta(target string, started time.Time) {
	fmt.Println()
	KV("Target", target)
	KV("Started At", started.Format("2006-01-02 15:04:05 MST"))
	Divider()
}


func PrintDuration(d time.Duration) {
	Dim.Printf("\n  Scan completed in %s\n\n", d.Round(time.Millisecond))
}
