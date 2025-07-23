package main

import (
	"fmt"
	"github.com/miekg/dns"
	"github.com/nsf/termbox-go"
	"os"
)

func (app *App) run() {
	for {
		termbox.Clear(termbox.ColorDefault, termbox.ColorDefault)

		switch app.state {
		case StateList:
			app.renderList()
		case StateDetail:
			app.renderDetail()
		}

		termbox.Flush()

		ev := termbox.PollEvent()
		if ev.Type == termbox.EventKey {
			switch app.state {
			case StateList:
				app.handleListInput(ev)
			case StateDetail:
				app.handleDetailInput(ev)
			}
		}
	}
}

func (app *App) renderList() {
	_, h := termbox.Size()
	maxVisible := h - 3

	// Header
	printLine(0, 0, "Source IP         Dest IP           Type", termbox.ColorWhite|termbox.AttrBold)
	printLine(0, 1, "─────────────────────────────────────────────────", termbox.ColorWhite)

	// Adjust offset
	if app.selected < app.offset {
		app.offset = app.selected
	} else if app.selected >= app.offset+maxVisible {
		app.offset = app.selected - maxVisible + 1
	}

	// Display packets
	for i := 0; i < maxVisible && app.offset+i < len(app.packets); i++ {
		idx := app.offset + i
		p := app.packets[idx]
		line := fmt.Sprintf("%-17s %-17s %s", p.SrcIP, p.DstIP, p.Type)

		fg := termbox.ColorWhite
		bg := termbox.ColorDefault
		if idx == app.selected {
			fg = termbox.ColorBlack
			bg = termbox.ColorWhite
		}

		printLineWithColor(0, i+2, line, fg, bg)
	}

	// Instructions
	printLine(0, h-1, "↑/↓: Navigate  Enter: View Details  q: Quit", termbox.ColorYellow)
}

func (app *App) renderDetail() {
	if app.current == nil || app.current.Msg == nil {
		return
	}

	y := 0
	msg := app.current.Msg

	// Title
	printLine(0, y, "╔══════════════════╗", termbox.ColorCyan)
	y++
	printLine(0, y, fmt.Sprintf("║                 DNS PACKET DETAILS                   ║"), termbox.ColorCyan)
	y++
	printLine(0, y, "╚══════════════════╝", termbox.ColorCyan)
	y += 2

	// Packet Info
	printLine(0, y, "📦PACKET INFORMATION", termbox.ColorWhite|termbox.AttrBold)
	y++
	printLine(0, y, fmt.Sprintf("   Source: %s  → Destination: %s", app.current.SrcIP, app.current.DstIP), termbox.ColorWhite)
	y++
	printLine(0, y, fmt.Sprintf("   Type: %s | Size: %d bytes", app.current.Type, len(app.current.RawData)), termbox.ColorWhite)
	y += 2

	// Header Section
	printLine(0, y, "🏷️DNS HEADER", termbox.ColorWhite|termbox.AttrBold)
	y++
	y = app.renderHeader(msg, y)
	y++

	// Question Section
	if len(msg.Question) > 0 {
		printLine(0, y, "❓ QUESTION SECTION", termbox.ColorWhite|termbox.AttrBold)
		y++
		y = app.renderQuestions(msg.Question, y)
		y++
	}

	// Answer Section
	if len(msg.Answer) > 0 {
		printLine(0, y, fmt.Sprintf("✅ ANSWER SECTION (%d records)", len(msg.Answer)), termbox.ColorWhite|termbox.AttrBold)
		y++
		y = app.renderResourceRecords(msg.Answer, y)
		y++
	}

	// Authority Section
	if len(msg.Ns) > 0 {
		printLine(0, y, fmt.Sprintf("🏛️  AUTHORITY SECTION (%d records)", len(msg.Ns)), termbox.ColorWhite|termbox.AttrBold)
		y++
		y = app.renderResourceRecords(msg.Ns, y)
		y++
	}

	// Additional Section
	if len(msg.Extra) > 0 {
		printLine(0, y, fmt.Sprintf("➕ ADDITIONAL SECTION (%d records)", len(msg.Extra)), termbox.ColorWhite|termbox.AttrBold)
		y++
		y = app.renderResourceRecords(msg.Extra, y)
	}

	// Instructions at bottom
	_, h := termbox.Size()
	printLine(0, h-1, "Press 'q' to return to packet list", termbox.ColorYellow)
}

func (app *App) renderHeader(msg *dns.Msg, y int) int {
	// Create header box
	printLine(2, y, "├──────────────────", termbox.ColorWhite)
	y++

	// ID
	printLine(2, y, fmt.Sprintf("├ ID: %d ", msg.Id), termbox.ColorWhite)
	y++

	// QR Flag
	qrStr := "Query"
	if msg.Response {
		qrStr = "Response"
	}
	printLine(2, y, fmt.Sprintf("├ QR: %d (%s) ", boolToInt(msg.Response), qrStr), termbox.ColorWhite)
	y++

	// Opcode
	printLine(2, y, fmt.Sprintf("├ Opcode: %d (%s) ", msg.Opcode, dns.OpcodeToString[msg.Opcode]), termbox.ColorWhite)
	y++

	// AA Flag
	printLine(2, y, fmt.Sprintf("├ AA: %d (Authoritative Answer: %s) ", boolToInt(msg.Authoritative), boolToString(msg.Authoritative)), termbox.ColorWhite)
	y++

	// TC Flag
	printLine(2, y, fmt.Sprintf("├ TC: %d (Truncated: %s) ", boolToInt(msg.Truncated), boolToString(msg.Truncated)), termbox.ColorWhite)
	y++

	// RD Flag
	printLine(2, y, fmt.Sprintf("├ RD: %d (Recursion Desired: %s) ", boolToInt(msg.RecursionDesired), boolToString(msg.RecursionDesired)), termbox.ColorWhite)
	y++

	// RA Flag
	printLine(2, y, fmt.Sprintf("├ RA: %d (Recursion Available: %s) ", boolToInt(msg.RecursionAvailable), boolToString(msg.RecursionAvailable)), termbox.ColorWhite)
	y++

	// Z Flag
	printLine(2, y, fmt.Sprintf("├ Z: %d (Reserved - should be 0)", app.current.ZValue), termbox.ColorWhite)
	y++
	// Add warning if non-zero
	if app.current.ZValue != 0 {
		printLine(2, y, "├ ⚠️  WARNING: Non-zero Z value detected!      ", termbox.ColorRed|termbox.AttrBold)
		y++
	}

	// RCODE
	rcodeStr := dns.RcodeToString[msg.Rcode]
	printLine(2, y, fmt.Sprintf("├ RCODE: %d (%s) ", msg.Rcode, rcodeStr), termbox.ColorWhite)
	y++

	// Counts line
	printLine(2, y, "├──────────────────", termbox.ColorWhite)
	y++

	// Section counts
	printLine(2, y, fmt.Sprintf("├ Questions:  %d", len(msg.Question)), termbox.ColorWhite)
	y++
	printLine(2, y, fmt.Sprintf("├ Answers:    %d", len(msg.Answer)), termbox.ColorWhite)
	y++
	printLine(2, y, fmt.Sprintf("├ Authority:  %d", len(msg.Ns)), termbox.ColorWhite)
	y++
	printLine(2, y, fmt.Sprintf("├ Additional: %d", len(msg.Extra)), termbox.ColorWhite)
	y++

	printLine(2, y, "└──────────────────", termbox.ColorWhite)
	y++

	return y
}

func (app *App) renderQuestions(questions []dns.Question, y int) int {
	for i, q := range questions {
		printLine(2, y, fmt.Sprintf("%d. Name: %s", i+1, q.Name), termbox.ColorWhite)
		y++
		printLine(4, y, fmt.Sprintf("Type: %s (%d)", dns.TypeToString[q.Qtype], q.Qtype), termbox.ColorWhite)
		y++
		printLine(4, y, fmt.Sprintf("Class: %s (%d)", dns.ClassToString[q.Qclass], q.Qclass), termbox.ColorWhite)
		y++
	}
	return y
}

func (app *App) renderResourceRecords(records []dns.RR, y int) int {
	for i, rr := range records {
		// Format the record more nicely
		rrStr := rr.String()
		if len(rrStr) > 75 {
			rrStr = rrStr[:72] + "..."
		}
		printLine(2, y, fmt.Sprintf("%d. %s", i+1, rrStr), termbox.ColorWhite)
		y++
	}
	return y
}

func (app *App) handleListInput(ev termbox.Event) {
	switch ev.Key {
	case termbox.KeyArrowUp:
		if app.selected > 0 {
			app.selected--
		}
	case termbox.KeyArrowDown:
		if app.selected < len(app.packets)-1 {
			app.selected++
		}
	case termbox.KeyEnter:
		app.current = &app.packets[app.selected]
		app.state = StateDetail
	case termbox.KeyEsc:
		termbox.Close()
		os.Exit(0)
	default:
		if ev.Ch == 'q' || ev.Ch == 'Q' {
			termbox.Close()
			os.Exit(0)
		}
	}
}

func (app *App) handleDetailInput(ev termbox.Event) {
	if ev.Ch == 'q' || ev.Ch == 'Q' || ev.Key == termbox.KeyEsc {
		app.state = StateList
	}
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

func boolToString(b bool) string {
	if b {
		return "Yes"
	}
	return "No"
}

func printLine(x, y int, text string, attr termbox.Attribute) {
	for i, ch := range text {
		termbox.SetCell(x+i, y, ch, attr, termbox.ColorDefault)
	}
}

func printLineWithColor(x, y int, text string, fg, bg termbox.Attribute) {
	for i, ch := range text {
		termbox.SetCell(x+i, y, ch, fg, bg)
	}
}
