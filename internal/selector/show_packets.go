package selector

import (
	"github.com/nsf/termbox-go"
)

func PrintLine(x, y int, text string, attr termbox.Attribute) {
	for i, ch := range text {
		termbox.SetCell(x+i, y, ch, attr, termbox.ColorDefault)
	}
}

func PrintLineWithColor(x, y int, text string, fg, bg termbox.Attribute) {
	for i, ch := range text {
		termbox.SetCell(x+i, y, ch, fg, bg)
	}
}
