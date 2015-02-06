package main

import (
    "fmt"
    "os"
    "strings"
)

type ProgressBar struct {
    Width    int
    Progress int
    Total    int
    Title    string

    progress chan int
    total    chan int
    end      chan int
}

func NewProgressBar(title string, width int) *ProgressBar {
    return &ProgressBar{
        Width:    width,
        Title:    title + ": ",
        total:    make(chan int),
        progress: make(chan int),
        end:      make(chan int),
    }
}

func (p *ProgressBar) Render() {
    dots := 0
    left := ""
    if p.Total > 0 {
        dots = int((float64(p.Progress) / float64(p.Total)) * float64(p.Width))
    }
    if dots > 0 {
        left = strings.Repeat("=", dots-1) + ">"
    }
    right := strings.Repeat(" ", p.Width-dots)
    fmt.Fprintf(os.Stderr, "%s[%s%s]", p.Title, left, right)
}

func (p *ProgressBar) DisplayWidth() int {
    return len(p.Title) + p.Width + 2
}

func (p *ProgressBar) ResetCursor() {
    back := strings.Repeat("\b", p.DisplayWidth())
    fmt.Fprintf(os.Stderr, "%s", back)
}

func (p *ProgressBar) Erase() {
    p.ResetCursor()
    clear := strings.Repeat(" ", p.DisplayWidth())
    fmt.Fprintf(os.Stderr, "%s", clear)
    p.ResetCursor()
}

func (p *ProgressBar) Start() {
    p.Render()
    go func() {
        for {
            select {
            case n := <-p.total:
                p.Total += n
                p.ResetCursor()
                p.Render()
            case n := <-p.progress:
                p.Progress += n
                p.ResetCursor()
                p.Render()
            case <-p.end:
                close(p.total)
                close(p.progress)
                p.end <- 1
                close(p.end)
                return
            }
        }
    }()
}

func (p *ProgressBar) End() {
    p.end <- 1
    <-p.end
}

func (p *ProgressBar) AddTotal(n int) {
    p.total <- n
}

func (p *ProgressBar) AddProgress(n int) {
    p.progress <- n
}
