package tui

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

const (
	maxEventsPerTab = 4096
	maxEPSWindow    = 512
)

var (
	titleStyle       = lipgloss.NewStyle().Bold(true)
	headerStyle      = lipgloss.NewStyle().Foreground(lipgloss.Color("6")).Bold(true)
	tabActiveStyle   = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("0")).Background(lipgloss.Color("7")).Padding(0, 1)
	tabInactiveStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("8")).Padding(0, 1)
	cursorStyle      = lipgloss.NewStyle().Foreground(lipgloss.Color("6")).Bold(true)
	selectedStyle    = lipgloss.NewStyle()
	detailBoxStyle   = lipgloss.NewStyle().Border(lipgloss.RoundedBorder()).BorderForeground(lipgloss.Color("8")).Padding(0, 1)
	footerStyle      = lipgloss.NewStyle().Foreground(lipgloss.Color("6")).Bold(true)
	separatorStyle   = lipgloss.NewStyle().Foreground(lipgloss.Color("8"))
)

type batchMsg struct {
	records []displayRecord
}

type tailErrMsg struct {
	err error
}

type spinnerTickMsg struct{}

type streamClosedMsg struct{}

type displayRecord struct {
	Endpoint  string
	Timestamp time.Time
	Summary   string
	Detail    string
}

type model struct {
	path          string
	stream        <-chan tea.Msg
	width         int
	height        int
	recordsByTab  map[string][]displayRecord
	selectedByTab map[string]int
	tabIndex      int
	totalEvents   int
	eventTimes    []time.Time
	showDetail    bool
	confirmQuit   bool
	spinnerIndex  int
	err           error
}

func Run(ctx context.Context, path string) error {
	streamMessages := make(chan tea.Msg, 32)
	m := model{
		path:          path,
		stream:        streamMessages,
		recordsByTab:  make(map[string][]displayRecord),
		selectedByTab: make(map[string]int),
	}

	p := tea.NewProgram(m, tea.WithAltScreen(), tea.WithContext(ctx))
	go streamFile(ctx, path, streamMessages)
	_, err := p.Run()
	if err != nil {
		return err
	}
	return nil
}

func (m model) Init() tea.Cmd {
	return tea.Batch(tickSpinner(), m.waitForStream())
}

func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
	case tea.KeyMsg:
		if m.confirmQuit {
			switch msg.String() {
			case "ctrl+c", "y", "Y", "enter":
				return m, tea.Quit
			case "q", "Q", "n", "N", "esc":
				m.confirmQuit = false
			}
			return m, nil
		}
		switch msg.String() {
		case "ctrl+c":
			return m, tea.Quit
		case "q":
			m.confirmQuit = true
		case "tab", "l":
			m.tabIndex = (m.tabIndex + 1) % len(tabOrder)
			m.showDetail = false
		case "shift+tab", "h":
			m.tabIndex = (m.tabIndex - 1 + len(tabOrder)) % len(tabOrder)
			m.showDetail = false
		case "j", "down":
			m.moveSelection(1)
		case "k", "up":
			m.moveSelection(-1)
		case "G", "end":
			m.moveSelectionToBottom()
		case "v", "enter":
			if len(m.currentRecords()) > 0 {
				m.showDetail = !m.showDetail
			}
		}
	case spinnerTickMsg:
		m.spinnerIndex = (m.spinnerIndex + 1) % len(spinnerFrames)
		return m, tickSpinner()
	case batchMsg:
		for _, record := range msg.records {
			m.totalEvents++
			m.eventTimes = append(m.eventTimes, record.Timestamp)
			if len(m.eventTimes) > maxEPSWindow {
				m.eventTimes = m.eventTimes[len(m.eventTimes)-maxEPSWindow:]
			}
			m.appendRecord(allTab, record)
			m.appendRecord(record.Endpoint, record)
		}
		return m, m.waitForStream()
	case tailErrMsg:
		m.err = msg.err
		return m, m.waitForStream()
	case streamClosedMsg:
		return m, nil
	}
	return m, nil
}

func (m model) View() string {
	if m.width == 0 || m.height == 0 {
		return "loading TUI..."
	}

	bodyHeight := max(6, m.height-7)
	listHeight := bodyHeight
	detail := ""
	if m.showDetail {
		listHeight = bodyHeight / 2
		detail = m.renderDetail(bodyHeight - listHeight)
	}

	parts := []string{
		m.renderHeader(),
		m.renderDivider(),
		m.renderTabs(),
		m.renderList(listHeight),
	}
	if detail != "" {
		parts = append(parts, detail)
	}
	parts = append(parts, m.renderDivider(), m.renderFooter())

	if m.confirmQuit {
		return m.renderQuitConfirm()
	}
	return strings.Join(parts, "\n")
}

func (m *model) appendRecord(tab string, record displayRecord) {
	m.recordsByTab[tab] = append(m.recordsByTab[tab], record)
	if len(m.recordsByTab[tab]) > maxEventsPerTab {
		m.recordsByTab[tab] = m.recordsByTab[tab][len(m.recordsByTab[tab])-maxEventsPerTab:]
	}
	if m.selectedByTab[tab] >= len(m.recordsByTab[tab]) {
		m.selectedByTab[tab] = len(m.recordsByTab[tab]) - 1
	}
}

func (m *model) moveSelection(delta int) {
	records := m.currentRecords()
	if len(records) == 0 {
		return
	}
	tab := m.currentTab()
	next := max(0, m.selectedByTab[tab]+delta)
	if next >= len(records) {
		next = len(records) - 1
	}
	m.selectedByTab[tab] = next
}

func (m *model) moveSelectionToBottom() {
	records := m.currentRecords()
	if len(records) == 0 {
		return
	}
	m.selectedByTab[m.currentTab()] = len(records) - 1
}

func (m model) currentTab() string {
	return tabOrder[m.tabIndex]
}

func (m model) currentRecords() []displayRecord {
	return m.recordsByTab[m.currentTab()]
}

func (m model) renderTabs() string {
	tabs := make([]string, 0, len(tabOrder))
	for i, tab := range tabOrder {
		label := tab
		if i == m.tabIndex {
			tabs = append(tabs, tabActiveStyle.Render(label))
			continue
		}
		tabs = append(tabs, tabInactiveStyle.Render(label))
	}
	return lipgloss.JoinHorizontal(lipgloss.Left, tabs...)
}

func (m model) renderList(height int) string {
	records := m.currentRecords()
	if len(records) == 0 {
		return detailBoxStyle.Width(max(1, m.width-2)).Height(height).Render("starting watchu... waiting for probe attach and first events")
	}

	selected := m.selectedByTab[m.currentTab()]
	start := 0
	if selected >= height {
		start = selected - height + 1
	}
	end := min(len(records), start+height)

	lines := make([]string, 0, end-start)
	for i := start; i < end; i++ {
		record := records[i]
		line := m.renderRecordLine(record, i == selected)
		if i == selected {
			line = selectedStyle.Width(max(0, m.width-4)).Render(line)
		}
		lines = append(lines, line)
	}

	return detailBoxStyle.Width(max(1, m.width-2)).Height(height).Render(strings.Join(lines, "\n"))
}

func (m model) renderHeader() string {
	fileName := truncateText(filepath.Base(m.path), max(24, m.width/2))
	status := fmt.Sprintf("total events: %d (%.2f e/s)", m.totalEvents, m.eventsPerSecond())
	header := fmt.Sprintf("watchu %s  [%s] %s", fileName, spinnerFrames[m.spinnerIndex], status)
	if m.err != nil {
		header = header + "  " + truncateText(m.err.Error(), max(16, m.width/4))
	}
	return headerStyle.Render(header)
}

func (m model) renderDivider() string {
	if m.width <= 0 {
		return ""
	}
	return separatorStyle.Render(strings.Repeat("─", m.width))
}

func (m model) renderFooter() string {
	footer := "j/k: move  |  G: bottom  |  tab/h/l: switch tab  |  v: toggle details  |  q: quit (confirm) | ctrl-c: quit"
	return footerStyle.Render(footer)
}

func (m model) renderQuitConfirm() string {
	dialog := detailBoxStyle.Render("Quit watchu?\n\nEnter/y: confirm\nEsc/n/q: cancel\nCtrl-C: quit now")
	return lipgloss.Place(
		m.width,
		m.height,
		lipgloss.Center,
		lipgloss.Center,
		dialog,
		lipgloss.WithWhitespaceChars(" "),
		lipgloss.WithWhitespaceForeground(lipgloss.Color("8")),
	)
}

func (m model) renderRecordLine(record displayRecord, selected bool) string {
	style := endpointDefinitionFor(record.Endpoint).Style
	ts := record.Timestamp.Format("15:04:05")
	label := style.Render(record.Endpoint)
	cursor := "  "
	if selected {
		cursor = cursorStyle.Render("> ")
	}
	prefix := lipgloss.JoinHorizontal(lipgloss.Left, cursor, ts+" ", label, " ")
	summaryWidth := max(0, m.width-4-lipgloss.Width(prefix))
	return lipgloss.JoinHorizontal(lipgloss.Left, prefix, truncateText(record.Summary, summaryWidth))
}

func (m model) waitForStream() tea.Cmd {
	if m.stream == nil {
		return nil
	}
	return waitForStream(m.stream)
}

func (m model) renderDetail(height int) string {
	records := m.currentRecords()
	if len(records) == 0 {
		return ""
	}
	record := records[m.selectedByTab[m.currentTab()]]
	title := titleStyle.Render(fmt.Sprintf("%s  %s", record.Endpoint, record.Timestamp.Format(time.RFC3339)))
	detail := strings.TrimSpace(record.Detail)
	if detail == "" {
		detail = "{}"
	}
	box := detailBoxStyle.Width(max(1, m.width-2)).Height(height).Render(title + "\n" + clampLines(detail, height-2))
	return box
}

func (m model) eventsPerSecond() float64 {
	if len(m.eventTimes) == 0 {
		return 0
	}
	cutoff := time.Now().Add(-time.Second)
	count := 0
	for i := len(m.eventTimes) - 1; i >= 0; i-- {
		if m.eventTimes[i].Before(cutoff) {
			break
		}
		count++
	}
	return float64(count)
}

func tickSpinner() tea.Cmd {
	return tea.Tick(120*time.Millisecond, func(time.Time) tea.Msg {
		return spinnerTickMsg{}
	})
}

func clampLines(s string, height int) string {
	if height <= 0 {
		return ""
	}
	lines := strings.Split(s, "\n")
	if len(lines) <= height {
		return s
	}
	return strings.Join(lines[:height], "\n")
}

func truncateText(s string, width int) string {
	if width <= 0 {
		return ""
	}
	runes := []rune(s)
	if len(runes) <= width {
		return s
	}
	if width == 1 {
		return "…"
	}
	return string(runes[:width-1]) + "…"
}
