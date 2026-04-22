package tui

import (
	"context"
	"fmt"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/viewport"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

const (
	maxEventsPerTab = 4096
	maxEPSWindow    = 512
	listScrollOff   = 3
)

var (
	titleStyle        = lipgloss.NewStyle().Bold(true)
	headerStyle       = lipgloss.NewStyle().Foreground(lipgloss.Color("6")).Bold(true)
	tabActiveStyle    = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("6")).Background(lipgloss.Color("7")).Padding(0, 1)
	tabInactiveStyle  = lipgloss.NewStyle().Foreground(lipgloss.Color("8")).Padding(0, 1)
	cursorStyle       = lipgloss.NewStyle().Foreground(lipgloss.Color("6")).Bold(true)
	selectedStyle     = lipgloss.NewStyle()
	detailBoxStyle    = lipgloss.NewStyle().Border(lipgloss.RoundedBorder()).BorderForeground(lipgloss.Color("8")).Padding(0, 1)
	footerStyle       = lipgloss.NewStyle().Foreground(lipgloss.Color("6")).Bold(true)
	separatorStyle    = lipgloss.NewStyle().Foreground(lipgloss.Color("8"))
	sessionLinkStyles = []lipgloss.Style{
		lipgloss.NewStyle().Foreground(lipgloss.CompleteColor{TrueColor: "#A5B4FC", ANSI256: "147", ANSI: "4"}),
		lipgloss.NewStyle().Foreground(lipgloss.CompleteColor{TrueColor: "#86EFAC", ANSI256: "120", ANSI: "2"}),
		lipgloss.NewStyle().Foreground(lipgloss.CompleteColor{TrueColor: "#67E8F9", ANSI256: "81", ANSI: "6"}),
		lipgloss.NewStyle().Foreground(lipgloss.CompleteColor{TrueColor: "#C4B5FD", ANSI256: "183", ANSI: "5"}),
		lipgloss.NewStyle().Foreground(lipgloss.CompleteColor{TrueColor: "#F9A8D4", ANSI256: "218", ANSI: "5"}),
	}
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
	Endpoint   string
	Timestamp  time.Time
	SessionKey string
	Summary    string
	Detail     string
}

type viewLayout struct {
	header     string
	divider    string
	tabs       string
	footer     string
	bodyHeight int
}

type sessionPairCache struct {
	pairs       []pairInterval
	maxLevel    int
	recordCount int
	valid       bool
}

type model struct {
	path           string
	stream         <-chan tea.Msg
	width          int
	height         int
	recordsByTab   map[string][]displayRecord
	selectedByTab  map[string]int
	listStartByTab map[string]int
	tabIndex       int
	totalEvents    int
	eventTimes     []time.Time
	showDetail     bool
	detailViewport viewport.Model
	allTabPairs    sessionPairCache
	confirmQuit    bool
	spinnerIndex   int
	err            error
}

func Run(ctx context.Context, path string) error {
	streamMessages := make(chan tea.Msg, 32)
	m := model{
		path:           path,
		stream:         streamMessages,
		recordsByTab:   make(map[string][]displayRecord),
		selectedByTab:  make(map[string]int),
		listStartByTab: make(map[string]int),
		detailViewport: viewport.New(0, 0),
	}
	m.detailViewport.Style = detailBoxStyle

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
		m.syncDetailViewport(false)
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
			m.syncDetailViewport(true)
		case "shift+tab", "h":
			m.tabIndex = (m.tabIndex - 1 + len(tabOrder)) % len(tabOrder)
			m.showDetail = false
			m.syncDetailViewport(true)
		case "j", "down":
			if m.showDetail {
				m.detailViewport.ScrollDown(1)
				break
			}
			m.moveSelection(1)
		case "k", "up":
			if m.showDetail {
				m.detailViewport.ScrollUp(1)
				break
			}
			m.moveSelection(-1)
		case "G", "end":
			if m.showDetail {
				m.detailViewport.GotoBottom()
				break
			}
			m.moveSelectionToBottom()
		case "g", "home":
			if m.showDetail {
				m.detailViewport.GotoTop()
			}
		case "v", "enter":
			if len(m.currentRecords()) > 0 {
				m.showDetail = !m.showDetail
				m.syncDetailViewport(true)
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
		m.refreshAllTabPairCache()
		m.syncDetailViewport(false)
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

	layout := m.computeLayout()

	parts := []string{
		layout.header,
		layout.divider,
		layout.tabs,
	}
	if m.showDetail {
		parts = append(parts, m.renderDetail(layout.bodyHeight))
	} else {
		parts = append(parts, m.renderList(layout.bodyHeight))
	}
	parts = append(parts, layout.divider, layout.footer)

	if m.confirmQuit {
		return m.renderQuitConfirm()
	}
	return strings.Join(parts, "\n")
}

func (m *model) appendRecord(tab string, record displayRecord) {
	records := m.recordsByTab[tab]
	selected := m.selectedByTab[tab]
	listStart := m.listStartByTab[tab]
	insertAt := sort.Search(len(records), func(i int) bool {
		return records[i].Timestamp.After(record.Timestamp)
	})
	records = slices.Insert(records, insertAt, record)
	if len(records) > 1 && insertAt <= selected {
		selected++
	}
	if len(records) > 1 && insertAt <= listStart {
		listStart++
	}
	m.recordsByTab[tab] = records
	if len(records) > maxEventsPerTab {
		dropped := len(records) - maxEventsPerTab
		m.recordsByTab[tab] = records[dropped:]
		selected -= dropped
		listStart -= dropped
	}
	if selected >= len(m.recordsByTab[tab]) {
		selected = len(m.recordsByTab[tab]) - 1
	}
	maxStart := max(0, len(m.recordsByTab[tab])-1)
	if listStart > maxStart {
		listStart = maxStart
	}
	m.selectedByTab[tab] = max(0, selected)
	m.listStartByTab[tab] = max(0, listStart)
	if tab == allTab {
		m.allTabPairs.valid = false
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
	m.syncDetailViewport(true)
}

func (m *model) moveSelectionToBottom() {
	records := m.currentRecords()
	if len(records) == 0 {
		return
	}
	m.selectedByTab[m.currentTab()] = len(records) - 1
	m.syncDetailViewport(true)
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
	contentWidth := m.panelContentWidth()
	listViewport := viewport.New(max(1, m.width), max(1, height))
	listViewport.Style = detailBoxStyle
	contentHeight := max(1, height-detailBoxStyle.GetVerticalFrameSize())
	if len(records) == 0 {
		listViewport.SetContent("starting watchu... waiting for probe attach and first events")
		return listViewport.View()
	}

	selected := m.selectedByTab[m.currentTab()]
	start := m.adjustListStart(len(records), contentHeight, selected)
	end := min(len(records), start+contentHeight)
	annotations := make([]pairLineAnnotation, end-start)
	if m.currentTab() == allTab {
		pairs, maxLevel := m.allTabSessionPairs()
		annotations = buildVisiblePairAnnotations(start, end, pairs, maxLevel)
	}

	lines := make([]string, 0, end-start)
	for i := start; i < end; i++ {
		record := records[i]
		line := m.renderRecordLine(record, annotations[i-start], i == selected, contentWidth)
		if i == selected {
			line = selectedStyle.Width(contentWidth).Render(line)
		}
		lines = append(lines, line)
	}

	listViewport.SetContent(strings.Join(lines, "\n"))
	return listViewport.View()
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
	if m.showDetail {
		footer = "j/k: scroll detail  |  g/G: top/bottom detail  |  v: close detail  |  tab/h/l: switch tab"
	}
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

func (m model) renderRecordLine(record displayRecord, annotation pairLineAnnotation, selected bool, contentWidth int) string {
	style := endpointDefinitionFor(record.Endpoint).Style
	ts := record.Timestamp.Format("15:04:05")
	label := style.Render(record.Endpoint)
	cursor := "  "
	if selected {
		cursor = cursorStyle.Render("> ")
	}
	link := renderPairLink(annotation)
	prefix := lipgloss.JoinHorizontal(lipgloss.Left, cursor, ts+" ", link, label, " ")
	summaryWidth := max(0, contentWidth-lipgloss.Width(prefix))
	return lipgloss.JoinHorizontal(lipgloss.Left, prefix, truncateText(record.Summary, summaryWidth))
}

func renderPairLink(annotation pairLineAnnotation) string {
	if len(annotation.Columns) == 0 {
		return ""
	}

	var out strings.Builder
	for idx, column := range annotation.Columns {
		switch column {
		case pairLinkDot:
			out.WriteString(sessionLinkStyleForLevel(idx).Render("● "))
		case pairLinkPipe:
			out.WriteString(sessionLinkStyleForLevel(idx).Render("┊ "))
		default:
			out.WriteString("  ")
		}
	}
	return out.String()
}

func sessionLinkStyleForLevel(level int) lipgloss.Style {
	if len(sessionLinkStyles) == 0 {
		return lipgloss.NewStyle()
	}
	return sessionLinkStyles[level%len(sessionLinkStyles)]
}

func (m model) waitForStream() tea.Cmd {
	if m.stream == nil {
		return nil
	}
	return waitForStream(m.stream)
}

func (m model) renderDetail(height int) string {
	if !m.showDetail {
		return ""
	}
	vp := m.detailViewport
	vp.Width = max(1, m.width)
	vp.Height = max(1, height)
	vp.Style = detailBoxStyle
	return vp.View()
}

func (m model) panelContentWidth() int {
	return max(1, m.width-detailBoxStyle.GetHorizontalFrameSize())
}

func (m *model) adjustListStart(total, height, selected int) int {
	tab := m.currentTab()
	start := m.listStartByTab[tab]
	if total <= 0 || height <= 0 {
		m.listStartByTab[tab] = 0
		return 0
	}

	maxStart := max(0, total-height)
	if start > maxStart {
		start = maxStart
	}
	if start < 0 {
		start = 0
	}

	scrolloff := min(listScrollOff, max(0, height-1))
	if selected < start+scrolloff {
		start = max(0, selected-scrolloff)
	}
	lowerBound := start + height - 1 - scrolloff
	if selected > lowerBound {
		start = min(maxStart, selected-(height-1-scrolloff))
	}

	m.listStartByTab[tab] = start
	return start
}

func (m *model) syncDetailViewport(resetScroll bool) {
	layout := m.computeLayout()
	m.detailViewport.Width = max(1, m.width)
	m.detailViewport.Height = max(1, layout.bodyHeight)
	m.detailViewport.Style = detailBoxStyle
	m.detailViewport.SetContent(m.wrappedDetailContent())
	if resetScroll {
		m.detailViewport.GotoTop()
	}
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

func normalizedDetail(detail string) string {
	detail = strings.TrimSpace(detail)
	if detail == "" {
		return "{}"
	}
	return detail
}

func (m model) currentDetailContent() string {
	records := m.currentRecords()
	if len(records) == 0 {
		return ""
	}
	record := records[m.selectedByTab[m.currentTab()]]
	title := titleStyle.Render(fmt.Sprintf("%s  %s", record.Endpoint, record.Timestamp.Format(time.RFC3339)))
	return title + "\n" + normalizedDetail(record.Detail)
}

func (m model) wrappedDetailContent() string {
	return lipgloss.NewStyle().Width(m.panelContentWidth()).Render(m.currentDetailContent())
}

func (m *model) refreshAllTabPairCache() {
	pairs, maxLevel := buildSessionPairs(m.recordsByTab[allTab])
	m.allTabPairs = sessionPairCache{
		pairs:       pairs,
		maxLevel:    maxLevel,
		recordCount: len(m.recordsByTab[allTab]),
		valid:       true,
	}
}

func (m model) allTabSessionPairs() ([]pairInterval, int) {
	if m.allTabPairs.valid && m.allTabPairs.recordCount == len(m.recordsByTab[allTab]) {
		return m.allTabPairs.pairs, m.allTabPairs.maxLevel
	}
	return buildSessionPairs(m.recordsByTab[allTab])
}

func (m model) computeLayout() viewLayout {
	layout := viewLayout{
		header:  m.renderHeader(),
		divider: m.renderDivider(),
		tabs:    m.renderTabs(),
		footer:  m.renderFooter(),
	}
	if m.height <= 0 {
		layout.bodyHeight = 1
		return layout
	}
	chromeHeight := lipgloss.Height(layout.header) +
		lipgloss.Height(layout.divider) +
		lipgloss.Height(layout.tabs) +
		lipgloss.Height(layout.divider) +
		lipgloss.Height(layout.footer)
	layout.bodyHeight = max(1, m.height-chromeHeight)
	return layout
}
