package annex7

import (
	"errors"
	"fmt"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
)

// wizardStep is which screen is on-screen: the section overview, or a
// single field within a section.
type wizardStep int

const (
	stepOverview wizardStep = iota
	stepField
)

// Model is the bubbletea Elm-architecture model driving the Annex VII
// wizard. Every confirmed field is written to disk immediately (see
// confirmField), so the on-disk file doubles as the session's own draft:
// there's no separate draft file to manage, and quitting at any point
// (Ctrl+C, 'q' from the overview, or just closing the terminal) leaves
// exactly as much progress on disk as was confirmed.
type Model struct {
	doc  *TechnicalFile
	path string
	step wizardStep

	cursor        int // section cursor, overview screen
	activeSection int // index into sections, while editing
	fieldIndex    int // index into sections[activeSection].fields, while editing
	selectCursor  int // cursor for fieldSelect/fieldBool choices
	// textBuffer is a plain string, not a strings.Builder: bubbletea's
	// Elm architecture copies Model by value on every Update call (it's
	// returned by value and reassigned each time), and strings.Builder's
	// internal copy-detection panics the moment a builder that's already
	// been written to gets written again from a new address — which is
	// exactly what happens here across Update calls.
	textBuffer string

	err error
}

func newModel(doc *TechnicalFile, path string) Model {
	return Model{doc: doc, path: path, step: stepOverview}
}

// Run launches the interactive Annex VII wizard over doc, saving to path
// after every confirmed field, and returns the resulting document.
func Run(doc *TechnicalFile, path string) (*TechnicalFile, error) {
	// Persist immediately so a scaffold always produces a file on disk,
	// even if the operator quits before touching anything.
	if err := Save(doc, path); err != nil {
		return nil, err
	}

	finalModel, err := tea.NewProgram(newModel(doc, path)).Run()
	if err != nil {
		return nil, fmt.Errorf("running annex7 wizard: %w", err)
	}
	fm, ok := finalModel.(Model)
	if !ok {
		return nil, errors.New("annex7 wizard returned an unexpected model type")
	}
	if fm.err != nil {
		return nil, fm.err
	}
	return fm.doc, nil
}

func (m Model) Init() tea.Cmd { return nil }

func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	keyMsg, ok := msg.(tea.KeyMsg)
	if !ok {
		return m, nil
	}
	if keyMsg.Type == tea.KeyCtrlC {
		return m, tea.Quit
	}

	switch m.step {
	case stepOverview:
		return m.updateOverview(keyMsg)
	default:
		return m.updateField(keyMsg)
	}
}

func (m Model) updateOverview(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "q":
		return m, tea.Quit
	case "up", "k":
		m.cursor = (m.cursor - 1 + len(sections)) % len(sections)
	case "down", "j":
		m.cursor = (m.cursor + 1) % len(sections)
	case "enter":
		m.step = stepField
		m.activeSection = m.cursor
		m.fieldIndex = 0
		m = m.prepareCurrentField()
	}
	return m, nil
}

func (m Model) updateField(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	if msg.Type == tea.KeyEsc {
		m.step = stepOverview
		m.cursor = m.activeSection
		return m, nil
	}

	f := sections[m.activeSection].fields[m.fieldIndex]
	if f.isChoice() {
		return m.updateChoiceField(msg, f)
	}
	return m.updateTextField(msg, f)
}

func (m Model) updateChoiceField(msg tea.KeyMsg, f field) (tea.Model, tea.Cmd) {
	options := f.choiceOptions()
	switch msg.String() {
	case "up", "k":
		m.selectCursor = (m.selectCursor - 1 + len(options)) % len(options)
	case "down", "j":
		m.selectCursor = (m.selectCursor + 1) % len(options)
	case "enter":
		return m.confirmField(options[m.selectCursor])
	}
	return m, nil
}

// updateTextField handles the free-text and comma-list fields. 'q' is
// intentionally not a quit key here so it can be typed as ordinary text.
func (m Model) updateTextField(msg tea.KeyMsg, _ field) (tea.Model, tea.Cmd) {
	switch msg.Type {
	case tea.KeyEnter:
		return m.confirmField(strings.TrimSpace(m.textBuffer))
	case tea.KeyBackspace, tea.KeyDelete:
		if r := []rune(m.textBuffer); len(r) > 0 {
			m.textBuffer = string(r[:len(r)-1])
		}
	case tea.KeySpace:
		m.textBuffer += " "
	case tea.KeyRunes:
		m.textBuffer += string(msg.Runes)
	}
	return m, nil
}

// confirmField stores value into the active field, saves the document to
// disk right away, and advances to the next field (or back to the overview
// once the section's last field is confirmed).
func (m Model) confirmField(value string) (tea.Model, tea.Cmd) {
	f := sections[m.activeSection].fields[m.fieldIndex]
	f.set(m.doc, value)

	if err := Save(m.doc, m.path); err != nil {
		m.err = err
		return m, tea.Quit
	}

	m.fieldIndex++
	if m.fieldIndex >= len(sections[m.activeSection].fields) {
		m.step = stepOverview
		m.cursor = m.activeSection
		return m, nil
	}
	return m.prepareCurrentField(), nil
}

// prepareCurrentField seeds the input widget for sections[m.activeSection]
// .fields[m.fieldIndex] from its currently stored value, so re-opening an
// already-answered field (typical during --edit) shows what's there rather
// than a blank prompt.
func (m Model) prepareCurrentField() Model {
	f := sections[m.activeSection].fields[m.fieldIndex]
	m.textBuffer = ""
	m.selectCursor = 0

	if f.isChoice() {
		current := f.get(m.doc)
		for i, opt := range f.choiceOptions() {
			if opt == current {
				m.selectCursor = i
				break
			}
		}
		return m
	}

	m.textBuffer = f.get(m.doc)
	return m
}
