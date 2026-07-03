// Package vextriage is an interactive terminal UI (bubbletea/lipgloss) for
// walking through vulnscan findings one vulnerability at a time and
// recording a manufacturer's VEX triage decision for each: the human step
// that "crasec vex generate" needs before it can emit a CycloneDX VEX
// document, since only a person can say whether a given CVE is actually
// exploitable in the product.
package vextriage

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	openvex "github.com/openvex/go-vex/pkg/vex"

	"github.com/getcrasec/crasec/internal/vex"
	"github.com/getcrasec/crasec/internal/vulnscan"
)

// DefaultDraftPath is where triage progress is saved after each confirmed
// finding, so a long session (50+ findings) can be resumed by rerunning the
// same command from the same directory instead of losing prior answers.
const DefaultDraftPath = ".crasec-vex-draft.json"

// statusOptions is the order statuses are offered in during triage.
var statusOptions = []openvex.Status{
	openvex.StatusNotAffected,
	openvex.StatusAffected,
	openvex.StatusFixed,
	openvex.StatusUnderInvestigation,
}

var statusDescriptions = map[openvex.Status]string{
	openvex.StatusNotAffected:        "not_affected           vulnerable code isn't reachable or present",
	openvex.StatusAffected:           "affected                remediation/mitigation is in progress",
	openvex.StatusFixed:              "fixed                    already resolved in a specific version",
	openvex.StatusUnderInvestigation: "under_investigation    triage not yet complete",
}

// justificationOptions is deliberately the 4 codes called out for this
// triage flow, not go-vex's full set of 5: vulnerable_code_not_in_execute_path
// is a valid OpenVEX justification but isn't offered here to keep the
// picker to the CRA-relevant shortlist.
var justificationOptions = []openvex.Justification{
	openvex.ComponentNotPresent,
	openvex.VulnerableCodeNotPresent,
	openvex.VulnerableCodeCannotBeControlledByAdversary,
	openvex.InlineMitigationsAlreadyExist,
}

var justificationDescriptions = map[openvex.Justification]string{
	openvex.ComponentNotPresent:                         "component_not_present                       vulnerable component isn't included",
	openvex.VulnerableCodeNotPresent:                    "vulnerable_code_not_present                 included, but vulnerable code was stripped",
	openvex.VulnerableCodeCannotBeControlledByAdversary: "vulnerable_code_cannot_be_controlled_by_adversary   attacker can't reach the vulnerable input",
	openvex.InlineMitigationsAlreadyExist:               "inline_mitigations_already_exist            built-in protections block exploitation",
}

// group collapses every finding for one vulnerability ID into a single
// triage unit: the CRA asks "is CVE-X exploitable in our product", not
// "is CVE-X exploitable in this specific copy of the component", so a CVE
// hitting three components is triaged once, not three times.
type group struct {
	id         string
	components []vulnscan.Finding
}

func groupFindings(findings []vulnscan.Finding) []group {
	index := map[string]int{}
	var groups []group
	for _, f := range findings {
		if i, ok := index[f.VulnerabilityID]; ok {
			groups[i].components = append(groups[i].components, f)
			continue
		}
		index[f.VulnerabilityID] = len(groups)
		groups = append(groups, group{id: f.VulnerabilityID, components: []vulnscan.Finding{f}})
	}
	sort.SliceStable(groups, func(i, j int) bool {
		return groups[i].components[0].CRARelevanceScore > groups[j].components[0].CRARelevanceScore
	})
	return groups
}

// step is which prompt is currently on screen for the finding at the front
// of the queue.
type step int

const (
	stepStatus step = iota
	stepJustification
	stepActionStatement
	stepFixedVersion
	stepNotes
)

// Model is the bubbletea Elm-architecture model driving the triage session.
type Model struct {
	groups     []group
	queue      []int // indices into groups still needing a decision, front = on screen
	statements map[string]vex.Statement
	draftPath  string

	step         step
	statusCursor int
	justCursor   int
	textBuffer   strings.Builder

	pendingStatus          openvex.Status
	pendingJustification   openvex.Justification
	pendingActionStatement string
	pendingFixedVersion    string

	validationMsg string
	confirmed     int
	skipped       int
	err           error
}

func newModel(groups []group, resumed map[string]vex.Statement, draftPath string) Model {
	statements := make(map[string]vex.Statement, len(resumed))
	for k, v := range resumed {
		statements[k] = v
	}

	var queue []int
	for i, g := range groups {
		if _, done := statements[g.id]; done {
			continue
		}
		queue = append(queue, i)
	}

	return Model{
		groups:     groups,
		queue:      queue,
		statements: statements,
		draftPath:  draftPath,
		confirmed:  len(statements),
	}
}

// Run launches the interactive triage TUI over findings, resuming any prior
// progress saved at draftPath (DefaultDraftPath if empty), and returns the
// accumulated triage decisions plus whether every finding was triaged
// (false if the user quit early with 'q'/Ctrl+C).
func Run(findings []vulnscan.Finding, draftPath string) (map[string]vex.Statement, bool, error) {
	if draftPath == "" {
		draftPath = DefaultDraftPath
	}

	groups := groupFindings(findings)
	resumed, err := loadDraft(draftPath)
	if err != nil {
		return nil, false, err
	}

	m := newModel(groups, resumed, draftPath)
	if len(m.queue) == 0 {
		return m.statements, true, nil
	}

	finalModel, err := tea.NewProgram(m).Run()
	if err != nil {
		return nil, false, fmt.Errorf("running triage TUI: %w", err)
	}

	fm, ok := finalModel.(Model)
	if !ok {
		return nil, false, errors.New("triage TUI returned an unexpected model type")
	}
	if fm.err != nil {
		return nil, false, fm.err
	}
	return fm.statements, len(fm.queue) == 0, nil
}

// Init satisfies tea.Model. The triage session needs no startup command.
func (m Model) Init() tea.Cmd { return nil }

// Update handles one input event, advancing the triage queue and persisting
// the draft as findings are confirmed.
func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	keyMsg, ok := msg.(tea.KeyMsg)
	if !ok {
		return m, nil
	}
	if len(m.queue) == 0 {
		return m, tea.Quit
	}
	if keyMsg.Type == tea.KeyCtrlC {
		return m, tea.Quit
	}
	if keyMsg.Type == tea.KeyTab {
		return m.skipCurrent(), nil
	}

	switch m.step {
	case stepStatus:
		return m.updateStatusStep(keyMsg)
	case stepJustification:
		return m.updateJustificationStep(keyMsg)
	default:
		return m.updateTextStep(keyMsg)
	}
}

// skipCurrent moves the finding at the front of the queue to the back
// (Tab: "skip and come back") and resets the step so it starts fresh
// whenever it resurfaces.
func (m Model) skipCurrent() Model {
	if len(m.queue) > 1 {
		m.queue = append(m.queue[1:], m.queue[0])
	}
	m.skipped++
	return m.resetStep()
}

func (m Model) resetStep() Model {
	m.step = stepStatus
	m.statusCursor = 0
	m.justCursor = 0
	m.textBuffer.Reset()
	m.validationMsg = ""
	m.pendingActionStatement = ""
	m.pendingFixedVersion = ""
	return m
}

func (m Model) updateStatusStep(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "q":
		return m, tea.Quit
	case "up", "k":
		m.statusCursor = (m.statusCursor - 1 + len(statusOptions)) % len(statusOptions)
	case "down", "j":
		m.statusCursor = (m.statusCursor + 1) % len(statusOptions)
	case "enter":
		m.pendingStatus = statusOptions[m.statusCursor]
		m.validationMsg = ""
		switch m.pendingStatus {
		case openvex.StatusNotAffected:
			m.step = stepJustification
		default:
			m.step = advanceStep(m.pendingStatus)
			m.textBuffer.Reset()
		}
	}
	return m, nil
}

// advanceStep is the step that follows status selection for every status
// other than not_affected (which always goes to the justification picker).
func advanceStep(status openvex.Status) step {
	switch status {
	case openvex.StatusAffected:
		return stepActionStatement
	case openvex.StatusFixed:
		return stepFixedVersion
	default: // under_investigation: deadline is auto-computed, no prompt needed
		return stepNotes
	}
}

func (m Model) updateJustificationStep(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "q":
		return m, tea.Quit
	case "up", "k":
		m.justCursor = (m.justCursor - 1 + len(justificationOptions)) % len(justificationOptions)
	case "down", "j":
		m.justCursor = (m.justCursor + 1) % len(justificationOptions)
	case "enter":
		m.pendingJustification = justificationOptions[m.justCursor]
		m.step = stepNotes
		m.textBuffer.Reset()
		m.validationMsg = ""
	}
	return m, nil
}

// updateTextStep handles the three free-text steps (action statement, fixed
// version, notes). 'q' is intentionally not a quit key here so it can be
// typed as ordinary text.
func (m Model) updateTextStep(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.Type {
	case tea.KeyEnter:
		return m.advanceFromTextStep()
	case tea.KeyBackspace, tea.KeyDelete:
		if s := m.textBuffer.String(); len(s) > 0 {
			r := []rune(s)
			m.textBuffer.Reset()
			m.textBuffer.WriteString(string(r[:len(r)-1]))
		}
	case tea.KeySpace:
		m.textBuffer.WriteRune(' ')
	case tea.KeyRunes:
		m.textBuffer.WriteString(string(msg.Runes))
	}
	return m, nil
}

func (m Model) advanceFromTextStep() (tea.Model, tea.Cmd) {
	text := strings.TrimSpace(m.textBuffer.String())
	switch m.step {
	case stepActionStatement:
		if text == "" {
			m.validationMsg = `action statement is required for status "affected"`
			return m, nil
		}
		m.pendingActionStatement = text
		m.step = stepNotes
		m.textBuffer.Reset()
		m.validationMsg = ""
		return m, nil
	case stepFixedVersion:
		if text == "" {
			m.validationMsg = `fixed version is required for status "fixed"`
			return m, nil
		}
		m.pendingFixedVersion = text
		m.step = stepNotes
		m.textBuffer.Reset()
		m.validationMsg = ""
		return m, nil
	default: // stepNotes: last step, confirms the whole finding
		return m.confirmCurrent(text)
	}
}

// confirmCurrent builds the Statement for the finding at the front of the
// queue, validates it, and, if valid, commits it, persists the draft, and
// advances the queue. This is the "[Enter] to confirm" + "save progress
// after each confirmed finding" behavior.
func (m Model) confirmCurrent(notes string) (tea.Model, tea.Cmd) {
	g := m.groups[m.queue[0]]
	stmt := vex.Statement{VulnerabilityID: g.id, Status: m.pendingStatus}
	switch m.pendingStatus {
	case openvex.StatusNotAffected:
		stmt.Justification = m.pendingJustification
		stmt.ImpactStatement = notes
	case openvex.StatusAffected:
		stmt.ActionStatement = m.pendingActionStatement
		stmt.Notes = notes
	case openvex.StatusFixed:
		stmt.FixedVersion = m.pendingFixedVersion
		stmt.Notes = notes
	case openvex.StatusUnderInvestigation:
		deadline := time.Now().Add(vex.MaxUnderInvestigationDeadline)
		stmt.Deadline = &deadline
		stmt.Notes = notes
	}

	if err := stmt.Validate(); err != nil {
		m.validationMsg = err.Error()
		return m, nil
	}

	m.statements[stmt.VulnerabilityID] = stmt
	m.confirmed++
	m.queue = m.queue[1:]
	m = m.resetStep()

	if err := saveDraft(m.draftPath, m.statements); err != nil {
		m.err = err
		return m, tea.Quit
	}
	if len(m.queue) == 0 {
		return m, tea.Quit
	}
	return m, nil
}

// loadDraft reads a previously saved draft (or --statements file; they
// share the same JSON shape), indexed by vulnerability ID. A missing file
// is not an error: it means this is the first session.
func loadDraft(path string) (map[string]vex.Statement, error) {
	statements := map[string]vex.Statement{}
	data, err := os.ReadFile(path) // #nosec G304 -- path is caller-supplied (ultimately a CLI flag), not attacker-controlled remote input
	if errors.Is(err, os.ErrNotExist) {
		return statements, nil
	}
	if err != nil {
		return nil, fmt.Errorf("reading draft %s: %w", path, err)
	}
	var list []vex.Statement
	if err := json.Unmarshal(data, &list); err != nil {
		return nil, fmt.Errorf("parsing draft %s: %w", path, err)
	}
	for _, s := range list {
		statements[s.VulnerabilityID] = s
	}
	return statements, nil
}

func saveDraft(path string, statements map[string]vex.Statement) error {
	list := make([]vex.Statement, 0, len(statements))
	for _, s := range statements {
		list = append(list, s)
	}
	sort.Slice(list, func(i, j int) bool { return list[i].VulnerabilityID < list[j].VulnerabilityID })

	data, err := json.MarshalIndent(list, "", "  ")
	if err != nil {
		return fmt.Errorf("encoding draft: %w", err)
	}
	if err := os.WriteFile(path, data, 0o644); err != nil { // #nosec G306 -- triage draft is local working state, not secret
		return fmt.Errorf("writing draft %s: %w", path, err)
	}
	return nil
}
