// Package initwizard implements "crasec init": the guided first-run setup
// that detects a project's ecosystem, collects product and manufacturer
// identity, and writes .crasec.yaml — the config file every other crasec
// command reads afterward, so a project set up once needs far fewer flags
// on every later run.
package initwizard

import (
	"errors"
	"fmt"
	"path/filepath"
	"strings"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/getcrasec/crasec/internal/config"
)

// step is which screen is on-screen.
type step int

const (
	stepEcosystem step = iota
	stepProductName
	stepProductVersion
	stepManufacturerName
	stepManufacturerAddress
	stepScanTarget
	stepReview
)

// Model is the bubbletea Elm-architecture model driving the init wizard.
type Model struct {
	cwd string

	detected          []ecosystemManifest
	ecosystemCursor   int
	skipEcosystemStep bool // true once ecosystem is already known (single detection, or a prior .crasec.yaml)

	step step

	ecosystem           string
	productName         string
	productVersion      string
	manufacturerName    string
	manufacturerAddress string
	scanTarget          string

	// textBuffer is a plain string, not a strings.Builder: bubbletea
	// copies Model by value on every Update call, and Builder's internal
	// copy-detection panics the moment a builder written-to before a copy
	// is written to again afterward.
	textBuffer    string
	validationMsg string

	quit bool
	err  error
}

// decideEcosystem picks the ecosystem to use without asking, when
// possible: a prior .crasec.yaml's value wins (re-running init shouldn't
// re-litigate a settled answer), then a single unambiguous manifest
// detection. Anything else (nothing detected, or more than one candidate,
// e.g. a monorepo) means the wizard has to ask.
func decideEcosystem(existing *config.Config, detected []ecosystemManifest) (value string, skip bool) {
	if existing != nil && existing.Ecosystem != "" {
		return existing.Ecosystem, true
	}
	if len(detected) == 1 {
		return detected[0].Ecosystem, true
	}
	return "", false
}

func newModel(cwd string, existing *config.Config) Model {
	detected := DetectEcosystems(cwd)
	ecosystem, skip := decideEcosystem(existing, detected)

	m := Model{
		cwd:               cwd,
		detected:          detected,
		skipEcosystemStep: skip,
		ecosystem:         ecosystem,
	}

	if existing != nil {
		m.productName = existing.Product.Name
		m.productVersion = existing.Product.Version
		m.manufacturerName = existing.Manufacturer.Name
		m.manufacturerAddress = existing.Manufacturer.Address
		m.scanTarget = existing.Scan.Target
	}
	if m.productName == "" {
		m.productName = filepath.Base(cwd)
	}
	if m.productVersion == "" {
		m.productVersion = "0.1.0"
	}
	if m.scanTarget == "" {
		m.scanTarget = "."
	}

	if skip {
		m = m.advanceTo(stepProductName)
	} else {
		m.step = stepEcosystem
		if len(detected) > 0 {
			for i, e := range KnownEcosystems {
				if e == detected[0].Ecosystem {
					m.ecosystemCursor = i
					break
				}
			}
		}
	}
	return m
}

// Run launches the interactive init wizard rooted at cwd, pre-filling
// fields from existing (nil if no .crasec.yaml exists yet — a fresh
// project), and returns the resulting Config plus whether the user
// completed the wizard (false if they quit early with Ctrl+C or 'q').
func Run(cwd string, existing *config.Config) (*config.Config, bool, error) {
	finalModel, err := tea.NewProgram(newModel(cwd, existing)).Run()
	if err != nil {
		return nil, false, fmt.Errorf("running init wizard: %w", err)
	}
	fm, ok := finalModel.(Model)
	if !ok {
		return nil, false, errors.New("init wizard returned an unexpected model type")
	}
	if fm.err != nil {
		return nil, false, fm.err
	}
	if fm.quit {
		return nil, false, nil
	}

	return &config.Config{
		Product:      config.Product{Name: fm.productName, Version: fm.productVersion},
		Manufacturer: config.Manufacturer{Name: fm.manufacturerName, Address: fm.manufacturerAddress},
		Ecosystem:    fm.ecosystem,
		Scan:         config.Scan{Target: fm.scanTarget},
	}, true, nil
}

func (m Model) Init() tea.Cmd { return nil }

func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	keyMsg, ok := msg.(tea.KeyMsg)
	if !ok {
		return m, nil
	}
	if keyMsg.Type == tea.KeyCtrlC {
		m.quit = true
		return m, tea.Quit
	}

	switch m.step {
	case stepEcosystem:
		return m.updateEcosystemStep(keyMsg)
	case stepReview:
		return m.updateReviewStep(keyMsg)
	default:
		return m.updateTextStep(keyMsg)
	}
}

func (m Model) updateEcosystemStep(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "up", "k":
		m.ecosystemCursor = (m.ecosystemCursor - 1 + len(KnownEcosystems)) % len(KnownEcosystems)
	case "down", "j":
		m.ecosystemCursor = (m.ecosystemCursor + 1) % len(KnownEcosystems)
	case "enter":
		m.ecosystem = KnownEcosystems[m.ecosystemCursor]
		m = m.advanceTo(stepProductName)
	}
	return m, nil
}

// updateTextStep handles every free-text field. 'q' is intentionally not a
// quit key here so it can be typed as ordinary text (e.g. in an address).
func (m Model) updateTextStep(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.Type {
	case tea.KeyEnter:
		return m.confirmTextStep()
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

func (m Model) confirmTextStep() (tea.Model, tea.Cmd) {
	value := strings.TrimSpace(m.textBuffer)

	switch m.step {
	case stepProductName:
		if value == "" {
			m.validationMsg = "product name is required"
			return m, nil
		}
		m.productName = value
		m = m.advanceTo(stepProductVersion)

	case stepProductVersion:
		m.productVersion = value
		m = m.advanceTo(stepManufacturerName)

	case stepManufacturerName:
		if value == "" {
			m.validationMsg = "manufacturer name is required (needed for the EU Declaration of Conformity)"
			return m, nil
		}
		m.manufacturerName = value
		m = m.advanceTo(stepManufacturerAddress)

	case stepManufacturerAddress:
		if value == "" {
			m.validationMsg = "manufacturer address is required (must be an EU-registered address for the DoC)"
			return m, nil
		}
		m.manufacturerAddress = value
		m = m.advanceTo(stepScanTarget)

	case stepScanTarget:
		if value == "" {
			value = "."
		}
		m.scanTarget = value
		m.validationMsg = ""
		m.step = stepReview
	}
	return m, nil
}

// advanceTo moves to the next step and seeds its input widget with
// whatever value is already known for that field (a prior .crasec.yaml's
// value, or a sensible guess), clearing any validation message left over
// from the step being departed.
func (m Model) advanceTo(next step) Model {
	m.step = next
	m.validationMsg = ""
	switch next {
	case stepProductName:
		m.textBuffer = m.productName
	case stepProductVersion:
		m.textBuffer = m.productVersion
	case stepManufacturerName:
		m.textBuffer = m.manufacturerName
	case stepManufacturerAddress:
		m.textBuffer = m.manufacturerAddress
	case stepScanTarget:
		m.textBuffer = m.scanTarget
	}
	return m
}

func (m Model) updateReviewStep(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "enter", "y":
		return m, tea.Quit
	case "b":
		if m.skipEcosystemStep {
			m = m.advanceTo(stepProductName)
		} else {
			m.step = stepEcosystem
		}
	case "q":
		m.quit = true
		return m, tea.Quit
	}
	return m, nil
}
