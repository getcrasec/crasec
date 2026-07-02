package annex7

import "strings"

// fieldKind is how a field's value is entered and stored.
type fieldKind int

const (
	fieldText   fieldKind = iota // single-line free text
	fieldList                    // comma-separated list, stored as []string
	fieldBool                    // yes/no
	fieldSelect                  // one of a fixed set of options
)

// field is one prompt within a section: get/set close over TechnicalFile
// directly (no reflection), and required is a function of the whole
// document so a field can be conditionally required — e.g. section 8's
// notified-body fields only matter when the product isn't self-assessed.
type field struct {
	key      string // stable identifier, used to resume mid-section
	label    string
	help     string
	kind     fieldKind
	options  []string // for fieldSelect
	get      func(*TechnicalFile) string
	set      func(*TechnicalFile, string)
	required func(*TechnicalFile) bool
}

func (f field) isRequired(doc *TechnicalFile) bool {
	if f.required == nil {
		return true
	}
	return f.required(doc)
}

// isChoice reports whether the field is answered by picking from a fixed
// set of options (fieldSelect, fieldBool) rather than typing free text.
func (f field) isChoice() bool {
	return f.kind == fieldSelect || f.kind == fieldBool
}

// choiceOptions returns the options to offer for a choice field; fieldBool
// doesn't carry its own options slice since it's always the same two.
func (f field) choiceOptions() []string {
	if f.kind == fieldBool {
		return []string{"no", "yes"}
	}
	return f.options
}

// section is one of Annex VII's 10 mandatory sections.
type section struct {
	number int
	title  string
	fields []field
}

func alwaysRequired(*TechnicalFile) bool { return true }

func neverRequired(*TechnicalFile) bool { return false }

// sections is the wizard's data-driven definition of all 10 Annex VII
// sections. Order here is both the JSON section numbering and the order the
// wizard walks them in.
var sections = []section{
	{
		number: 1,
		title:  "General description",
		fields: []field{
			{key: "product_name", label: "Product name", kind: fieldText,
				get:      func(d *TechnicalFile) string { return d.General.ProductName },
				set:      func(d *TechnicalFile, v string) { d.General.ProductName = v },
				required: alwaysRequired},
			{key: "product_version", label: "Product version", kind: fieldText,
				get:      func(d *TechnicalFile) string { return d.General.ProductVersion },
				set:      func(d *TechnicalFile, v string) { d.General.ProductVersion = v },
				required: alwaysRequired},
			{key: "purpose", label: "Purpose (what the product does)", kind: fieldText,
				get:      func(d *TechnicalFile) string { return d.General.Purpose },
				set:      func(d *TechnicalFile, v string) { d.General.Purpose = v },
				required: alwaysRequired},
			{key: "intended_use_environment", label: "Intended use environment", kind: fieldText,
				get:      func(d *TechnicalFile) string { return d.General.IntendedUseEnvironment },
				set:      func(d *TechnicalFile, v string) { d.General.IntendedUseEnvironment = v },
				required: alwaysRequired},
		},
	},
	{
		number: 2,
		title:  "Design & development documentation",
		fields: []field{
			{key: "architecture_diagram_path", label: "Architecture diagram path", kind: fieldText,
				get:      func(d *TechnicalFile) string { return d.Design.ArchitectureDiagramPath },
				set:      func(d *TechnicalFile, v string) { d.Design.ArchitectureDiagramPath = v },
				required: alwaysRequired},
			{key: "threat_model_reference", label: "Threat model reference", kind: fieldText,
				get:      func(d *TechnicalFile) string { return d.Design.ThreatModelReference },
				set:      func(d *TechnicalFile, v string) { d.Design.ThreatModelReference = v },
				required: alwaysRequired},
			{key: "design_rationale", label: "Design rationale for security decisions", kind: fieldText,
				get:      func(d *TechnicalFile) string { return d.Design.DesignRationale },
				set:      func(d *TechnicalFile, v string) { d.Design.DesignRationale = v },
				required: alwaysRequired},
		},
	},
	{
		number: 3,
		title:  "Security-by-default configuration",
		fields: []field{
			{key: "default_auth_settings", label: "Default authentication settings", kind: fieldText,
				get:      func(d *TechnicalFile) string { return d.SecurityByDefault.DefaultAuthSettings },
				set:      func(d *TechnicalFile, v string) { d.SecurityByDefault.DefaultAuthSettings = v },
				required: alwaysRequired},
			{key: "network_exposure", label: "Network exposure (what's reachable by default)", kind: fieldText,
				get:      func(d *TechnicalFile) string { return d.SecurityByDefault.NetworkExposure },
				set:      func(d *TechnicalFile, v string) { d.SecurityByDefault.NetworkExposure = v },
				required: alwaysRequired},
			{key: "automatic_update_mechanism", label: "Automatic update mechanism", kind: fieldText,
				get:      func(d *TechnicalFile) string { return d.SecurityByDefault.AutomaticUpdateMechanism },
				set:      func(d *TechnicalFile, v string) { d.SecurityByDefault.AutomaticUpdateMechanism = v },
				required: alwaysRequired},
		},
	},
	{
		number: 4,
		title:  "SDLC description",
		fields: []field{
			{key: "development_process", label: "Development process", kind: fieldText,
				get:      func(d *TechnicalFile) string { return d.SDLC.DevelopmentProcess },
				set:      func(d *TechnicalFile, v string) { d.SDLC.DevelopmentProcess = v },
				required: alwaysRequired},
			{key: "code_review_policy", label: "Code review policy", kind: fieldText,
				get:      func(d *TechnicalFile) string { return d.SDLC.CodeReviewPolicy },
				set:      func(d *TechnicalFile, v string) { d.SDLC.CodeReviewPolicy = v },
				required: alwaysRequired},
			{key: "testing_approach", label: "Testing approach", kind: fieldText,
				get:      func(d *TechnicalFile) string { return d.SDLC.TestingApproach },
				set:      func(d *TechnicalFile, v string) { d.SDLC.TestingApproach = v },
				required: alwaysRequired},
			{key: "dependency_management", label: "Dependency management", kind: fieldText,
				get:      func(d *TechnicalFile) string { return d.SDLC.DependencyManagement },
				set:      func(d *TechnicalFile, v string) { d.SDLC.DependencyManagement = v },
				required: alwaysRequired},
		},
	},
	{
		number: 5,
		title:  "Applicable standards",
		fields: []field{
			{key: "assessed_to_annex_i_directly", label: "Assessed directly against Annex I (no harmonised standards used)?", kind: fieldBool,
				get:      func(d *TechnicalFile) string { return boolString(d.Standards.AssessedToAnnexIDirectly) },
				set:      func(d *TechnicalFile, v string) { d.Standards.AssessedToAnnexIDirectly = parseBool(v) },
				required: alwaysRequired},
			{key: "standards", label: "Harmonised standards/specs used (comma-separated)", kind: fieldList,
				get:      func(d *TechnicalFile) string { return strings.Join(d.Standards.Standards, ", ") },
				set:      func(d *TechnicalFile, v string) { d.Standards.Standards = splitList(v) },
				required: func(d *TechnicalFile) bool { return !d.Standards.AssessedToAnnexIDirectly }},
		},
	},
	{
		number: 6,
		title:  "SBOM reference",
		fields: []field{
			{key: "path", label: "Path or URL to the signed SBOM", kind: fieldText,
				get:      func(d *TechnicalFile) string { return d.SBOM.Path },
				set:      func(d *TechnicalFile, v string) { d.SBOM.Path = v },
				required: alwaysRequired},
			{key: "signature_path", label: "Path or URL to the SBOM signature (optional)", kind: fieldText,
				get:      func(d *TechnicalFile) string { return d.SBOM.SignaturePath },
				set:      func(d *TechnicalFile, v string) { d.SBOM.SignaturePath = v },
				required: neverRequired},
		},
	},
	{
		number: 7,
		title:  "Vulnerability handling policy",
		fields: []field{
			{key: "policy_url", label: "URL to SECURITY.md / vulnerability disclosure policy", kind: fieldText,
				get:      func(d *TechnicalFile) string { return d.VulnHandling.PolicyURL },
				set:      func(d *TechnicalFile, v string) { d.VulnHandling.PolicyURL = v },
				required: alwaysRequired},
		},
	},
	{
		number: 8,
		title:  "Conformity assessment result",
		fields: []field{
			{key: "product_class", label: "Product class", kind: fieldSelect,
				options:  []string{string(ClassDefault), string(ClassImportant), string(ClassCritical)},
				get:      func(d *TechnicalFile) string { return string(d.Conformity.Class) },
				set:      func(d *TechnicalFile, v string) { d.Conformity.Class = ProductClass(v) },
				required: alwaysRequired},
			{key: "self_assessment", label: "Self-assessed (vs. notified-body assessment)?", kind: fieldBool,
				get:      func(d *TechnicalFile) string { return boolString(d.Conformity.SelfAssessment) },
				set:      func(d *TechnicalFile, v string) { d.Conformity.SelfAssessment = parseBool(v) },
				required: alwaysRequired},
			{key: "notified_body_name", label: "Notified body name", kind: fieldText,
				get:      func(d *TechnicalFile) string { return d.Conformity.NotifiedBodyName },
				set:      func(d *TechnicalFile, v string) { d.Conformity.NotifiedBodyName = v },
				required: notifiedBodyRequired},
			{key: "notified_body_id", label: "Notified body ID", kind: fieldText,
				get:      func(d *TechnicalFile) string { return d.Conformity.NotifiedBodyID },
				set:      func(d *TechnicalFile, v string) { d.Conformity.NotifiedBodyID = v },
				required: notifiedBodyRequired},
			{key: "certificate_reference", label: "Certificate reference", kind: fieldText,
				get:      func(d *TechnicalFile) string { return d.Conformity.CertificateReference },
				set:      func(d *TechnicalFile, v string) { d.Conformity.CertificateReference = v },
				required: notifiedBodyRequired},
		},
	},
	{
		number: 9,
		title:  "EU Declaration of Conformity reference",
		fields: []field{
			{key: "reference", label: "Reference to the EU DoC document (ID, path, or URL)", kind: fieldText,
				get:      func(d *TechnicalFile) string { return d.DoCReference.Reference },
				set:      func(d *TechnicalFile, v string) { d.DoCReference.Reference = v },
				required: alwaysRequired},
		},
	},
	{
		number: 10,
		title:  "Copy of EU Declaration of Conformity",
		fields: []field{
			{key: "link_path", label: "Path or URL to the EU DoC (leave blank if embedding instead)", kind: fieldText,
				get:      func(d *TechnicalFile) string { return d.DoCCopy.LinkPath },
				set:      func(d *TechnicalFile, v string) { d.DoCCopy.LinkPath = v },
				required: func(d *TechnicalFile) bool { return d.DoCCopy.EmbeddedText == "" }},
			{key: "embedded_text", label: "Embedded EU DoC text (leave blank if linking instead)", kind: fieldText,
				get:      func(d *TechnicalFile) string { return d.DoCCopy.EmbeddedText },
				set:      func(d *TechnicalFile, v string) { d.DoCCopy.EmbeddedText = v },
				required: func(d *TechnicalFile) bool { return d.DoCCopy.LinkPath == "" }},
		},
	},
}

// notifiedBodyRequired: section 8's notified-body fields only matter once
// the product isn't self-assessed (i.e. Important/Critical class going
// through a notified body).
func notifiedBodyRequired(d *TechnicalFile) bool {
	return !d.Conformity.SelfAssessment
}

// SectionComplete reports whether every currently-required field in section
// s (by index into Sections()) has a non-empty value in doc.
func SectionComplete(doc *TechnicalFile, sectionIndex int) bool {
	for _, f := range sections[sectionIndex].fields {
		if f.isRequired(doc) && strings.TrimSpace(f.get(doc)) == "" {
			return false
		}
	}
	return true
}

// Completion returns how many of the 10 sections are complete, and the
// total (always 10) — the "X/10 sections complete" figure.
func Completion(doc *TechnicalFile) (done, total int) {
	total = len(sections)
	for i := range sections {
		if SectionComplete(doc, i) {
			done++
		}
	}
	return done, total
}

func boolString(b bool) string {
	if b {
		return "yes"
	}
	return "no"
}

func parseBool(s string) bool {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "y", "yes", "true":
		return true
	default:
		return false
	}
}

func splitList(s string) []string {
	var out []string
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if part != "" {
			out = append(out, part)
		}
	}
	return out
}
