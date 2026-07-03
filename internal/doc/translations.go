// Package doc embeds the standard EU New Legislative Framework (NLF)
// "sole responsibility of the manufacturer" conformity declaration
// statement, translated into the EU's 24 official languages. CRA Annex V
// requires the Declaration of Conformity to be available in the
// language(s) of every member state a product is sold into; this sentence
// is the one part of the DoC that's fully standardized wording: the same
// text (only translated) recurs across the EU's other NLF product
// legislation (RED, Machinery Regulation, EMC Directive, etc.), so it
// doesn't vary by product and is safe to embed as static assets rather
// than generate per document.
//
// Translation status: only a subset of the 24 official languages currently
// have an embedded translation (see AvailableLanguages); the rest are
// added incrementally as translations/conformity_statement_<code>.txt
// files. The included translations follow the standard published NLF
// wording as closely as possible, but crasec is not a certified legal
// translation service. Verify against your own qualified legal/linguistic
// counsel before relying on them for a regulatory submission.
package doc

import (
	"embed"
	"errors"
	"fmt"
	"sort"
	"strings"
)

//go:embed translations/conformity_statement_*.txt
var translationsFS embed.FS

const translationFilePattern = "translations/conformity_statement_%s.txt"

// Language is one of the EU's 24 official languages.
type Language struct {
	Code string // ISO 639-1, e.g. "en"; what --languages and Statement expect
	Name string // English name, e.g. "English"
}

// EULanguages lists all 24 EU official languages
// (https://europa.eu/european-union/abouteu/eu-languages_en), regardless
// of whether a translation has been embedded yet; see AvailableLanguages
// for that.
var EULanguages = []Language{
	{"bg", "Bulgarian"},
	{"cs", "Czech"},
	{"da", "Danish"},
	{"de", "German"},
	{"el", "Greek"},
	{"en", "English"},
	{"es", "Spanish"},
	{"et", "Estonian"},
	{"fi", "Finnish"},
	{"fr", "French"},
	{"ga", "Irish"},
	{"hr", "Croatian"},
	{"hu", "Hungarian"},
	{"it", "Italian"},
	{"lt", "Lithuanian"},
	{"lv", "Latvian"},
	{"mt", "Maltese"},
	{"nl", "Dutch"},
	{"pl", "Polish"},
	{"pt", "Portuguese"},
	{"ro", "Romanian"},
	{"sk", "Slovak"},
	{"sl", "Slovenian"},
	{"sv", "Swedish"},
}

// ErrTranslationNotAvailable is returned by Statement for a valid EU
// language code that doesn't have an embedded translation yet.
var ErrTranslationNotAvailable = errors.New("translation not yet available")

// Statement returns the standard NLF conformity declaration statement in
// the given EU language, identified by its ISO 639-1 code
// (case-insensitive, e.g. "EN" or "en").
func Statement(langCode string) (string, error) {
	code := strings.ToLower(strings.TrimSpace(langCode))

	data, err := translationsFS.ReadFile(fmt.Sprintf(translationFilePattern, code))
	if err != nil {
		if !isEULanguage(code) {
			return "", fmt.Errorf("%q is not one of the EU's 24 official language codes", langCode)
		}
		return "", fmt.Errorf("%s (%s): %w", LanguageName(code), code, ErrTranslationNotAvailable)
	}
	return strings.TrimSpace(string(data)), nil
}

// LanguageName returns the English name for an EU language code, or the
// code itself if it isn't a recognized EU official language.
func LanguageName(code string) string {
	code = strings.ToLower(strings.TrimSpace(code))
	for _, l := range EULanguages {
		if l.Code == code {
			return l.Name
		}
	}
	return code
}

// AvailableLanguages returns the EU language codes that currently have an
// embedded translation, sorted.
func AvailableLanguages() []string {
	entries, err := translationsFS.ReadDir("translations")
	if err != nil {
		return nil
	}
	var codes []string
	for _, e := range entries {
		name, ok := strings.CutPrefix(e.Name(), "conformity_statement_")
		if !ok {
			continue
		}
		codes = append(codes, strings.TrimSuffix(name, ".txt"))
	}
	sort.Strings(codes)
	return codes
}

// MissingLanguages returns the EU official language codes that don't have
// an embedded translation yet, informational, used to report what a
// "--languages all" request couldn't include.
func MissingLanguages() []string {
	have := make(map[string]bool)
	for _, c := range AvailableLanguages() {
		have[c] = true
	}
	var missing []string
	for _, l := range EULanguages {
		if !have[l.Code] {
			missing = append(missing, l.Code)
		}
	}
	return missing
}

func isEULanguage(code string) bool {
	for _, l := range EULanguages {
		if l.Code == code {
			return true
		}
	}
	return false
}
