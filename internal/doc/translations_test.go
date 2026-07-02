package doc

import (
	"errors"
	"testing"
)

func TestStatement_KnownLanguagesCaseInsensitive(t *testing.T) {
	for _, code := range []string{"en", "EN", "En"} {
		s, err := Statement(code)
		if err != nil {
			t.Fatalf("Statement(%q): %v", code, err)
		}
		if s == "" {
			t.Fatalf("Statement(%q) returned empty text", code)
		}
	}
}

func TestStatement_AllFourInitialLanguagesDiffer(t *testing.T) {
	seen := map[string]string{}
	for _, code := range []string{"en", "it", "de", "fr"} {
		s, err := Statement(code)
		if err != nil {
			t.Fatalf("Statement(%q): %v", code, err)
		}
		for otherCode, otherText := range seen {
			if otherText == s {
				t.Errorf("expected %q and %q to have distinct translated text, both got %q", code, otherCode, s)
			}
		}
		seen[code] = s
	}
}

func TestStatement_UnknownCodeIsRejected(t *testing.T) {
	if _, err := Statement("xx"); err == nil {
		t.Fatal("expected an error for a non-EU language code")
	}
}

func TestStatement_ValidEULanguageWithoutTranslationYet(t *testing.T) {
	// "pl" (Polish) is a real EU official language not yet embedded.
	_, err := Statement("pl")
	if err == nil {
		t.Fatal("expected an error for a not-yet-translated EU language")
	}
	if !errors.Is(err, ErrTranslationNotAvailable) {
		t.Errorf("expected ErrTranslationNotAvailable, got %v", err)
	}
}

func TestAvailableLanguages_ContainsInitialFour(t *testing.T) {
	available := AvailableLanguages()
	want := map[string]bool{"en": true, "it": true, "de": true, "fr": true}
	if len(available) != len(want) {
		t.Fatalf("expected exactly the 4 initial languages, got %v", available)
	}
	for _, code := range available {
		if !want[code] {
			t.Errorf("unexpected available language %q", code)
		}
	}
}

func TestMissingLanguages_ExcludesAvailableAndCoversAllTwentyFour(t *testing.T) {
	available := AvailableLanguages()
	missing := MissingLanguages()
	if len(available)+len(missing) != len(EULanguages) {
		t.Fatalf("expected available (%d) + missing (%d) to cover all %d EU languages",
			len(available), len(missing), len(EULanguages))
	}
	for _, code := range available {
		for _, m := range missing {
			if code == m {
				t.Errorf("%q reported as both available and missing", code)
			}
		}
	}
}

func TestLanguageName(t *testing.T) {
	if got := LanguageName("de"); got != "German" {
		t.Errorf("expected German, got %q", got)
	}
	if got := LanguageName("DE"); got != "German" {
		t.Errorf("expected case-insensitive lookup to work, got %q", got)
	}
	if got := LanguageName("xx"); got != "xx" {
		t.Errorf("expected unknown code to be returned as-is, got %q", got)
	}
}

func TestEULanguages_HasTwentyFour(t *testing.T) {
	if len(EULanguages) != 24 {
		t.Fatalf("expected 24 EU official languages, got %d", len(EULanguages))
	}
}
