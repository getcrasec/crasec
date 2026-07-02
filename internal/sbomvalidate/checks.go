package sbomvalidate

import (
	cyclonedx "github.com/CycloneDX/cyclonedx-go"
)

// orgPopulated returns true when the entity exists and carries at least a name,
// a URL, or a contact entry — enough to identify who made/supplied the component.
func orgPopulated(org *cyclonedx.OrganizationalEntity) bool {
	if org == nil {
		return false
	}
	if org.Name != "" {
		return true
	}
	if org.URL != nil {
		for _, u := range *org.URL {
			if u != "" {
				return true
			}
		}
	}
	if org.Contact != nil {
		for _, c := range *org.Contact {
			if c.Email != "" || c.Name != "" {
				return true
			}
		}
	}
	return false
}

func hasBSIProp(c *cyclonedx.Component, name string) bool {
	if c.Properties == nil {
		return false
	}
	for _, p := range *c.Properties {
		if p.Name == name && p.Value != "" {
			return true
		}
	}
	return false
}

// hasDistSHA512 checks the BSI-mandated path: externalReferences[type=distribution].hashes[alg=SHA-512].
func hasDistSHA512(c *cyclonedx.Component) bool {
	if c.ExternalReferences == nil {
		return false
	}
	for _, ref := range *c.ExternalReferences {
		if ref.Type == cyclonedx.ERTypeDistribution && ref.Hashes != nil {
			for _, h := range *ref.Hashes {
				if h.Algorithm == cyclonedx.HashAlgoSHA512 && h.Value != "" {
					return true
				}
			}
		}
	}
	return false
}

// hasInlineSHA512 checks component.hashes[alg=SHA-512] as an accepted fallback.
func hasInlineSHA512(c *cyclonedx.Component) bool {
	if c.Hashes == nil {
		return false
	}
	for _, h := range *c.Hashes {
		if h.Algorithm == cyclonedx.HashAlgoSHA512 && h.Value != "" {
			return true
		}
	}
	return false
}

func hasLicense(c *cyclonedx.Component) bool {
	if c.Licenses == nil {
		return false
	}
	for _, lc := range *c.Licenses {
		if lc.Expression != "" {
			return true
		}
		if lc.License != nil && (lc.License.ID != "" || lc.License.Name != "") {
			return true
		}
	}
	return false
}
