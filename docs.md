# crasec — documentation

This document explains **why crasec exists, what it does, and how it works** —
the reasoning behind the tool, not just its command-line flags. For
copy-pasteable quickstart commands, see [README.md](README.md). For
build/test/contribution workflow, see [CONTRIBUTING.md](CONTRIBUTING.md).

---

## Why

### The regulation

The **EU Cyber Resilience Act (CRA)** — Regulation (EU) 2024/2847 — is the
first EU law to impose horizontal, mandatory cybersecurity requirements on
"products with digital elements": basically any hardware or software placed
on the EU market that has a network connection or otherwise processes data,
from a smart thermostat to a backend service to an open-source library
shipped as a dependency. It entered into force in December 2024 and phases
in on two dates that matter to anyone building software for the EU market:

- **11 September 2026** — Article 14 reporting obligations become
  enforceable. A manufacturer who becomes aware of an actively exploited
  vulnerability in their product must notify ENISA within **24 hours**, and
  follow up with fuller reports at 72 hours and on resolution. There is no
  grace period for "we didn't have a process" — the obligation exists the
  moment a qualifying vulnerability is found.
- **11 December 2027** — the full set of essential requirements applies
  (CRA Annex I): secure-by-default configuration, a Software Bill of
  Materials, a documented vulnerability-handling policy, and more. A
  product that doesn't meet them cannot legally carry the CE marking or be
  placed on the EU market.

Non-compliance carries real penalties (up to €15M or 2.5% of global
turnover, whichever is higher, for the most serious breaches) — but the
more immediate operational problem is simpler: **on 11 September 2026, "we
found a CVE" has to become "ENISA has been notified within 24 hours" with a
paper trail proving it**, for every in-scope product a manufacturer ships.

### The actual problem

None of the individual pieces the CRA asks for are new or exotic —
generating an SBOM, scanning for vulnerabilities, writing a Declaration of
Conformity — every one of them already has tooling. The problem is that
CRA compliance isn't any single artifact; it's a **chain of five
artifacts that all have to agree with each other and stay current**:

1. An SBOM that actually lists what's in the product (not a stale one from
   three releases ago).
2. A vulnerability scan correlated against *that specific* SBOM.
3. A VEX statement recording, per vulnerability, whether it's actually
   exploitable in this product (a scanner match isn't the same as real
   exposure, and regulators know it).
4. A CSAF security advisory in the machine-readable format ENISA expects,
   built from the same findings.
5. Technical documentation (Annex VII) and a signed Declaration of
   Conformity (Annex V) that reference the SBOM, the vulnerability
   handling policy, and the conformity assessment — consistently.

Doing this by hand, or by stitching together five separate tools with no
shared data model, is exactly the kind of process that quietly breaks the
week before an audit: the SBOM gets regenerated but the VEX document
doesn't, the advisory cites a CVE that's since been fixed, nobody can
prove which build the Declaration of Conformity actually describes. crasec
exists because **this should be one pipeline, not five disconnected
tools**, and because the artifacts should be able to prove their own
integrity rather than relying on "trust me, this is the current version."

---

## What

crasec is a single CLI that takes a repository (or a container image, or a
remote git URL) and produces every artifact the CRA's evidentiary chain
requires, each one correctly derived from the last:

| Artifact | What it is | CRA requirement it satisfies |
|---|---|---|
| `sbom.cdx.json` | CycloneDX 1.6 SBOM (syft + cdxgen) | Annex I, Part II, §1 — Software Bill of Materials |
| `findings.json` | Vulnerability matches, scored for CRA relevance | Feeds Article 14's "is this actively exploited" trigger |
| `vex.cdx.json` | Per-vulnerability exploitability statements | Annex I, Part II, §2 — Vulnerability handling |
| `advisory.json` | CSAF 2.0 security advisory | Article 14 — vulnerability reporting / public disclosure |
| `annex7.json` / `.pdf` | Technical documentation (10 required sections) | Annex VII — kept on file for 10 years |
| `eu-doc.json` / `.pdf` | EU Declaration of Conformity | Annex V — required for CE marking |
| `evidence-bundle.zip` | All of the above, manifest + README included | The package handed to an auditor or market-surveillance authority |

Every artifact that can be signed, is: crasec uses **Sigstore keyless
signing** (a GitHub Actions workflow's ambient OIDC token in CI, or an
interactive browser login locally) so there's no private key to manage,
rotate, or leak, and every signature is recorded in Rekor's public
transparency log — independently verifiable by anyone, not just crasec
itself.

crasec also scores an SBOM against **BSI TR-03183-2 v2.1.0**, the
technical guideline German and EU regulators point to for what a
CRA-compliant SBOM's *contents* actually need to look like (a CycloneDX
document can be technically valid and still be missing the fields BSI
requires — this catches that gap before an auditor does).

### What crasec deliberately is not

- **Not a legal-advice tool.** It automates the evidence-generation
  mechanics (SBOM, VEX, CSAF, Annex VII, Annex V); it doesn't make the
  legal judgment calls — product risk classification, which conformity
  assessment route applies — that stay the manufacturer's to make.
- **Not a SaaS.** Every artifact is a plain file (JSON, PDF, ZIP) on disk.
  There's no vendor lock-in, no account, nothing to migrate away from if
  crasec stops being the right tool — the CycloneDX SBOM, CSAF advisory,
  and OpenVEX statements are all independently-specified open formats
  readable by any other compliant tool.
- **Not a vulnerability scanner from scratch.** It uses established,
  independently-maintained scanners (Grype, OSV-Scanner) and enriches
  their output with CRA-specific context (KEV, EPSS, the CRA relevance
  score) rather than reimplementing vulnerability intelligence.

---

## How

### The pipeline

```
crasec init
     │  detect ecosystem (go.mod / package.json / pom.xml / Cargo.toml / requirements.txt),
     │  collect product + manufacturer identity, write .crasec.yaml
     ▼
crasec sbom generate
     │  syft scans the filesystem/image; cdxgen overlays richer build-time
     │  metadata when a build manifest is present and cdxgen is installed
     ▼
crasec sbom validate            (optional but recommended — CI gate)
     │  score the SBOM against BSI TR-03183-2's 10 mandatory fields
     ▼
crasec vuln correlate
     │  Grype (library, in-process) + OSV-Scanner match the SBOM against
     │  vulnerability databases; CISA KEV flags active exploitation;
     │  FIRST.org EPSS scores 30-day exploitation probability;
     │  CRA Score = CVSS × KEV multiplier × EPSS weight
     ▼
crasec vex generate
     │  per finding: not_affected / affected / fixed / under_investigation,
     │  from an interactive triage session or a version-controlled decisions file
     ▼
crasec csaf generate
     │  builds the CSAF 2.0 advisory from the same findings, validated
     │  against the OASIS CSAF 2.0 JSON schema
     ▼
crasec annex7 scaffold  +  crasec doc generate
     │  the 10-section technical file, and the EU Declaration of Conformity
     │  (auto-populated from Annex VII where fields overlap)
     ▼
crasec bundle export
     └─ assembles every artifact above (+ signatures) into one ZIP,
        with manifest.json and a plain-language README.txt
```

Every generate/sign step is independently runnable and independently
scriptable — the pipeline above is the common path, not a monolith. A team
that only needs the SBOM and vulnerability scoring for now can stop there;
`bundle export` simply won't produce a ZIP until every artifact it needs
exists, and tells you exactly which command produces each missing one.

### The CRA relevance score

Grype and OSV-Scanner report CVSS base scores, which describe a
vulnerability's theoretical severity but not whether it's actually being
exploited or affects this specific product. crasec combines three signals
into one prioritization number:

```
CRA Score = CVSS Base Score × KEV Multiplier × EPSS Weight

  KEV Multiplier: 2.0 if the CVE is in CISA's Known Exploited
                  Vulnerabilities catalog (confirmed active exploitation),
                  else 1.0
  EPSS Weight:    1.5 if FIRST.org's EPSS 30-day exploitation probability
                  is > 0.7, else 1.0

  CRA Score > 14  →  CRA-CRITICAL: this is the Article 14 trigger —
                     report to ENISA within 24 hours
```

This is the difference between a generic vulnerability scanner (which
reports hundreds of findings with no sense of what actually needs a
same-day response) and the CRA-specific question crasec is built to
answer: *which of these findings is a legal reporting obligation, right
now?*

### Ecosystem detection and scanning strategy

`crasec init` detects the primary ecosystem by checking for `go.mod`,
`package.json` (+lockfile), `pom.xml`/`build.gradle`, `Cargo.toml`, or
`requirements.txt`/`pyproject.toml`. SBOM generation always runs syft
(broad, dependable filesystem-level detection across all ecosystems), and
layers `cdxgen` on top when it's installed and a build manifest cdxgen
understands is present — cdxgen's build-time dependency resolution is
richer for npm/Maven/Gradle/Cargo/pip projects; syft fills in whatever
cdxgen didn't cover. Container images are scanned with syft alone.

### Signing and verification

Every signable artifact goes through the same flow: Sigstore issues a
short-lived certificate for an OIDC identity (a GitHub Actions workflow
token in CI — no secrets to configure — or a browser login locally), signs
with a fresh ephemeral keypair, and records the signature in Rekor's
transparency log. `crasec <artifact> verify` checks the signature against
the artifact's digest, validates the certificate chain, confirms the Rekor
entry, and (optionally) pins verification to a specific signer identity —
e.g. requiring the signature come from a specific GitHub Actions workflow,
not just "any Sigstore identity."

---

## Glossary

| Term | Meaning |
|---|---|
| **SBOM** | Software Bill of Materials — the full list of components (and their versions, licenses, hashes) that make up a product. |
| **CycloneDX** | The SBOM standard crasec produces by default; OWASP-maintained, the format BSI TR-03183-2 and most CRA guidance assumes. |
| **VEX** | Vulnerability Exploitability eXchange — a statement of whether a known vulnerability in a component is actually exploitable *in this product*, separate from whether the component merely contains it. |
| **CSAF** | Common Security Advisory Framework — OASIS's machine-readable security advisory format; what ENISA/the EUVD expect for vulnerability disclosures. |
| **Annex VII** | The CRA's required technical documentation: architecture, SDLC, security-by-default configuration, vulnerability handling policy, conformity assessment result — kept for 10 years. |
| **EU DoC (Annex V)** | EU Declaration of Conformity — the manufacturer's formal, signed statement that a product meets the CRA's essential requirements; required for CE marking. |
| **BSI TR-03183-2** | Germany's BSI technical guideline defining what fields a CRA-compliant SBOM must actually populate per component — the "is this SBOM good enough" standard, distinct from "is this SBOM valid CycloneDX." |
| **KEV** | CISA's Known Exploited Vulnerabilities catalog — CVEs confirmed to be under active exploitation in the wild. |
| **EPSS** | FIRST.org's Exploit Prediction Scoring System — a 0–1 probability that a CVE will be exploited in the next 30 days. |
| **PURL** | Package URL — a standardized identifier for a software package (e.g. `pkg:npm/lodash@4.17.15`), used throughout SBOM/VEX/CSAF to unambiguously reference components. |
| **Sigstore / Fulcio / Rekor** | Sigstore is the keyless-signing project; Fulcio issues short-lived signing certificates from an OIDC identity; Rekor is the public transparency log every signature is recorded in. |
| **Article 14** | The CRA article requiring manufacturers to report actively exploited vulnerabilities to ENISA within 24 hours. |

---

## Who this is for

Anyone shipping software (or connected hardware) into the EU market who
needs to produce CRA compliance evidence — in practice, that's most
commercial software vendors and increasingly open-source maintainers whose
projects get bundled into commercial products. It's built CI-first: every
command is scriptable and non-interactive-friendly (flags, `--from-file`
decision files, ambient CI signing), so the common path is "this runs on
every PR and release," not "someone remembers to run this before an
audit."
