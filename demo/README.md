# README demo GIF

`demo.tape` is a [vhs](https://github.com/charmbracelet/vhs) script that records the terminal demo GIF embedded near the top of the project README.

## One-time setup

Both `prepare.sh` and `demo.tape` invoke the `crasec` command directly — build it from this branch and put it on `PATH` first (a stale globally-installed `crasec` would silently record the wrong version's behavior):

```sh
go build -o /tmp/crasec-demo/crasec .   # from the repo root
export PATH="/tmp/crasec-demo:$PATH"
crasec version                          # sanity check: should print this branch's build
```

```sh
go install github.com/charmbracelet/vhs@latest   # also needs ttyd + ffmpeg on PATH
cd demo
./prepare.sh   # generates the VEX/CSAF/Annex VII/EU DoC artifacts recorded runs assume already exist
```

`prepare.sh` runs the real (non-interactive) parts of the pipeline itself, including signing the SBOM/VEX/CSAF, and then prints the two commands you run yourself: `crasec annex7 scaffold` (a guided wizard — meant to be filled in by a human, not scripted) and `crasec doc generate --sign` (fully flag-driven, but signs with your Sigstore identity). Both write into `demo/.seed/`, which is gitignored.

## Recording

```sh
cd demo
vhs demo.tape
```

`demo.tape` copies `demo/.seed/`'s artifacts into a scratch working directory and records `crasec init`, `sbom generate`, `vuln correlate`, and `bundle export` live against them — fully offline and deterministic, no network- or browser-dependent step in the recording itself. See the comments at the top of `demo.tape` for why signing (all four artifacts, including the SBOM's) is pre-baked rather than live: each needs its own interactive Sigstore browser login, and a step that shells out to open a real browser is exactly the kind of thing vhs's screen-capture can lag behind or hang on mid-recording.

Output is `demo/demo.gif`. Move/copy it wherever the README's `![demo](...)` reference points.

## Fixture

`fixtures/vulnerable-node-app/` is a minimal `package.json`/`package-lock.json` pinned to `express@4.17.1`, `lodash@4.17.15`, and `minimist@0.0.8` — real npm packages with real, published CVEs, chosen so `crasec vuln correlate` has something genuine to report. `vex-decisions.yaml` has a pre-triaged decision for every CVE currently found against it; if `vuln correlate` starts reporting a new one (grype's database moves forward over time), add a decision for it there or `vex generate --from-file` will refuse to proceed.
