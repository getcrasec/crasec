package sbomgen

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"fmt"
	"io"

	cyclonedx "github.com/CycloneDX/cyclonedx-go"
	jsonschema "github.com/santhosh-tekuri/jsonschema/v5"
)

//go:embed schema/bom-1.6.schema.json
var cdx16SchemaBytes []byte

//go:embed schema/spdx.schema.json
var spdxSchemaBytes []byte

//go:embed schema/jsf-0.82.schema.json
var jsfSchemaBytes []byte

// $id values declared inside the downloaded schema files.
const (
	cdx16SchemaID = "http://cyclonedx.org/schema/bom-1.6.schema.json"
	spdxSchemaID  = "http://cyclonedx.org/schema/spdx.schema.json"
	jsfSchemaID   = "http://cyclonedx.org/schema/jsf-0.82.schema.json"
)

// WriteCycloneDX16 encodes bom as pretty-printed CycloneDX 1.6 JSON,
// validates it against the embedded schema, and writes it to w. Nothing is
// written if validation fails.
func WriteCycloneDX16(w io.Writer, bom *cyclonedx.BOM) error {
	var buf bytes.Buffer
	enc := cyclonedx.NewBOMEncoder(&buf, cyclonedx.BOMFileFormatJSON)
	enc.SetPretty(true)
	if err := enc.EncodeVersion(bom, cyclonedx.SpecVersion1_6); err != nil {
		return fmt.Errorf("encoding CycloneDX 1.6 BOM: %w", err)
	}

	if err := ValidateCycloneDX16(buf.Bytes()); err != nil {
		return err
	}

	_, err := w.Write(buf.Bytes())
	return err
}

// ValidateCycloneDX16 validates data against the embedded CycloneDX 1.6
// JSON schema.
func ValidateCycloneDX16(data []byte) error {
	compiler := jsonschema.NewCompiler()
	if err := compiler.AddResource(cdx16SchemaID, bytes.NewReader(cdx16SchemaBytes)); err != nil {
		return fmt.Errorf("loading CycloneDX 1.6 schema: %w", err)
	}
	if err := compiler.AddResource(spdxSchemaID, bytes.NewReader(spdxSchemaBytes)); err != nil {
		return fmt.Errorf("loading SPDX license schema: %w", err)
	}
	if err := compiler.AddResource(jsfSchemaID, bytes.NewReader(jsfSchemaBytes)); err != nil {
		return fmt.Errorf("loading JSF 0.82 schema: %w", err)
	}

	sch, err := compiler.Compile(cdx16SchemaID)
	if err != nil {
		return fmt.Errorf("compiling CycloneDX 1.6 schema: %w", err)
	}

	var doc any
	if err := json.Unmarshal(data, &doc); err != nil {
		return fmt.Errorf("parsing BOM JSON: %w", err)
	}

	if err := sch.Validate(doc); err != nil {
		return fmt.Errorf("CycloneDX 1.6 schema validation failed: %w", err)
	}
	return nil
}
