package audit

import (
	"bytes"
	"encoding/json"
	"os"
	"reflect"
	"sort"
	"testing"

	jsonschema "github.com/santhosh-tekuri/jsonschema/v6"
)

func TestSchemaMatchesCanonicalEventAndRejectsContentFields(t *testing.T) {
	encodedSchema, err := os.ReadFile("../../schemas/audit-event-v1.schema.json")
	if err != nil {
		t.Fatalf("read audit event schema: %v", err)
	}
	schemaDocument, err := jsonschema.UnmarshalJSON(bytes.NewReader(encodedSchema))
	if err != nil {
		t.Fatalf("parse audit event schema: %v", err)
	}
	const schemaURL = "https://compliantai.example/schemas/audit-event-v1.schema.json"
	compiler := jsonschema.NewCompiler()
	compiler.AssertFormat()
	if err := compiler.AddResource(schemaURL, schemaDocument); err != nil {
		t.Fatalf("add audit schema: %v", err)
	}
	schema, err := compiler.Compile(schemaURL)
	if err != nil {
		t.Fatalf("compile audit schema: %v", err)
	}

	canonical, err := Canonical(canonicalFixture())
	if err != nil {
		t.Fatalf("Canonical(): %v", err)
	}
	var eventDocument map[string]any
	if err := json.Unmarshal(canonical, &eventDocument); err != nil {
		t.Fatalf("parse canonical event: %v", err)
	}
	if err := schema.Validate(eventDocument); err != nil {
		t.Fatalf("canonical event rejected by schema: %v", err)
	}

	invalidAuthDocuments := []map[string]any{}
	for _, mutation := range []func(map[string]any){
		func(document map[string]any) { document["oidc_issuer_hash"] = nil },
		func(document map[string]any) { document["auth_method"] = "api_key" },
	} {
		document := make(map[string]any, len(eventDocument))
		for key, value := range eventDocument {
			document[key] = value
		}
		mutation(document)
		invalidAuthDocuments = append(invalidAuthDocuments, document)
	}
	for _, document := range invalidAuthDocuments {
		if err := schema.Validate(document); err == nil {
			t.Fatal("schema accepted invalid auth/issuer combination")
		}
	}

	nanosecondDocument := make(map[string]any, len(eventDocument))
	for key, value := range eventDocument {
		nanosecondDocument[key] = value
	}
	nanosecondDocument["occurred_at"] = "2026-07-24T10:00:00.123456789Z"
	if err := schema.Validate(nanosecondDocument); err == nil {
		t.Fatal("schema accepted timestamp finer than PostgreSQL microseconds")
	}

	aboveMaxInt64 := json.Number("9223372036854775808")
	for _, field := range []string{
		"request_bytes",
		"response_bytes",
		"input_tokens",
		"output_tokens",
		"reserved_cost_micros",
		"actual_cost_micros",
	} {
		copyDocument := make(map[string]any, len(eventDocument))
		for key, value := range eventDocument {
			copyDocument[key] = value
		}
		copyDocument[field] = aboveMaxInt64
		if err := schema.Validate(copyDocument); err == nil {
			t.Fatalf("schema accepted %s above MaxInt64", field)
		}
	}
	oversizedCounts := make(map[string]any, len(eventDocument))
	for key, value := range eventDocument {
		oversizedCounts[key] = value
	}
	oversizedCounts["pii_match_counts"] = map[string]any{"tax_id": aboveMaxInt64}
	if err := schema.Validate(oversizedCounts); err == nil {
		t.Fatal("schema accepted PII match count above MaxInt64")
	}

	for _, forbidden := range []string{"prompt", "response", "content", "message", "details", "metadata", "request_body", "response_body"} {
		copyDocument := make(map[string]any, len(eventDocument)+1)
		for key, value := range eventDocument {
			copyDocument[key] = value
		}
		copyDocument[forbidden] = "CONTENT-CANARY"
		if err := schema.Validate(copyDocument); err == nil {
			t.Fatalf("schema accepted forbidden field %q", forbidden)
		}
	}

	schemaMap := schemaDocument.(map[string]any)
	properties := schemaMap["properties"].(map[string]any)
	requiredValues := schemaMap["required"].([]any)
	required := make([]string, 0, len(requiredValues))
	for _, value := range requiredValues {
		required = append(required, value.(string))
	}
	sort.Strings(required)
	goFields := make([]string, 0, reflect.TypeOf(Event{}).NumField())
	for index := 0; index < reflect.TypeOf(Event{}).NumField(); index++ {
		goFields = append(goFields, reflect.TypeOf(Event{}).Field(index).Tag.Get("json"))
	}
	sort.Strings(goFields)
	if !reflect.DeepEqual(required, goFields) {
		t.Fatalf("schema required fields differ from Event JSON fields:\nschema=%v\ngo=%v", required, goFields)
	}
	if len(properties) != len(goFields) {
		t.Fatalf("schema property count = %d, want %d", len(properties), len(goFields))
	}
}
