# Schema conformance data

These are language-independent inputs for [the schema contract](../../docs/schema_format.md).
A consumer can implement schema validation in another language and compare its
results without Go or the development generator.

Each `cases/<name>/` directory contains a `schema.json` input, `want.json` result
and optional `case.json` metadata. Expected results distinguish acceptance from
a named error. Preserve numeric values, key presence, duplicate keys and raw
input bytes: parsing and re-encoding an invalid fixture can hide its error.
The `downstream/` directories contain additional fixed positive schema inputs.

The development checkout owns regeneration and source provenance. The source
package omits generator-only base pins and why/source metadata. English note,
authority and detail values describe the same schema conditions as the original
fixtures; they do not change the expected validation result.
