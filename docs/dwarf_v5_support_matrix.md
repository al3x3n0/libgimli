# DWARF v5 Support Matrix

This matrix documents current coverage for DWARF v5 forms/opcodes and split-DWARF handling in this repository.

## Forms

| Form family | Status | Notes |
|---|---|---|
| `DW_FORM_strx`, `DW_FORM_strx1..4` | Supported | Resolves through `.debug_str_offsets` with contribution bounds. |
| `DW_FORM_addrx`, `DW_FORM_addrx1..4` | Supported | Resolves through `.debug_addr` with contribution bounds and segment-selector stride handling. |
| GNU indexed predecessors (`DW_FORM_GNU_str_index`, `DW_FORM_GNU_addr_index`) | Supported | Parsed as aliases of `strx`/`addrx` semantics. |
| `DW_FORM_loclistx` | Supported | Resolves via `.debug_loclists` index tables. |
| `DW_FORM_rnglistx` | Supported | Resolves via `.debug_rnglists` index tables. |
| `DW_FORM_line_strp` | Supported | Uses `.debug_line_str`. |
| `DW_FORM_strp_sup` | Supported | Uses supplementary debug string section. |
| `DW_FORM_ref_sup4`, `DW_FORM_ref_sup8` | Supported | Supplementary references are parsed and biased for lookups. |
| GNU alt forms (`DW_FORM_GNU_strp_alt`, `DW_FORM_GNU_ref_alt`) | Supported | Parsed as supplementary string/reference forms with CU-format-sized offsets. |
| `DW_FORM_data16` | Supported | Parsed as 16-byte block. |
| `DW_FORM_implicit_const` | Supported | Value is read from abbrev SLEB128 and propagated as signed attribute value. |

## Expression opcodes

| Opcode family | Status | Notes |
|---|---|---|
| Core stack/arithmetic/compare ops | Supported | Includes literal/register range opcodes, branch ops, and utility string round-trip mapping for these families. |
| Typed ops (`*_type`, `convert`, `reinterpret`) | Supported | Includes GNU predecessors. |
| Indexed ops (`DW_OP_addrx`, `DW_OP_constx`) | Supported | Includes GNU predecessors (`*_index`) plus utility round-trip and operand-size decoding. |
| Piecewise locations (`DW_OP_piece`, `DW_OP_bit_piece`) | Supported | Composite location output with implicit/unavailable piece handling. |
| TLS ops (`DW_OP_form_tls_address`, GNU variant) | Supported | Produces TLS-flavored symbolic/evaluated values. |
| Entry/call ops (`DW_OP_entry_value`, `DW_OP_call2/4/call_ref`) | Supported | Call/ref resolution uses DIE cache and section-relative semantics. |
| WebAssembly extension (`DW_OP_WASM_location`) | Supported | Utility decode/tokenization includes kind/index annotations and baseline concrete/symbolic evaluator semantics (synthetic WASM location values). |
| GNU extensions (`DW_OP_GNU_*`) | Partial | Major extensions implemented, including utility operand-size decoding for known GNU predecessors (`*_index`, `parameter_ref`, `encoded_addr`) with context-aware address/offset size support in tokenization/assembly helpers; unsupported-op diagnostics now include CU/DIE/attribute context in both concrete and symbolic evaluators. Unknown vendor ops remain unsupported by design. |

## Split DWARF

| Area | Status | Notes |
|---|---|---|
| `.dwo` discovery/loading | Supported | Skeleton CU attributes (`dwo_name`, `dwo_id`) are consumed and linked. |
| `.dwp` CU/TU index parsing | Supported | Section id tables and slot mapping are parsed and bounded. |
| DWO address table use in expression eval | Supported | `DW_OP_addrx`/`DW_OP_constx` can resolve against `.debug_addr.dwo`. |
| Unsupported/unknown index section ids | Partial | Unknown sections are skipped safely; no specialized decoding beyond known ids. |

## Runtime Support Fields (`dwarf_dump --show-support`)

`dwarf_dump --show-support` rows are emitted from a canonical in-tree table (`include/dwarf_support_matrix.hpp` + `src/dwarf_support_matrix.cpp`) so text/json output stays synchronized across CLI code paths.

When a file path is provided, runtime output includes split-DWARF observability fields:

1. `has_loaded_dwp`: whether a `.dwp` package was loaded.
2. `dwp_path`: loaded `.dwp` path (empty when none loaded).
3. `has_dwp_cu_index`: whether `.debug_cu_index` is present in the loaded `.dwp`.
4. `dwp_cu_index_valid`: whether CU index parsing succeeded.
5. `dwp_cu_index_units`: number of units indexed in CU index.
6. `dwp_hits`: units resolved from `.dwp`.
7. `dwo_hits`: units resolved from `.dwo`.
8. `dwo_fallback_hits`: times parser fell back to `.dwo` after attempting `.dwp`.
9. `fallback_no_index`: fallback because `.debug_cu_index` was absent.
10. `fallback_invalid_index`: fallback because CU index was present but malformed/invalid.
11. `fallback_sig_miss`: fallback because index was valid but unit signature was not found.
12. `has_dwp_tu_index`: whether `.debug_tu_index` is present in loaded `.dwp`.
13. `dwp_tu_index_valid`: whether TU index parsing succeeded.
14. `dwp_tu_index_units`: number of units indexed in TU index.
15. `vendor_form_skips`: number of unsupported vendor-form attributes skipped via recovery heuristics while parsing loaded units.
16. `vendor_form_skip_examples`: semicolon-separated sample entries (`form=0x...,off=0x...,cu=0x...,die=0x...,attr=...`) for the first skipped vendor forms encountered (deduplicated by form+attribute to prioritize unique exemplars).
17. `vendor_form_skip_examples_structured` (JSON schema v2): structured array of `{form,offset,cu_offset,die_offset,attr}` entries while preserving the v1 string field for compatibility.
18. `vendor_form_skip_histogram`: compact text histogram (`0xFORM:count;...`) of top skipped vendor forms by occurrence.
19. `vendor_form_skip_histogram_structured` (JSON schema v2): structured array of `{form,count}` entries sorted by descending count.
20. `vendor_form_skip_offset_buckets`: compact text buckets (`bucket:count;...`) for coarse skip regions (`before_die`, `unit_die_payload`, `child_die_payload`).
21. `vendor_form_skip_offset_buckets_structured` (JSON schema v2): structured array of `{bucket,count}` entries.
22. `vendor_form_skip_severity_buckets`: compact text severity counts (`known_shape:N;fallback_offset_sized:M;...`) distinguishing recovery strength.
23. `vendor_form_skip_severity_buckets_structured` (JSON schema v2): structured array of `{severity,count}` entries.

## Split-DWARF Troubleshooting

`fallback reason=no_cu_index`:
1. Confirm the `.dwp` actually contains `.debug_cu_index`.
2. Regenerate package with toolchain packaging step enabled (for example, `dwp` stage in build).
3. If no package index is expected, ensure corresponding `.dwo` files are discoverable via search paths.

`fallback reason=invalid_cu_index`:
1. Validate `.debug_cu_index` integrity (truncated/corrupted payloads will be rejected).
2. Rebuild/repackage `.dwp` from original `.dwo` files.
3. Check for tooling mismatch between producer/consumer versions if index format differs.

`fallback reason=signature_not_found`:
1. Confirm `DW_AT_dwo_id`/unit signature in skeleton CUs matches entries in `.debug_cu_index`.
2. Ensure `.dwp` corresponds to the same binary revision as the main object/executable.
3. If package is incomplete, keep `.dwo` files available to allow fallback resolution.

## Next gaps to target

1. Add fixture-backed end-to-end tests from real `-gsplit-dwarf` binaries for GCC and Clang variants.
2. Expand vendor-form skip heuristics for additional payload families as real-world samples surface (for example indirect chains with unknown nested forms).
3. Add structured text/JSON helpers for parsing `--show-support` runtime telemetry in tests to reduce ad-hoc substring assertions as the schema grows.
