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
| Standard typed attribute/form routing | Supported | `location`, `ranges`, `stmt_list`, type-reference, reference-metadata (`containing_type`, `friend`, `common_reference`, `call_origin`, `base_types`, `namelist_item`, `trampoline`, `extension`), address metadata (`entry_pc`, `call_return_pc`), scalar/string/flag metadata used by `TypeSystem` and `TypePrinter` (including scale/count, visibility/access, textual metadata, boolean declaration/property flags, and standard split/section base attributes such as `dwo_id`, `signature`, `addr_base`, `rnglists_base`, `loclists_base`, `str_offsets_base`, `macro_info`, and `macros`), call-site/discriminant payload attributes (`call_value`, `call_parameter`, `discr_list`), and standard constant/bound-style metadata (`const_value`, `default_value`, `data_location`, `string_length`, `lower_bound`, `upper_bound`, `count`, `allocated`, `associated`, `rank`, `byte_stride`, `bit_stride`, `start_scope`, `data_bit_offset`, `string_length_bit_size`, `string_length_byte_size`) decode through explicit typed paths; invalid standard form pairings degrade to deterministic empty typed values instead of vendor-form recovery. |
| Semantic helpers for preserved payload attrs | Supported | Utility helpers provide structured decoding for parsed `DW_AT_call_value`, `DW_AT_call_parameter`, and `DW_AT_discr_list` payloads, including raw bytes, DWARF-expression tokens, assembly rendering, and `dwarf_dump` surfacing without introducing new core attribute types. |
| Standard relationship semantic attrs | Supported | `DW_AT_trampoline` and `DW_AT_extension` now decode through the same explicit reference-metadata path as the repo’s other standard DIE relationship attributes and surface as ordinary references. |
| DWARF 5 line table content preservation | Supported | Standard directory/file entry fields are preserved, including extra directory metadata and file MD5 payloads. |

## Expression opcodes

| Opcode family | Status | Notes |
|---|---|---|
| Core stack/arithmetic/compare ops | Supported | Includes literal/register range opcodes, branch ops, and utility string round-trip mapping for these families. |
| Typed ops (`*_type`, `convert`, `reinterpret`) | Supported | Includes GNU predecessors. |
| Indexed ops (`DW_OP_addrx`, `DW_OP_constx`) | Supported | Includes GNU predecessors (`*_index`) plus utility round-trip and operand-size decoding. |
| Piecewise locations (`DW_OP_piece`, `DW_OP_bit_piece`) | Supported | Composite location output with implicit/unavailable piece handling. |
| TLS ops (`DW_OP_form_tls_address`, GNU variant) | Supported | Produces TLS-flavored symbolic/evaluated values. |
| Entry/call ops (`DW_OP_entry_value`, `DW_OP_call2/4/call_ref`) | Supported | Call/ref resolution uses DIE cache and section-relative semantics; `entry_value` now materializes register-location subexpressions as entry-time register values and address-location subexpressions as entry-time loads in both evaluators. |
| WebAssembly extension (`DW_OP_WASM_location`) | Supported | Utility decode/tokenization includes kind/index annotations, and both concrete and symbolic evaluators now preserve WASM locations as synthetic register-location identifiers rather than downgrading them to plain values. |
| GNU extensions (`DW_OP_GNU_*`) | Supported | The enumerated GNU predecessor opcode set is implemented in utility decoding plus concrete and symbolic evaluators, including `push_tls_address`, `uninit`, `encoded_addr`, `implicit_pointer`, `entry_value`, typed predecessors, `parameter_ref`, and `*_index`. `DW_OP_GNU_encoded_addr` handles `absptr`, `pcrel`, `textrel`, `datarel`, `funcrel`, and `aligned` application modes with the same best-effort unknown-format `absptr` fallback in both evaluators. |
| Unknown vendor/extension opcodes | Unsupported | Opcodes outside the known GNU set remain rejected by design while preserving structured unsupported metadata (`unsupported_opcode`, `unsupported_vendor_extension`) in evaluator and CLI diagnostics. |

## Split DWARF

| Area | Status | Notes |
|---|---|---|
| `.dwo` discovery/loading | Supported | Skeleton CU attributes (`dwo_name`, `dwo_id`) are consumed and linked, including real compiler-produced relocatable split-DWARF objects. |
| `.dwp` CU/TU index parsing | Supported | Section id tables and slot mapping are parsed and bounded; tests cover synthetic package fixtures and real `.dwo` payloads consumed through a packaged `.dwp` path. |
| DWO address table use in expression eval | Supported | `DW_OP_addrx`/`DW_OP_constx` can resolve against `.debug_addr.dwo`. |
| Unsupported/unknown index section ids | Supported | Unknown sections are skipped safely, and observed unknown `DW_SECT_*` ids are surfaced through parser/runtime telemetry; no specialized decoding beyond known ids. |

## Legacy Standard Sections

| Section family | Status | Notes |
|---|---|---|
| `.debug_macinfo` | Supported | `DW_AT_macro_info` resolves through the legacy macro parser; `DW_AT_macros` continues to use `.debug_macro`. |
| `.debug_aranges` | Supported | Parsed into CU-associated address ranges and exposed through `DwarfParser`. |
| `.debug_pubnames`, `.debug_pubtypes` | Supported | Parsed into legacy public name/type records and exposed through `DwarfParser`. |

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

## Recent hardening

1. Added real compiler-produced split-DWARF fixture coverage for relocatable `.o` + `.dwo` loading.
2. Added hybrid `.dwp` coverage that packages real `.dwo` payload sections behind a CU index and verifies package-only resolution.
3. Expanded vendor-form recovery to handle nested vendor-mirrored indirect payloads.
4. Broadened known-shape vendor-form recovery across mirrored string-pointer, offset, indexed, supplementary-reference, and fixed-width payload families instead of treating them as generic offset-sized fallbacks.
5. Added reusable text/JSON schema-v2 test helpers for `--show-support` vendor-form telemetry.
6. Added evaluator support and regression coverage for `DW_OP_GNU_encoded_addr` text/data/function-relative application modes.
7. Added evaluator and utility-tokenization support for `DW_OP_GNU_encoded_addr` aligned payload decoding.
8. Expanded `DW_OP_GNU_implicit_pointer` evaluation to preserve value/register referents instead of collapsing non-address referents.
9. Preserved `DW_OP_GNU_uninit` as an explicit uninitialized-result taint in concrete and symbolic evaluation.
10. SMT verification now treats symbolic `unknown(...)` leaves as opaque solver variables instead of failing encoding immediately, reducing `UNKNOWN` outcomes for normalized branch/piece expressions.
11. SMT verification now treats `uninitialized` taint as part of semantic equivalence, rejecting matches where value expressions agree but taint differs.
12. SMT verification now handles top-level wide byte literals deterministically with prechecks instead of dropping to `encoding_error` for `BYTES` values larger than 64 bits.
13. SMT verification now applies the same deterministic prechecks to composite piece locations carrying wide implicit-byte expressions, avoiding `encoding_error` for large merged implicit pieces.
14. SMT verification now short-circuits exact structural matches for unsupported symbolic shapes (for example, identical `load(..., 9)` expressions), reducing `UNKNOWN` outcomes when both sides normalize to the same non-encodable form.
15. SMT verification now models oversized symbolic loads as opaque solver-visible values keyed by their symbolic form, so mismatches like `load(..., 9)` versus a constant can produce real counterexamples instead of generic `encoding_error`.
16. SMT verification now treats wide concrete `BYTES` literals as opaque solver-visible values when compared against non-byte symbolic forms, so wide implicit values can also produce real `sat` mismatches.
17. `compare-expr` CLI coverage now includes solver-visible wide-byte and oversized-load mismatches end to end, including JSON/text row output and `fail-on-solver-result=sat` gate behavior.
18. SMT verification now treats malformed/internal symbolic shapes with invalid node arity as deterministic precheck outcomes instead of generic `encoding_error`, both for top-level values and composite piece locations.
19. SMT verification now treats zero-byte symbolic loads and invalid symbolic kind discriminants as deterministic precheck outcomes instead of generic `encoding_error`, both for top-level values and composite piece locations.
20. SMT encoding now falls back to opaque solver-visible terms for malformed/invalid symbolic nodes that somehow bypass verifier prechecks, so residual `encoding_error` is reserved for verifier/backend failures rather than symbolic-expression content.
21. SMT symbolic verification no longer reports `encoding_error` for symbolic-expression content paths; any future occurrence should be treated as a backend or verifier defect rather than a supported DWARF limitation.
22. Optional real `dwp` fixture coverage now auto-activates when `dwp` or `llvm-dwp` is available in the test environment, while continuing to skip cleanly on environments that only have compiler-produced `.o` + `.dwo` support.

The real packaged-`.dwp` coverage path currently has three explicit environment requirements:
1. a compiler that can emit split-DWARF `.o` + `.dwo` output,
2. either `dwp` or `llvm-dwp` on `PATH`, and
3. a test environment that allows invoking those tools at runtime.
When any of those are missing, the parser and CLI real-package tests intentionally report a skip rather than a failure.

## Next gaps to target

1. Promote the optional real toolchain-produced `.dwp` package tests into CI or other environments where `dwp`/`llvm-dwp` is guaranteed to be available.
2. Expand vendor-form skip heuristics for additional payload families only as new real-world samples surface beyond the currently covered mirrored string-pointer, offset, indexed, block, supplementary-reference, fixed-width, and nested-indirect shapes.
3. Broaden non-GNU vendor expression opcode semantics only when real producer samples justify it; unknown vendor ops remain intentionally diagnosed and rejected.
