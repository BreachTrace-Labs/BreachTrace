# Paper blueprint

**Recommended title:** *Which Key Was Used? Measuring Attribution Limits After Repository Credential Exposure*

Alternatives: *From Repository Alert to Audit Evidence: A Cross-Provider Study of Credential Attribution*; *When Account Activity Becomes a Credential Claim: Evaluating Forensic Reports Under Incomplete Telemetry*.

**Thesis to test.** A credential-exposure investigation can be evaluated by following a known action through the audit source, collection, normalized event and investigator-facing assertion. The fraction of correct and supportable credential-specific conclusions may differ materially at each transition. This yields actionable guidance even where a native query performs as well as the integrated system.

## Section and evidence plan

| Section | Argument or artifact to put there | Required evidence |
|---|---|---|
| 1. Motivation | Open with one independently labelled benign example: two keys for the same principal, indistinguishable operation in one view, key-specific field in another. Identify the exact decision an investigator faces. | Redacted case from EXP-01/02 with evidence IDs. Until it exists use a labelled schematic. |
| 2. Scope and prior work | Detection, canary measurements, provenance systems, standards, commercial investigation tools, and incident summarization. Contrast observation models and evaluation units. | Literature matrix, current provider docs, equivalent-work search refresh. Avoid broad product rankings. |
| 3. Problem and threat model | Define credential, principal, user, initiated operation, native record, observation time, emitted claim and independent truth. Highlight legitimate sibling-key use, incomplete or late records, and ambiguous intent. | Objectives and action data dictionary. Explicitly exclude inference of attacker identity and mandatory notification. |
| 4. Methods/system | Show the actual per-incident route, native source mode, branch for detection-only, bounded collection, normalization, scope badge, score and report version. | Frozen source map and API specimens. One annotated architecture figure connecting components to measured transitions. |
| 5. Attribution model | Present paired indistinguishable worlds, field-aware baseline, scoring semantics and falsification criteria. Explain why same-input native query can recover all available information in some cases. | EXP-01/02 reference authoring, assumptions and source-field checks. |
| 6. Evaluation design | Define data ownership, independent sampling units, source and variant counts, held-out splits, blinded annotation, controls and unavailable cells. | Manifests, label rubric, agreement, case counts, paired design calculations, sensitivity and analysis code. |
| 7. Primary results | R1 evidence loss by transition. R2 wrong-key errors and useful coverage. R3 claim-level consistency across surfaces with independent truth. | EXP-01–03. Report counts, uncertainty, inconclusive conditions and all-assigned results. If any are missing, narrow the title and claims. |
| 8. Mechanisms and operational cost | Diagnose losses by missing identity, wrong key, timestamp, outcome, grouping and fallback. Report performance at measured loads only. | EXP-04/05; optional 06/07 in separate subsections. No model or scalability benefit without appropriate comparison. |
| 9. Interpretation | For each source, state what evidence can justify, what extra evidence could change that answer, and how often abstention occurred in sampled configurations. | Link each sentence to claim matrix and source condition. Include negative results and portability bounds. |
| 10. Ethics, validity, artifact | Cover consent/data rights, retention, redaction, transfer to new providers, replay fidelity, label disagreement and unavailable independent native data. | Risk register, protocol digest, reproducibility entry point and public/restricted manifest. |
| 11. Conclusion | Answer each primary RQ at its measured scope, name the remaining evidence gap. | Only supported matrix rows. Defer abstract and conclusion wording until analysis locks. |

## Formal elements

Use incident target k, action ledger A, native records R, independent linkage M ⊆ A×R, and method decision d(r) ∈ {target, other, unknown}. For GCP the actual rule requires eligible platform, associated key, matching principal and well-formed provider key resource. A valid differing digest gives other; missing/inconsistent fields give unknown or inapplicable. A matching key identifies a credential on that record. It cannot identify the person holding it or establish that exposure caused its use.

The implemented sets are S = {r : t(r) ≥ t_commit} for the stored pipeline score and W = {r ∈ S : t_end missing or t(r) ≤ t_end} for the bounded dynamic summary. Both are intersected with the acquired record set. In the paper compare them with the independent observation interval. Equality at the boundary, clock conversion and absent endpoints matter. One cannot derive authentic exposure duration from these definitions.

For each source and method tabulate Y = warranted target actions recovered / initiated target actions and E = non-target actions assigned to target / non-target actions. Compare paired differences in Y and E. Source-field ceiling estimates are empirical adjudications under a specified information set. They are not universal theoretical maxima. The indistinguishable-worlds example supplies a narrower mathematical limit. A research-only assertion provenance record should include scope, outcome, time basis and supporting source IDs. Distinguish that proposed representation from current implementation.

## Figure and table production map

| Exhibit | Required input and encoding |
|---|---|
| F1 system and audit boundaries | Source map. One lane each for exposure signal, provider record, derived fact and prose. Distinguish simulated, historical and regular paths. |
| T1 dataset and baselines | Manifest and scope table: accounts, independent cases, actions, records, source modes, missing/ambiguous links, provider configuration and fair input budget. |
| F2 evidence retention | EXP-01. Separate action denominator from record denominator in adjacent panels. Show unavailable modes as NA, zero only for observed zero. |
| F3 selective attribution | EXP-02. Per-source coverage vs error plus separate target yield and confidence intervals. Label always-abstain as undefined conditional error. |
| F4 annotated timeline | EXP-03. Show commit estimate, independent observation interval, arrival and closure; source IDs beside paired timeline/report claims. |
| T2 and F5 semantic failures | EXP-03/04. Identity/outcome confusion and unsupported-claim incidence by surface, with raw counts and blind agreement. |
| F6 robustness | EXP-05. Per-fault received records, useful yield and silent failure versus clean counterpart. Do not assign frequency weights without field data. |
| F7 optional performance | EXP-06. Load vs completion probability, latency distribution and RSS; separate queue and service clocks. |
| T3 optional reporting | EXP-07. Template, raw model, facts-only, validated hybrid; first attempt and delivered text in distinct columns. |
| Appendix | EXP-08/09 where available; baseline queries, matching and scope rubric, risks, privacy/access limitations, result-to-claim table. |

**Venue fit.** Consider a digital forensics or empirical security measurement venue if native-source evidence and independent truth are strong. A reproducible lab-only artifact fits a workshop, tools or dataset track with clear scope. A human-centered venue needs the analyst study and sampling rationale. A broad systems venue would need independent deployment or substantially stronger generalizable insight. No venue-level acceptance prediction follows from the prototype.
