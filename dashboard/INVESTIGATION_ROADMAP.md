# Analyst investigation workflow

Trace is a tool for analysts to interpret evidence. ML prioritizes unusual requests; the analyst connects events, forms a hypothesis and documents findings. Report exports should organize selected evidence and analyst notes, without generating an attack narrative.

## Implemented in this update

- Home page with analyst workflow and model-scoring diagrams.
- Routes for home/overview, analysis, model methodology and individual investigations, with browser Back/Forward navigation and server fallbacks.
- Filename-based result headings and candidate time ranges as investigation titles.
- File, paste and saved-investigation input tabs.
- Model confidence slider with a concise explanation that its value is an anomaly percentile, not attack probability.
- Simplified header/actions and no account dropdown. Account search remains available.
- Model training methodology, a temporal split diagram and README benchmark results. Benchmarks are separate from currently available detector choices.

Routing preserves the current analysis while navigating in the same tab. It does not persist uploaded logs across a full reload. Use the saved-investigation file to restore those records.

## Priority 1 — Selected-request history

Automatically compare the selected request with earlier requests for the same account, method and exact target. Show status counts, response sizes, the most recent matching requests and links to original records. Let analysts explicitly broaden the comparison to other accounts or endpoint patterns.

A summary should be concrete, such as “Earlier matching requests returned 403; this request returned 200.” Calculate the historical window relative to the selected event, never include future events in an earlier baseline, and expose the full matching set behind the summary. Preserve source line numbers.

## Priority 2 — Surrounding activity

Show the requests immediately before and after the selected event, regardless of anomaly score. Start with a small time window that the analyst can expand. Provide simple account and source toggles within this evidence panel rather than adding more global controls.

Make time differences visible. An ordinary forum view one second before a privileged POST can be more useful than another high-scoring event.

## Priority 3 — Related resources and source history

Find activity across accounts involving the same resource, such as the view and edit endpoints for forum item 1042. Explain every proposed relationship using the actual matched account, source or resource identifier. Allow the analyst to inspect all matching requests and widen or narrow the relationship.

Show whether an account has used a source before, the first observed occurrence and other accounts associated with the source. Do not equate a source address with a person or physical device.

## Priority 4 — One clear evidence workflow

Keep the investigation workspace focused on a candidate list, the selected request and the retained timeline. Use Details, History and Related views within the selected-request panel. Collapse raw logs, model internals and secondary comparisons until needed.

Provide one obvious Add to timeline action for any related or historical request. Keep original scores intact, deduplicate records by source line, allow removal/undo and add short analyst notes. Support manually connecting evidence across accounts and days; automatic grouping must not prevent a coherent reconstruction.

## Priority 5 — Trustworthy save and export

Preserve original records, model provenance, retained events, ordering and notes. Export the analyst's findings with full evidence references, without adding a generated explanation. Show later contradictory evidence, such as access returning to 403, alongside the proposed timeline.

For a later usability pass, consider local autosave with clear storage controls and a recovery path. Uploaded records should not silently become permanent browser storage as a side effect of routing.

## Keep the interface simple

Every feature should answer one of three questions: why is this request unusual, what happened around it, or what evidence supports the conclusion? Favor a few connected evidence tools over new dashboard tiles, clustering visualizations, global dropdowns or a chat assistant. Homepage descriptions should reflect shipped functionality, not this roadmap.
