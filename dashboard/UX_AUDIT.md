# Investigation redesign

## Critique of the previous interface

The user had to infer relationships across filters, a score table, time buckets,
and a list of request sequences. The application found unusual rows but did not
maintain an investigation as the user moved between views. Score ranking also
broke chronological order. A top-N queue could omit part of a sequence.

The old narrative titles promoted request indicators into conclusions such as
“Login failed.” HTTP results and model output do not by themselves prove that
application-level event. Those generated activity labels should be removed.

Score-versus-time is a diagnostic, not a behavioral clustering view. A percentile
is a ranking, not attack confidence. Neither tells an analyst what changed for
this account. Model switching previously replaced the analysis context, making
comparison difficult. An analyst also lacked tools to reject or edit the proposed
reconstruction, and exports did not preserve those decisions.

Keep the simple upload flow, real progress, original logs, account/IP filters,
local scoring, surrounding requests, and native detector scores. Move request
records inside an investigation. Merge timeline and request inspection into a
linked workspace. Replace generic overview charts with candidate investigations.
Remove invented behavioral labels, decorative selection treatments, and the
always-visible score plot.

## Information architecture and screen hierarchy

1. **Upload and process:** select logs and an available detector. Preserve the
   existing streaming processing progress; continuous log ingestion is out of scope.
2. **Investigations found:** account, observed time range, associated sources,
   request progression, candidate count, and detector provenance. Search and
   account filtering narrow investigations; the detection cutoff remains explicit.
3. **Investigation workspace:** factual summary, chronological episodes, then
   individual requests. A persistent adjacent evidence workspace keeps the story
   visible while inspecting parsed data, model evidence, and original logs.
4. **Earlier-upload comparison:** show previous observed sources, targets, rates,
   time windows, and supporting records. This is an upload comparison, not a
   claim that previous traffic was normal or that a learned baseline exists.
5. **Export:** an investigation report with Who / What / When / How, detector
   evidence, analyst notes, and original records; retain raw CSV.

## Interactions

Selecting an episode shows its aggregate model evidence. Selecting a request
shows that exact record in the model visualization. Selecting a plotted record
returns to its episode. Changing the model lens preserves investigation, event,
and analyst edits. Unrun models are labeled unrun; an explicit action scores the
same upload. Unavailable detectors are not simulated. Model disagreements remain
visible as separate perspectives, not independent confirmations.

Analysts can rename, merge, and split episodes; remove or restore events; mark
requests important or benign; promote contextual requests; and add notes. These
edits change the reconstruction, not detector scores or original logs. Notes and
edits belong to the current browser session and exported report.

## Model interface

Use a common adapter receiving the selected rows, the full scored upload, and the
model run. Present the detector's native metric and an honest contextual view.
GMM uses negative log density; the autoencoder exposes its actual normalized
ensemble reconstruction metric; rule scores are explicitly fixed indicators;
hybrid review separates detector outputs from LLM verdicts. Percentiles appear
only as baseline or batch ranks. They are never universal confidence.

Memberships, embeddings, per-feature reconstructions, local neighborhoods, and
other model-specific artifacts should appear only when the backend provides
actual values. Current score-only responses cannot support those visualizations.
A selected-event score distribution is the honest fallback. The adapter supports
future detector-specific evidence without changing the investigation structure.

## Evidence and limits

Direct observations, model output, statistical comparisons, and analyst
interpretation are separate. Episode names default to literal request methods
and targets. Temporal/account grouping is a disclosed hypothesis, not validated
incident correlation. Anonymous requests relate by source IP; authenticated
account grouping can span source changes. A 30-minute candidate gap starts a new
investigation; nearby contextual requests remain available.

Implementation is reviewed from source only. Browser use and tests remain off at
the user's request; runtime interaction and visual checks have not been performed.
