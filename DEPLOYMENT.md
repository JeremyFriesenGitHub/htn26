# Deploy the dashboard on Vercel and the API on Railway

The current frontend is `dashboard/`: plain HTML, CSS, and JavaScript. It does not
need a Node application server. Vercel serves those files and proxies `/api/*`
to Railway, keeping browser requests on the same origin (no CORS setup needed).
The build uses Vercel's [Build Output API](https://vercel.com/docs/build-output-api/configuration).

The Python backend already contains heuristic scoring, trained GMM and deep AE
inference, and GMM + OpenAI triage. `bench/api.py` exposes the same scoring code
through Flask/Gunicorn for hosting. `python -m bench.dashboard` remains the local UI.

## 1. Railway backend

1. Push these changes, then create a Railway service from this repository. Use the
   **repository root** as its root directory. Railway uses `Dockerfile` and
   `railway.json`; leave the start-command override empty.
2. Generate a public domain under Networking. `/api/health` should return
   `{"status":"ok"}`. The container binds to `0.0.0.0:$PORT` automatically.
3. The trained models are bundled in `deployment/models/` and copied into the
   Docker image automatically. No volume or model upload is required.
4. Check `/api/status`: GMM and Deep AE should be available.
5. Optionally set **`OPENAI_API_KEY`** on Railway to enable hybrid triage. Never
   put that key in Vercel's frontend or commit `.keys.env`.

For custom models, mount a volume at `/models`, set `MODEL_STORE=/models`, and
upload a complete replacement model store. Restart after replacing files.
An empty volume falls back to the bundled models. A volume containing any model
artifact is authoritative; incomplete custom stores are not mixed with the bundle.
Local trained files in `results/model_store/` likewise take precedence by default.

Required artifacts:

| Feature | Files |
| --- | --- |
| GMM | `encoder.pkl`, `gmm.pkl`, `calibration3_gmm.json` |
| Deep AE | `encoder.pkl`, `ae_meta.pkl`, `ae_models.pt`, `calibration3_ae.json` |
| Hybrid | GMM files plus `profiles.json`, `profiles.artifacts.json`, and `OPENAI_API_KEY` |

The calibration files preserve training-baseline scores without shipping raw
training logs. Without them, scoring falls back to percentiles within the upload.
The profiles file supplies learned permission context for LLM triage. Copy only
your own trusted model artifacts: Python pickle files contain executable data.
The bundled artifacts include calibration and profiles, so raw training logs are not needed.

The image uses Python 3.13 and matching numerical-library versions from this
checkout, with CPU PyTorch (no GPU required). It does not train models on startup.
`MAX_UPLOAD_BYTES` optionally changes the API's default 32 MiB request limit.
Hosting proxy limits and request timeouts still apply; very large uploads or slow
LLM calls may require an asynchronous job API in future.

This is a public demo API without user authentication or per-user rate limits.
If you enable the OpenAI key, callers can trigger paid triage requests.

## 2. Vercel frontend

1. Import the same repository. Set **Root Directory** to the repository root
   (not `dashboard`) and **Framework Preset** to **Other**.
2. Set **`BACKEND_URL=https://YOUR-SERVICE.up.railway.app`** for Production and
   Preview environments as needed. Use the origin only, without `/api`.
3. Leave build, install, and output-directory overrides disabled; `vercel.json`
   runs `node scripts/build-vercel.mjs`. No npm dependencies are needed.
4. Deploy. The build writes `.vercel/output/static` and an external API route.
   It intentionally fails if `BACKEND_URL` is missing or malformed.
5. Open the deployed dashboard, select **Try sample logs**, and run heuristic
   analysis. Then verify GMM and Deep AE become selectable after models are loaded.

Redeploy Vercel after changing `BACKEND_URL` because the proxy destination is
generated at build time. Both production and preview deployments can use the same
Railway backend. Vercel's `/api/health` should return the backend health response.

## Local verification

```bash
docker build -t htn26-api .
docker run --rm -p 8080:8080 \
  -e MODEL_STORE=/models \
  -v "$PWD/results/model_store:/models:ro" htn26-api
```

Open `http://localhost:8080/api/health` or `/api/status`. The production image is
API-only; for the combined local frontend and API use:

```bash
.venv/bin/python -m bench.dashboard
```

To verify the Vercel build locally with Node.js installed:

```bash
BACKEND_URL=https://YOUR-SERVICE.up.railway.app node scripts/build-vercel.mjs
```

For backend tests install `requirements-serve.txt`, then run
`python -m unittest discover -s tests -v`. The original local dashboard tests also
work without ML/Flask packages; production API tests skip when Flask is absent.
