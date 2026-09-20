# Bundled trained models

This is the frozen model bundle used by the hosted demo: the feature encoder,
GMM parameters, autoencoder weights, calibration distributions, and permission
profiles. Unsupervised fitting learns these from unlabeled training logs.

These artifacts and their learned user/IP profiles are intentionally public.
They are copied into the Railway image, not into Vercel's static frontend.
No API keys or raw log files are included.

To update, train locally and replace the entire bundle from
`results/model_store/` together. Do not combine files from different runs.
