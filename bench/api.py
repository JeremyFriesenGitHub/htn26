"""Production API: gunicorn bench.api:app (the local dashboard stays standalone)."""
import os

from flask import Flask, jsonify, request
from werkzeug.exceptions import HTTPException

from . import dashboard

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = int(os.environ.get("MAX_UPLOAD_BYTES", 32 * 1024 * 1024))


@app.after_request
def response_headers(response):
    response.headers["Cache-Control"] = "no-store"
    response.headers["X-Content-Type-Options"] = "nosniff"
    return response


@app.errorhandler(dashboard.APIError)
def api_error(error):
    return jsonify(error=str(error)), error.status


@app.errorhandler(HTTPException)
def http_error(error):
    return jsonify(error=error.description), error.code


@app.errorhandler(Exception)
def unexpected_error(error):
    # Do not log exceptions that could contain uploaded log lines or credentials.
    app.logger.error("API failure: %s", type(error).__name__)
    return jsonify(error="Analysis could not complete. Check the backend configuration."), 500


@app.get("/api/health")
def health():
    # Liveness is independent of optional ML packages, artifacts, and OpenAI.
    return jsonify(status="ok")


@app.get("/api/status")
def status():
    result = dashboard.model_status()
    result["max_bytes"] = app.config["MAX_CONTENT_LENGTH"]
    return jsonify(result)


@app.get("/api/sample")
def sample():
    return jsonify(dashboard.sample_payload())


@app.post("/api/predict")
def predict():
    return jsonify(dashboard.predict_payload(request.get_json()))
