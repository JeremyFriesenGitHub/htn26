FROM python:3.13-slim
ENV PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1 OMP_NUM_THREADS=1
WORKDIR /app
COPY requirements-serve.txt ./
RUN pip install --no-cache-dir -r requirements-serve.txt
# CPU inference avoids downloading the CUDA runtime on Railway.
RUN pip install --no-cache-dir torch==2.6.0 --index-url https://download.pytorch.org/whl/cpu
COPY bench ./bench
COPY deployment/models ./deployment/models
CMD ["sh", "-c", "exec gunicorn bench.api:app --bind 0.0.0.0:${PORT:-8080} --workers 1 --threads 4 --timeout 300 --error-logfile -"]
