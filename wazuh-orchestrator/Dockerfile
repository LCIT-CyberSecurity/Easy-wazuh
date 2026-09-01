FROM python:3.12-slim

RUN useradd --create-home --uid 10001 orchestrator

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY --chown=orchestrator:orchestrator . .

USER orchestrator
ENTRYPOINT ["python3", "wazuh-orchestrator.py"]
