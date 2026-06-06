# syntax=docker/dockerfile:1
# Multi-stage build: a build stage installs the package into a venv, the final
# stage copies only the venv + source -> smaller, no build toolchain shipped.

# --- build stage ----------------------------------------------------------- #
FROM python:3.12-slim AS build

ENV PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /build
RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Install runtime deps first (layer-cached) using the project metadata.
COPY pyproject.toml README.md ./
COPY src ./src
# Core deps + the production "agents" extra (LangGraph + LlamaIndex).
RUN pip install ".[agents]"

# --- final stage ----------------------------------------------------------- #
FROM python:3.12-slim AS final

ENV PATH="/opt/venv/bin:$PATH" \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    OLLAMA_HOST="http://ollama:11434" \
    SENTRA_MODEL="llama3.1:8b" \
    SENTRA_KB="/app/data/attack_kb/techniques.json"

# Non-root runtime user.
RUN useradd --create-home --uid 10001 sentra

WORKDIR /app
COPY --from=build /opt/venv /opt/venv
COPY src ./src
COPY data ./data

USER sentra
EXPOSE 8000

# Liveness: the API's own healthz endpoint.
HEALTHCHECK --interval=15s --timeout=3s --start-period=20s --retries=3 \
    CMD python -c "import httpx,sys; sys.exit(0 if httpx.get('http://localhost:8000/healthz').text=='ok' else 1)"

CMD ["uvicorn", "sentra.api.service:app", "--host", "0.0.0.0", "--port", "8000", "--app-dir", "src"]
