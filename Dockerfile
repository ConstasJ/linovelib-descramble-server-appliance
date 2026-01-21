FROM python:3.14-slim

COPY --from=ghcr.io/astral-sh/uv:latest /uv /uvx /bin/

COPY . /app

WORKDIR /app
RUN uv sync --frozen --no-cache

EXPOSE 5302
CMD ["/app/.venv/bin/fastapi", "run", "main.py", "--port", "5302", "--host", "0.0.0.0"]