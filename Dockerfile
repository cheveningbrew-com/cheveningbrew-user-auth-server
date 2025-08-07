# Use Python image and add uv
FROM python:3.11-slim
COPY --from=ghcr.io/astral-sh/uv:latest /uv /uvx /bin/

# Set the working directory
WORKDIR /app

# Enable bytecode compilation
ENV UV_COMPILE_BYTECODE=1
ENV UV_LINK_MODE=copy
ENV PATH="/app/.venv/bin:$PATH"

# Copy dependency files
COPY pyproject.toml uv.lock ./

# Create virtual environment and install dependencies
RUN python -m venv .venv && \
    . .venv/bin/activate && \
    uv pip install uvicorn fastapi && \
    uv sync --frozen --no-install-project

# Copy application code
COPY . .

# Install the project
RUN . .venv/bin/activate && \
    uv sync --frozen

EXPOSE 8000

# Use the virtual environment's Python
CMD ["/app/.venv/bin/python", "-m", "uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8001"]