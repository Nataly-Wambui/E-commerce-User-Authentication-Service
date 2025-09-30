# Use official lightweight Python image
FROM python:3.11-slim

# Set work directory
WORKDIR /app

# Prevent Python from writing pyc files & buffering stdout
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

# Install system dependencies (needed for psycopg2 & others)
RUN apt-get update && apt-get install -y \
    build-essential \
    libpq-dev \
    && rm -rf /var/lib/apt/lists/*

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy project files
COPY src/ ./src/

# Expose Django port
EXPOSE 8000

# Default command (overridable in docker-compose)
CMD ["python", "src/manage.py", "runserver", "0.0.0.0:8000"]


