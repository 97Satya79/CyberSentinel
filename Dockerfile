# 1. Official lightweight Python base image
FROM python:3.11-slim

# 2. Prevent Python from buffering logs so print statements show up immediately
ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1

# 3. Install Nmap (required by Stage 1 discovery)
RUN apt-get update && apt-get install -y --no-install-recommends \
    nmap \
    && rm -rf /var/lib/apt/lists/*

# 4. Set working directory inside the container
WORKDIR /app

# 5. Copy and install Python dependencies with increased network timeout
COPY requirements.txt .
RUN pip install --no-cache-dir --default-timeout=1000 -r requirements.txt

# 6. Copy the project source code
COPY . /app

# 7. Expose the dashboard port
EXPOSE 5000

# 8. Run the FastAPI app using Uvicorn
CMD ["uvicorn", "web_dashboard:app", "--host", "0.0.0.0", "--port", "5000"]
