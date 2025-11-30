# # Use a lightweight base image
# FROM  alpine:3.2

# # Set a working directory inside the container
# WORKDIR /app

# # Copy all files from the current directory to /app
# COPY . .

# # (Optional) Install dependencies if you have a requirements.txt
# # RUN pip install -r requirements.txt

# # Run a simple Python script

# CMD ["python", "app.py"]

FROM python:3.11-slim

# Install OS deps if needed
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        curl \
        bash \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY sample_images/vulnerable-app /app

RUN if [ -f requirements.txt ]; then pip install --no-cache-dir -r requirements.txt; fi

EXPOSE 8000

CMD ["python3", "app.py"]


COPY sample_images/vulnerable-app /app/sample_images/vulnerable-app



