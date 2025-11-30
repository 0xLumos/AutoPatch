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

WORKDIR /app/sample_images/vulnerable-app

COPY sample_images/vulnerable-app /app/sample_images/vulnerable-app

CMD ["python3", "-m", "http.server", "8000"]

