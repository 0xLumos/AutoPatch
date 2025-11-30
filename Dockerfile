# Use a lightweight base image
FROM ubuntu:jammy-20250415.1

# Set a working directory inside the container
WORKDIR /app

# Copy all files from the current directory to /app
COPY . .

# RUN apt-get update && apt-get install -y python3 python3-pip

# (Optional) Install dependencies if you have a requirements.txt
# RUN pip install -r requirements.txt


