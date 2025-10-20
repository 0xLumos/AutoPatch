# Use a lightweight base image
FROM  alpine:3.2

# Set a working directory inside the container
WORKDIR /app

# Copy all files from the current directory to /app
COPY . .

# (Optional) Install dependencies if you have a requirements.txt
# RUN pip install -r requirements.txt

# Run a simple Python script
CMD ["python", "app.py"]