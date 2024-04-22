# Use python:3.11 as the base image, set environment variables, set the working directory, install dependencies, copy project files to the working directory, expose port 8000, and run the Django server. The command to run the Django server is python manage.py runserver_plus
FROM python:3.11

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE 1
ENV PYTHONUNBUFFERED 1
ENV FLASK_ENV development
ENV FLASK_APP gun.py

# Create the directory for the app
RUN mkdir /app

# Set working directory
WORKDIR /app

# Install dependencies
COPY ./flask_app/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy project files to working directory
COPY ./flask_app/* .

# Expose port
EXPOSE 1999

# Command to run the Flask server
ENTRYPOINT ["python", "gun.py"]