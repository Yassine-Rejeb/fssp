# Use Python base image
# FROM python:3.11
FROM arm64v8/python:3.11-slim

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

# Set working directory
WORKDIR /app

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy project files to working directory
COPY . .

# Collect static files
# RUN python manage.py collectstatic --noinput

# Run migrations
RUN python3 manage.py makemigrations

# Expose port
EXPOSE 8000

# Command to run the Django server
# CMD ["sh", "-c", "python3 manage.py migrate && python3 manage.py runserver_plus 0.0.0.0:8000 --cert ./ssl/server.crt --key ./ssl/server.key"]
CMD ["sh", "-c", "python3 manage.py migrate && gunicorn --bind 0.0.0.0:8000 --workers 3 fssp_django.wsgi:application"]
