# Use Python base image
FROM python:3.11

# Set environment variables
# ENV PYTHONDONTWRITEBYTECODE 1
# ENV PYTHONUNBUFFERED 1

# Set working directory
WORKDIR /app

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy project files to working directory
COPY . .

# Collect static files
RUN python manage.py collectstatic --noinput

# Run migrations
# RUN python manage.py makemigrations
# RUN python manage.py migrate

# Expose port
EXPOSE 8000

# Command to run the Django server
CMD ["python", "manage.py", "runserver", "0.0.0.0:8000"]
