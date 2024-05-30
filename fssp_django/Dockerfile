# Use Python base image
FROM python:3.11

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE 1
ENV PYTHONUNBUFFERED 1

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
CMD ["sh", "-c", "python3 manage.py migrate && python3 manage.py runserver 0.0.0.0:8000"]
# CMD ["runserver_plus", "0.0.0.0:8000", "--cert", "./ssl/server.crt", "--key", "./ssl/server.key"] 
# CMD ["/bin/sh" "-c" "[\"/bin/python\", \"manage.py\", \"runserver_plus\", \"0.0.0.0:8000\", \"--cert\", \".\\ssl\\server.crt\", \"--key\", \".\\ssl\\server.key\"]"]
# ENTRYPOINT ["/bin/usr/python manage.py runserver_plus 0.0.0.0:8000 --cert ./ssl/server.crt --key ./ssl/server.key"]
