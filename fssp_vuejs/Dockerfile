# Use Node.js image as base
FROM node:latest as build-stage

# Create a directory for the application
RUN mkdir /app -p

# Set working directory
WORKDIR /app

# Copy package.json and package-lock.json
COPY package*.json ./

# Install dependencies
RUN npm install

# Copy the rest of the application code
COPY . .

# Build the Vue.js application
RUN npm run build

# Stage 2 - Production environment
FROM nginx:stable-alpine as production-stage

# Copy built Vue.js files to nginx directory
COPY --from=build-stage /app/dist /usr/share/nginx/html

# Copy nginx configuration file
COPY /default.conf /etc/nginx/conf.d/default.conf

# Expose port 80
EXPOSE 80

# Command to run nginx
CMD ["nginx", "-g", "daemon off;"]
