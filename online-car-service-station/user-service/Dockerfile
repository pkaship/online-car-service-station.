# user-service/Dockerfile
# Use a specific version of Node.js for consistency
FROM node:18-alpine

# Set the working directory in the container
WORKDIR /usr/src/app

# Copy package.json and package-lock.json (or yarn.lock)
# to leverage Docker's layer caching
COPY package*.json ./

# Install production dependencies
RUN npm install --production

# Copy the rest of the application code
COPY . .

# Expose the port on which the Node.js application runs
EXPOSE 3000

# Command to run the application
CMD ["node", "src/index.js"]