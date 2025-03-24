# Use the official Go image as the base image for building
FROM golang:1.24-alpine AS builder

# Set the working directory for the Go build
WORKDIR /app

# Copy the Go module files
COPY go.mod go.sum ./
# Download the Go dependencies
RUN go mod download

# Copy the rest of the application code into the container
COPY . .

# Tidy up Go modules (optional, but recommended for cleaning up any issues)
RUN go mod tidy

# Build the Go application
RUN go build -o property-backend ./main.go

# Use Alpine as the base image for the final production image
FROM alpine:latest

# Copy the .env file from the docker folder into the container root
COPY docker/.env .env


# Install necessary packages for connecting to PostgreSQL
RUN apk --no-cache add ca-certificates postgresql-client

# Set the working directory for the final image
WORKDIR /root/

# Copy the compiled Go binary from the builder image
COPY --from=builder /app/property-backend .


# Expose the port your application listens to
EXPOSE 8080

# Define the entry point for the container
# Define the entry point for the container
ENTRYPOINT ["./property-backend"]
