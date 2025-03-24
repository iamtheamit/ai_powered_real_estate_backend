
```markdown
# Property Backend

A GraphQL API for managing property listings and related features, including user registration, property management, and lead scoring using a TensorFlow-based ML model.

## Overview

This project provides a GraphQL API built with Go, using a PostgreSQL database for persistence and a Python-based microservice for ML-based lead scoring. The API supports features like registering users, logging in, creating/updating/deleting properties (for vendors), and computing lead scores for properties based on user inputs.

## Features
- **User Management**: Register and login users with roles (`admin`, `user`, `vendor`).
- **Property Management**: Create, update, delete, and list properties (vendors only).
- **Lead Scoring**: Compute a lead score for properties using a TensorFlow neural network (served via a Python microservice).
- **GraphQL API**: Provides a flexible API accessible via a GraphQL Playground.

## Tech Stack
- **Backend**: Go (GraphQL API using `gqlgen`)
- **Database**: PostgreSQL
- **ML**: TensorFlow (Python microservice for lead scoring)
- **Containerization**: Docker and Docker Compose
- **Dependencies**: Managed via `go.mod` (Go) and `requirements.txt` (Python)

## Project Structure
```
property_backend/
├── docker/                   # Docker-related files
│   ├── Dockerfile            # Dockerfile for the Go app
│   └── docker-compose.yml    # Docker Compose file for app, db, and ml_service
├── ml_service/               # Python microservice for ML-based lead scoring
│   ├── Dockerfile            # Dockerfile for the ML microservice
│   ├── requirements.txt      # Python dependencies
│   ├── train_model_tf.py     # Script to train the TensorFlow model
│   └── app.py                # Flask app to serve the ML model
├── graph/                    # GraphQL schema and resolvers
│   ├── resolver.go           # GraphQL resolver implementations
│   ├── schema.graphqls       # GraphQL schema definition
│   └── model/                # Generated GraphQL models
├── main.go                   # Entry point for the Go app
├── go.mod                    # Go module dependencies
└── go.sum                    # Go module checksums
```

## Running Locally with Docker

### Prerequisites
- Docker and Docker Compose installed ([Docker installation guide](https://docs.docker.com/get-docker/), [Docker Compose installation guide](https://docs.docker.com/compose/install/)).
- Ensure ports `8080` (GraphQL API), `5433` (PostgreSQL), and `5000` (ML microservice) are free on your host machine, or adjust the port mappings in `docker-compose.yml` to avoid conflicts.

### Steps

1. **Navigate to Docker Directory:**
   ```bash
   cd docker
   ```

2. **Ensure All Required Files Are Present:**
   - Verify that `docker-compose.yml` and `Dockerfile` exist in the `docker/` directory.
   - Ensure that `ml_service/` exists in the project root with its own `Dockerfile`, `train_model_tf.py`, `app.py`, and `requirements.txt` (for the ML microservice).
   - Confirm that your Go project files (e.g., `main.go`, `go.mod`, `graph/`) are in the project root.
   - If the ML model files (`lead_score_model_tf`, `scaler_tf.joblib`, `location_encoder_tf.joblib`) are not present in `ml_service/`, generate them by running the training script locally:
     ```bash
     cd ../ml_service
     pip install -r requirements.txt
     python train_model_tf.py
     ```

3. **Build and Start the Services:**
   Build the Docker images and start the containers using Docker Compose:
   ```bash
   docker compose -f docker-compose.yml up --build
   ```
   - The `--build` flag ensures that the images are rebuilt if there are changes to the code or `Dockerfile`.
   - This command starts three services:
     - `app`: The Go-based GraphQL API, accessible at `http://localhost:8080`.
     - `db`: The PostgreSQL database, accessible at `localhost:5433`.
     - `ml_service`: The Python-based TensorFlow microservice for lead scoring, accessible at `localhost:5000`.

   **Optional**: Run in detached mode (in the background):
   ```bash
   docker compose -f docker-compose.yml up --build -d
   ```

4. **Verify Services Are Running:**
   Check the logs to ensure all services start successfully:
   ```bash
   docker compose logs
   ```
   Look for logs like:
   ```
   app-1         | ✅ Successfully connected to the database!
   app-1         | 🗄️ Connected to database: property_db
   app-1         | ✅ Users table is ready!
   app-1         | ✅ Properties table is ready!
   app-1         | 2025/03/04 09:00:01 🚀 Starting GraphQL Server...
   app-1         | 2025/03/04 09:00:01 🔗 Connect to http://localhost:8080/ for GraphQL playground
   db-1          | 2025-03-04 09:00:00.000 UTC [1] LOG:  database system is ready to accept connections
   ml_service-1  | * Serving Flask app 'app'
   ml_service-1  | * Running on http://0.0.0.0:5000
   ```

5. **Access the GraphQL API:**
   Open your browser and navigate to `http://localhost:8080` to access the GraphQL Playground. You can use this interface to interact with the API endpoints (e.g., `register`, `login`, `getLeadScore`).

6. **Test the API:**
   - **Register a User**:
     ```graphql
     mutation {
         register(input: {
             email: "testuser@example.com"
             password: "password123"
             role: "user"
         }) {
             id
             email
             role
         }
     }
     ```
   - **Login**:
     ```graphql
     mutation {
         login(email: "testuser@example.com", password: "password123") {
             token
             user {
                 id
                 email
                 role
             }
         }
     }
     ```
   - **Get Lead Score** (using the TensorFlow ML model):
     ```graphql
     query {
         getLeadScore(input: {
             userEmail: "priority_user@example.com"
             propertyPrice: 5000000
             location: "city center"
         }) {
             score
         }
     }
     ```
     Expected output:
     ```json
     {
         "data": {
             "getLeadScore": {
                 "score": 0.8154321
             }
         }
     }
     ```

7. **Stop the Services:**
   When you're done, stop the containers:
   ```bash
   docker compose -f docker-compose.yml down
   ```
   To also remove the database volume (resetting the database):
   ```bash
   docker compose -f docker-compose.yml down -v
   ```

## Notes

- **Environment Variables**: The `docker-compose.yml` file sets the required environment variables (`DATABASE_URL`, `JWT_SECRET`, `ML_SERVICE_URL`). If you need to add more variables (e.g., for additional API keys), update the `environment` section of the `app` service in `docker-compose.yml`.
- **Database Persistence**: The PostgreSQL data is stored in a Docker volume (`db-data`). To start fresh, use `docker compose down -v` to remove the volume.
- **ML Model**: The `ml_service` uses a TensorFlow model for lead scoring. Ensure that the model files (`lead_score_model_tf`, `scaler_tf.joblib`, `location_encoder_tf.joblib`) are present in `ml_service/` before building. These are generated by running `train_model_tf.py` locally or in the container.
- **Troubleshooting**:
  - If the database fails to start, check for port conflicts (e.g., port `5433`). You can change the mapping in `docker-compose.yml` (e.g., `"5434:5432"`).
  - If the `app` service fails to connect to the database, ensure the healthcheck (`pg_isready`) is working and that `depends_on` is correctly configured.
  - If the `ml_service` fails to start, verify that TensorFlow and dependencies are installed (`pip install -r requirements.txt`) and that the model files are present.
- **Performance**: To improve build performance, you can enable `COMPOSE_BAKE` as suggested by Docker Compose:
  ```bash
  COMPOSE_BAKE=true docker compose up --build
  ```

## Testing and Debugging

After starting the services, you can interact with the GraphQL API as described above. Here are some additional tips:

- **View Logs**: Use `docker compose logs` to debug issues with any service (`app`, `db`, `ml_service`).
- **Access the Database**: Connect to the PostgreSQL database using a client like `psql`:
  ```bash
  psql -h localhost -p 5433 -U postgres -d property_db
  ```
  Use the password specified in your environment (not included here for security).
- **Test the ML Microservice Directly**: You can test the `ml_service` endpoint independently:
  ```bash
  curl -X POST http://localhost:5000/predict \
  -H "Content-Type: application/json" \
  -d '{"property_price": 5000000, "location": "city center", "user_email": "priority_user@example.com"}'
  ```

## Next Steps

- **Customize the ML Model**: The TensorFlow model in `ml_service/train_model_tf.py` uses synthetic data. Replace it with real lead data for better accuracy.
- **Add Authentication**: Secure the ML microservice endpoint with authentication (e.g., API key) if exposed publicly.
- **Deploy to Production**: Once tested locally, you can deploy this setup to a cloud provider (e.g., AWS ECS, Google Cloud Run) by pushing the Docker images to a registry and adjusting configurations for production.
- **Monitoring**: Add monitoring (e.g., Prometheus, Grafana) to track API usage and ML inference performance.
```



