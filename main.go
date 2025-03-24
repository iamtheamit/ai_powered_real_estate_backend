package main

import (
	"property_backend/db"
	"property_backend/graph"
)

func main() {
	// Initialize the database
	db.InitDB()

	// Start the GraphQL server on port 8080
	graph.StartServer("8080")
}
