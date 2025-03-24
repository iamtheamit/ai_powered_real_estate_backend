package db

import (
	"context"
	"fmt"
	"log"
	"os"
	"property_backend/graph/model"

	"github.com/jackc/pgx/v5"
	"github.com/joho/godotenv"
)

var conn *pgx.Conn

func InitDB() {
	_ = godotenv.Load() // Load environment variables

	dbURL := os.Getenv("DATABASE_URL")
	if dbURL == "" {
		log.Fatal("❌ DATABASE_URL is not set in the environment variables")
	}

	var err error
	conn, err = pgx.Connect(context.Background(), dbURL)
	if err != nil {
		log.Fatal("❌ Unable to connect to database:", err)
	}

	// ✅ Ping Database to check connection
	err = conn.Ping(context.Background())
	if err != nil {
		log.Fatal("❌ Database ping failed:", err)
	}

	fmt.Println("✅ Successfully connected to the database!")

	// ✅ Log database connection details
	var dbName string
	err = conn.QueryRow(context.Background(), "SELECT current_database();").Scan(&dbName)
	if err != nil {
		log.Fatal("❌ Failed to get database name:", err)
	}
	fmt.Println("🗄️ Connected to database:", dbName)

	// ✅ Create users table with profile and location fields
	_, err = conn.Exec(context.Background(), `
        CREATE TABLE IF NOT EXISTS users (
            id SERIAL PRIMARY KEY,
            email TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            role TEXT DEFAULT 'user' CHECK (role IN ('user','vendor','admin')),
            profile TEXT DEFAULT NULL,  -- ✅ New: Stores user preferences
            location TEXT DEFAULT NULL, -- ✅ New: Stores user location
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
    `)
	if err != nil {
		log.Fatal("❌ Unable to create users table:", err)
	}
	fmt.Println("✅ Users table is ready!")

	// ✅ Create properties table
	_, err = conn.Exec(context.Background(), `
        CREATE TABLE IF NOT EXISTS properties (
            id SERIAL PRIMARY KEY,
            address TEXT NOT NULL,
            price FLOAT NOT NULL,
            vendor_name TEXT NOT NULL,
            description TEXT NOT NULL
        );
    `)
	if err != nil {
		log.Fatal("❌ Unable to create properties table:", err)
	}
	fmt.Println("✅ Properties table is ready!")
}

// GetConn returns the active database connection
func GetConn() *pgx.Conn {
	return conn
}

func FetchAllProperties(conn *pgx.Conn) ([]model.Property, error) {
	rows, err := conn.Query(context.Background(), "SELECT id, address, price, vendor_name, description FROM properties")
	if err != nil {
		log.Printf("❌ Error querying properties: %v", err)
		return nil, err
	}
	defer rows.Close()

	var properties []model.Property
	for rows.Next() {
		var p model.Property
		err := rows.Scan(&p.ID, &p.Address, &p.Price, &p.VendorName, &p.Description)
		if err != nil {
			log.Printf("❌ Error scanning property row: %v", err)
			return nil, err
		}
		properties = append(properties, p)
	}

	return properties, nil
}
