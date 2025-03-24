package graph

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"

	"strings"
	"time"

	"property_backend/db"
	"property_backend/graph/model"

	"github.com/golang-jwt/jwt/v5"
	"github.com/jackc/pgx/v5"
	"github.com/joho/godotenv"
	"golang.org/x/crypto/bcrypt"
)

var (
	dbURL     string
	jwtSecret string
)

type contextKey string

const UserKey contextKey = "user"

func init() {
	if err := godotenv.Load("docker/.env"); err != nil {
		log.Printf("⚠️ Warning: Failed to load .env: %v", err)
	}

	dbURL = os.Getenv("DATABASE_URL")
	jwtSecret = os.Getenv("JWT_SECRET")

	if dbURL == "" || jwtSecret == "" {
		log.Fatal("❌ Missing essential environment variables (DATABASE_URL, JWT_SECRET)")
	}
}

func (r *mutationResolver) Register(ctx context.Context, input model.RegisterInput) (*model.User, error) {
	role, err := normalizeRole(input.Role)
	if err != nil {
		log.Printf("❌ Role Validation Failed: %v", err)
		return nil, err
	}
	input.Role = role

	hashedPassword, err := hashPassword(input.Password)
	if err != nil {
		log.Printf("❌ Password Hashing Failed: %v", err)
		return nil, fmt.Errorf("internal server error")
	}

	conn := db.GetConn()
	if conn == nil {
		log.Println("❌ Database connection is nil")
		return nil, fmt.Errorf("internal server error")
	}

	// ✅ Check if email already exists
	var exists bool
	err = conn.QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM users WHERE email = $1)", input.Email).Scan(&exists)
	if err != nil {
		log.Printf("❌ Email existence check failed: %v", err)
		return nil, fmt.Errorf("internal server error")
	}
	if exists {
		return nil, fmt.Errorf("email already registered")
	}

	// ✅ Insert new user
	var user model.User
	err = conn.QueryRow(ctx,
		"INSERT INTO users (email, password, role, profile, location) VALUES ($1, $2, $3, $4, $5) RETURNING id, email, role, profile, location",
		input.Email, hashedPassword, input.Role, input.Profile, input.Location,
	).Scan(&user.ID, &user.Email, &user.Role, &user.Profile, &user.Location)

	if err != nil {
		log.Printf("❌ DB Insertion Error: %v", err)
		return nil, fmt.Errorf("failed to create user")
	}

	log.Printf("✅ User registered successfully: %s", user.Email)
	return &user, nil
}

func normalizeRole(role string) (string, error) {
	role = strings.ToLower(strings.TrimSpace(role))
	role = strings.ReplaceAll(role, "\u200B", "")
	role = strings.ReplaceAll(role, "\ufeff", "")

	validRoles := map[string]bool{"admin": true, "user": true, "vendor": true}
	if !validRoles[role] {
		return "", fmt.Errorf("invalid role: must be 'admin', 'user', or 'vendor'")
	}
	return role, nil
}

func hashPassword(password string) (string, error) {
	hashed, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	return string(hashed), err
}

func (r *mutationResolver) Login(ctx context.Context, email string, password string) (*model.AuthPayload, error) {
	jwtSecret, exists := os.LookupEnv("JWT_SECRET")
	if !exists || jwtSecret == "" {
		log.Println("❌ JWT_SECRET is missing")
		return nil, fmt.Errorf("internal server error")
	}

	conn := db.GetConn()
	if conn == nil {
		log.Println("❌ Database connection is nil")
		return nil, fmt.Errorf("internal server error")
	}

	user, hashedPassword, err := fetchUserByEmail(ctx, conn, email)
	if err != nil {
		log.Printf("❌ Login Failed (User Fetch): %v", err)
		return nil, fmt.Errorf("invalid credentials")
	}

	if err := bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(password)); err != nil {
		log.Println("❌ Password Mismatch")
		return nil, fmt.Errorf("invalid credentials")
	}

	tokenStr, err := generateJWT(user.ID, user.Email, user.Role, jwtSecret)
	if err != nil {
		log.Printf("❌ Token Generation Failed: %v", err)
		return nil, fmt.Errorf("failed to generate token")
	}

	log.Printf("✅ User logged in: %s", user.Email)
	return &model.AuthPayload{
		Token: tokenStr,
		User: &model.User{
			ID:    user.ID,
			Email: user.Email,
			Role:  user.Role,
		},
	}, nil
}

func fetchUserByEmail(ctx context.Context, conn *pgx.Conn, email string) (*model.User, string, error) {
	var user model.User
	var hashedPassword string
	err := conn.QueryRow(ctx, "SELECT id, email, password, role FROM users WHERE email = $1", email).
		Scan(&user.ID, &user.Email, &hashedPassword, &user.Role)
	if err != nil {
		return nil, "", err
	}
	return &user, hashedPassword, nil
}

func generateJWT(userID, email, role, secret string) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"userID": userID,
		"email":  email,
		"role":   role,
		"iat":    time.Now().Unix(),
		"exp":    time.Now().Add(time.Hour * 24).Unix(),
	})
	return token.SignedString([]byte(secret))
}

func (r *mutationResolver) CreateProperty(ctx context.Context, input model.PropertyInput) (*model.Property, error) {
	conn := db.GetConn()
	if conn == nil {
		log.Println("❌ Database connection is nil")
		return nil, fmt.Errorf("internal server error")
	}

	user, err := getUserFromContext(ctx)
	if err != nil {
		log.Printf("❌ Authentication Error: %v", err)
		return nil, fmt.Errorf("unauthorized: invalid user context")
	}

	if user.Role != "vendor" {
		log.Printf("🚫 Access Denied: User %s (%s) attempted to create a property", user.Email, user.Role)
		return nil, fmt.Errorf("forbidden: only vendors can create properties")
	}

	if err := validatePropertyInput(input); err != nil {
		log.Printf("❌ Invalid Property Input: %v", err)
		return nil, err
	}

	var id int
	err = conn.QueryRow(ctx,
		"INSERT INTO properties (address, price, vendor_name, description) VALUES ($1, $2, $3, $4) RETURNING id",
		input.Address, input.Price, input.VendorName, input.Description).Scan(&id)
	if err != nil {
		log.Printf("❌ Database Error: %v", err)
		return nil, fmt.Errorf("failed to create property")
	}

	log.Printf("✅ Property created successfully (ID: %d) by %s", id, user.Email)
	return &model.Property{
		ID:          fmt.Sprint(id),
		Address:     input.Address,
		Price:       input.Price,
		VendorName:  input.VendorName,
		Description: input.Description,
	}, nil
}

func getUserFromContext(ctx context.Context) (*model.User, error) {
	claims, ok := ctx.Value(UserKey).(jwt.MapClaims)
	if !ok {
		return nil, fmt.Errorf("invalid token: no JWT claims found")
	}

	userID, ok := claims["userID"].(string)
	if !ok {
		return nil, fmt.Errorf("invalid token: malformed userID")
	}

	email, ok := claims["email"].(string)
	if !ok {
		return nil, fmt.Errorf("invalid token: malformed email")
	}

	role, ok := claims["role"].(string)
	if !ok {
		return nil, fmt.Errorf("invalid token: malformed role")
	}

	return &model.User{
		ID:    userID,
		Email: email,
		Role:  role,
	}, nil
}

func validatePropertyInput(input model.PropertyInput) error {
	if strings.TrimSpace(input.Address) == "" {
		return fmt.Errorf("address cannot be empty")
	}
	if input.Price <= 0 {
		return fmt.Errorf("price must be greater than zero")
	}
	if strings.TrimSpace(input.VendorName) == "" {
		return fmt.Errorf("vendor name cannot be empty")
	}
	if strings.TrimSpace(input.Description) == "" {
		return fmt.Errorf("description cannot be empty")
	}
	return nil
}

func (r *mutationResolver) UpdateProperty(ctx context.Context, id string, input model.PropertyInput) (*model.Property, error) {
	conn := db.GetConn()
	if conn == nil {
		log.Println("❌ Database connection is nil")
		return nil, fmt.Errorf("internal server error")
	}

	user, err := getUserFromContext(ctx)
	if err != nil {
		log.Printf("❌ Authentication Error: %v", err)
		return nil, fmt.Errorf("unauthorized: invalid user context")
	}

	if user.Role != "vendor" {
		log.Printf("🚫 Access Denied: User %s (%s) attempted to update a property", user.Email, user.Role)
		return nil, fmt.Errorf("forbidden: only vendors can update properties")
	}

	if err := validatePropertyInput(input); err != nil {
		log.Printf("❌ Invalid Property Input: %v", err)
		return nil, err
	}

	var propertyOwner string
	err = conn.QueryRow(ctx, "SELECT vendor_name FROM properties WHERE id = $1", id).Scan(&propertyOwner)
	if err != nil {
		log.Printf("❌ Property Not Found (ID: %s)", id)
		return nil, fmt.Errorf("property not found")
	}

	if propertyOwner != user.Email {
		log.Printf("🚫 Unauthorized Update: Vendor %s tried to update property owned by %s", user.Email, propertyOwner)
		return nil, fmt.Errorf("forbidden: you can only update your own properties")
	}

	_, err = conn.Exec(ctx,
		"UPDATE properties SET address = $1, price = $2, description = $3 WHERE id = $4",
		input.Address, input.Price, input.Description, id)
	if err != nil {
		log.Printf("❌ Database Update Error: %v", err)
		return nil, fmt.Errorf("failed to update property")
	}

	log.Printf("✅ Property updated successfully (ID: %s) by %s", id, user.Email)
	return &model.Property{
		ID:          id,
		Address:     input.Address,
		Price:       input.Price,
		VendorName:  propertyOwner,
		Description: input.Description,
	}, nil
}

func getUserIDFromContext(ctx context.Context) (string, error) {
	claims, ok := ctx.Value(UserKey).(jwt.MapClaims)
	if !ok {
		return "", fmt.Errorf("invalid token: no JWT claims found")
	}

	userID, ok := claims["userID"].(string)
	if !ok {
		return "", fmt.Errorf("invalid token: malformed userID")
	}

	return userID, nil
}

func (r *mutationResolver) DeleteProperty(ctx context.Context, id string) (bool, error) {
	conn := db.GetConn()
	if conn == nil {
		log.Println("❌ Database connection is nil")
		return false, fmt.Errorf("internal server error")
	}

	user, err := getUserFromContext(ctx)
	if err != nil {
		log.Printf("❌ Authentication Error: %v", err)
		return false, fmt.Errorf("unauthorized: invalid user context")
	}

	if user.Role != "vendor" {
		log.Printf("🚫 Access Denied: User %s (%s) attempted to delete a property", user.Email, user.Role)
		return false, fmt.Errorf("forbidden: only vendors can delete properties")
	}

	var propertyOwner string
	err = conn.QueryRow(ctx, "SELECT vendor_name FROM properties WHERE id = $1", id).Scan(&propertyOwner)
	if err != nil {
		log.Printf("❌ Property Not Found (ID: %s)", id)
		return false, fmt.Errorf("property not found")
	}

	if propertyOwner != user.Email {
		log.Printf("🚫 Unauthorized Deletion: Vendor %s tried to delete property owned by %s", user.Email, propertyOwner)
		return false, fmt.Errorf("forbidden: you can only delete your own properties")
	}

	result, err := conn.Exec(ctx, "DELETE FROM properties WHERE id = $1", id)
	if err != nil {
		log.Printf("❌ Database Deletion Error: %v", err)
		return false, fmt.Errorf("failed to delete property")
	}

	if result.RowsAffected() == 0 {
		log.Printf("❌ Property Not Found: ID %s", id)
		return false, fmt.Errorf("property not found")
	}

	log.Printf("✅ Property deleted successfully (ID: %s) by %s", id, user.Email)
	return true, nil
}

func (r *queryResolver) ListProperties(ctx context.Context) ([]*model.Property, error) {
	conn := db.GetConn()
	if conn == nil {
		log.Println("❌ Database connection is nil")
		return nil, fmt.Errorf("internal server error: database connection failed")
	}

	rows, err := conn.Query(ctx, "SELECT id, address, price, vendor_name, description FROM properties")
	if err != nil {
		log.Printf("❌ Query Error: %v", err)
		return nil, fmt.Errorf("failed to list properties")
	}
	defer rows.Close()

	properties := make([]*model.Property, 0, 10)
	for rows.Next() {
		p := new(model.Property)
		if err := rows.Scan(&p.ID, &p.Address, &p.Price, &p.VendorName, &p.Description); err != nil {
			log.Printf("❌ Row Scan Error: %v", err)
			return nil, fmt.Errorf("failed to scan property")
		}
		properties = append(properties, p)
	}

	if err := rows.Err(); err != nil {
		log.Printf("❌ Row Iteration Error: %v", err)
		return nil, fmt.Errorf("error processing properties")
	}

	log.Printf("✅ Retrieved %d properties", len(properties))
	return properties, nil
}

func (r *queryResolver) GetLeadScore(ctx context.Context, input model.LeadInput) (*model.LeadScore, error) {
	mlServiceURL, ok := os.LookupEnv("ML_SERVICE_URL")
	if !ok || mlServiceURL == "" {
		log.Println("❌ ML_SERVICE_URL is not set")
		return nil, fmt.Errorf("internal server error: ML_SERVICE_URL not set")
	}

	payloadBytes, err := json.Marshal(map[string]interface{}{
		"property_price": input.PropertyPrice,
		"location":       input.Location,
		"user_email":     input.UserEmail,
	})
	if err != nil {
		log.Printf("❌ JSON Marshaling Error: %v", err)
		return nil, fmt.Errorf("failed to prepare ML request")
	}

	client := &http.Client{Timeout: 5 * time.Second}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, mlServiceURL, bytes.NewBuffer(payloadBytes))
	if err != nil {
		log.Printf("❌ Failed to create request: %v", err)
		return nil, fmt.Errorf("failed to create ML service request")
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		log.Printf("❌ ML service request failed: %v", err)
		return nil, fmt.Errorf("ML service request failed")
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		log.Printf("❌ ML service error (Status %d): %s", resp.StatusCode, string(bodyBytes))
		return nil, fmt.Errorf("ML service error: %s", resp.Status)
	}

	var result model.LeadScore
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		log.Printf("❌ Failed to decode ML response: %v", err)
		return nil, fmt.Errorf("failed to parse ML service response")
	}

	log.Printf("✅ Lead Score Retrieved: %f", result.Score)
	return &result, nil
}

func (r *mutationResolver) GetLeadScore(ctx context.Context, input model.LeadInput) (*model.LeadScore, error) {
	return r.Query().GetLeadScore(ctx, input)
}

func (r *queryResolver) SearchSimilarProperties(ctx context.Context, description string) (*model.SearchResponse, error) {
	n8nWebhookURL := os.Getenv("N8N_WEBHOOK_URL")
	if n8nWebhookURL == "" {
		log.Println("❌ N8N_WEBHOOK_URL is not set")
		return nil, fmt.Errorf("internal server error: N8N_WEBHOOK_URL not set")
	}
	log.Printf("ℹ️ Sending request to N8N Webhook: %s", n8nWebhookURL)

	// ✅ Fetch authenticated user ID
	userID, err := getUserIDFromContext(ctx)
	if err != nil {
		return nil, fmt.Errorf("unauthorized: %v", err)
	}

	// ✅ Get database connection
	conn := db.GetConn()
	if conn == nil {
		log.Println("❌ Database connection is nil")
		return nil, fmt.Errorf("internal server error")
	}

	// ✅ Ensure DB Connection is Active
	if err := conn.Ping(ctx); err != nil {
		log.Println("❌ Database connection lost")
		return nil, fmt.Errorf("internal server error: database connection lost")
	}

	// ✅ Fetch User Profile Data from PostgreSQL
	var userPreferences model.UserPreferences
	err = conn.QueryRow(ctx, `
		SELECT profile, location FROM users WHERE id = $1`, userID).
		Scan(&userPreferences.Profile, &userPreferences.Location)
	if err != nil {
		log.Printf("❌ Error fetching user data: %v", err)
		return nil, fmt.Errorf("error fetching user data")
	}
	if userPreferences.Profile == "" || userPreferences.Location == "" {
		log.Println("⚠️ No user preferences found for user:", userID)
		return nil, fmt.Errorf("user profile not found")
	}

	// ✅ Fetch Property Data from PostgreSQL
	properties, err := db.FetchAllProperties(conn)
	if err != nil {
		log.Printf("❌ Error fetching properties: %v", err)
		return nil, fmt.Errorf("error fetching properties")
	}

	// ✅ Prepare Payload for n8n
	payload := map[string]interface{}{
		"description": description,
		"user_data":   userPreferences,
		"properties":  properties,
	}

	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		log.Printf("❌ JSON Marshaling Error: %v", err)
		return nil, fmt.Errorf("failed to prepare N8N request")
	}

	// ✅ Send Request to n8n Webhook with Retry
	client := &http.Client{Timeout: 10 * time.Second}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, n8nWebhookURL, bytes.NewBuffer(payloadBytes))
	if err != nil {
		log.Printf("❌ Failed to create N8N request: %v", err)
		return nil, fmt.Errorf("failed to create N8N request")
	}
	req.Header.Set("Content-Type", "application/json")

	maxRetries := 3
	var resp *http.Response
	for i := 0; i < maxRetries; i++ {
		resp, err = client.Do(req)
		if err == nil && resp.StatusCode == http.StatusOK {
			break // Success, exit loop
		}
		log.Printf("⚠️ Retry %d/%d: N8N request failed, status: %d", i+1, maxRetries, resp.StatusCode)
		time.Sleep(2 * time.Second) // Wait before retrying
	}
	if err != nil {
		log.Printf("❌ N8N request failed: %v", err)
		return nil, fmt.Errorf("N8N service request failed")
	}
	defer resp.Body.Close()

	// ✅ Validate JSON response
	var searchResponse model.SearchResponse
	if err := json.NewDecoder(resp.Body).Decode(&searchResponse); err != nil {
		log.Printf("❌ Failed to decode N8N response: %v", err)
		return nil, fmt.Errorf("failed to parse N8N response")
	}

	// ✅ Check if recommendations are empty
	if len(searchResponse.Recommendations) == 0 {
		log.Println("⚠️ No recommendations found in Pinecone search.")
		return nil, fmt.Errorf("no matching properties found")
	}

	// ✅ Log & Return Results
	log.Printf("✅ Retrieved %d recommendations for query: %s", len(searchResponse.Recommendations), description)
	return &searchResponse, nil

	// ✅ Log & Return Results

}

func (r *mutationResolver) VerifyVendor(ctx context.Context, input model.VendorInput) (*model.VerificationResult, error) {
	userClaims, ok := ctx.Value(UserKey).(jwt.MapClaims)
	if !ok {
		log.Println("❌ Unauthorized: Invalid user context")
		return nil, fmt.Errorf("unauthorized: invalid token")
	}

	const adminRole = "admin"
	role, roleOk := userClaims["role"].(string)
	if !roleOk || role != adminRole {
		log.Printf("❌ Forbidden: User role '%s' is not allowed to verify vendors", role)
		return nil, fmt.Errorf("forbidden: only admins can verify vendors")
	}

	log.Printf("🔍 Verifying vendor - Name: %s, ID: %s", input.Name, input.ID)
	status, err := verifyVendorWithExternalService(input)
	if err != nil {
		log.Printf("❌ Vendor verification failed: %v", err)
		return nil, fmt.Errorf("vendor verification failed: %v", err)
	}

	return &model.VerificationResult{Status: status}, nil
}

func verifyVendorWithExternalService(input model.VendorInput) (string, error) {
	log.Printf("✅ Simulated verification for Vendor Name: %s, ID: %s", input.Name, input.ID)
	return "verified", nil
}

type Resolver struct{}

type mutationResolver struct{ *Resolver }
type queryResolver struct{ *Resolver }

func (r *Resolver) Mutation() MutationResolver {
	return &mutationResolver{r}
}

func (r *Resolver) Query() QueryResolver {
	return &queryResolver{r}
}

func (r *queryResolver) GetProperty(ctx context.Context, id string) (*model.Property, error) {
	conn := db.GetConn()
	if conn == nil {
		log.Println("❌ Database connection is nil")
		return nil, fmt.Errorf("internal server error: database connection failed")
	}

	log.Printf("🔍 Fetching property with ID: %s", id)
	var p model.Property
	err := conn.QueryRow(ctx, `
		SELECT id, address, price, vendor_name, description 
		FROM properties 
		WHERE id = $1
	`, id).Scan(&p.ID, &p.Address, &p.Price, &p.VendorName, &p.Description)

	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			log.Printf("⚠️ Property not found (ID: %s)", id)
			return nil, fmt.Errorf("property not found: %s", id)
		}
		log.Printf("❌ Database error while fetching property ID %s: %v", id, err)
		return nil, fmt.Errorf("failed to fetch property: %v", err)
	}

	log.Printf("✅ Property retrieved successfully (ID: %s)", p.ID)
	return &p, nil
}

func (r *queryResolver) GetProfile(ctx context.Context) (*model.User, error) {
	user, err := getUserFromContext(ctx)
	if err != nil {
		log.Printf("❌ Failed to get user profile: %v", err)
		return nil, fmt.Errorf("unauthorized: %v", err)
	}

	conn := db.GetConn()
	if conn == nil {
		log.Println("❌ Database connection is nil")
		return nil, fmt.Errorf("internal server error: database connection failed")
	}

	var fullUser model.User
	err = conn.QueryRow(ctx, `
		SELECT id, email, role 
		FROM users 
		WHERE id = $1
	`, user.ID).Scan(&fullUser.ID, &fullUser.Email, &fullUser.Role)

	if err != nil {
		log.Printf("❌ Failed to fetch user profile from DB: %v", err)
		return nil, fmt.Errorf("failed to fetch profile: %v", err)
	}

	log.Printf("✅ User profile retrieved for %s", fullUser.Email)
	return &fullUser, nil
}
