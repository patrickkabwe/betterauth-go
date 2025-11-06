package main

import (
	"context"
	databasesql "database/sql"
	"log"
	"net/http"
	"os"

	"github.com/patrickkabwe/betterauth-go/auth"
	sqlstore "github.com/patrickkabwe/betterauth-go/store/sql"

	_ "modernc.org/sqlite"
)

// NewAuth builds the application's Better Auth instance.
func NewAuth() (*auth.Auth, error) {
	db, err := databasesql.Open("sqlite", "file:"+envOr("DATABASE_PATH", "better-auth.db"))
	if err != nil {
		log.Fatal(err)
	}
	st := sqlstore.New(db, sqlstore.SQLite)
	if err := st.Migrate(context.Background()); err != nil {
		log.Fatal(err)
	}
	store := st
	return auth.New(auth.Config{
		AppName:        "Test",
		Secret:         os.Getenv("BETTER_AUTH_SECRET"),
		BaseURL:        envOr("BETTER_AUTH_URL", "http://localhost:8080"),
		TrustedOrigins: []string{"http://localhost:3000"},
		Store:          store,
	})
}

func main() {
	a, err := NewAuth()
	if err != nil {
		log.Fatal(err)
	}
	mux := http.NewServeMux()
	mux.Handle("/api/auth/", http.StripPrefix("/api/auth", a.Handler()))
	log.Println("listening on :8080")
	log.Fatal(http.ListenAndServe(":8080", mux))
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
