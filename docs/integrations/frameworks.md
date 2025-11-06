# Framework integration

`auth.Handler()` returns a standard `http.Handler`. Mount it in any Go web
framework that supports the net/http interface.

## net/http

```go
mux := http.NewServeMux()
mux.Handle("/api/auth/", http.StripPrefix("/api/auth", a.Handler()))
http.ListenAndServe(":8080", mux)
```

`StripPrefix` is required when mounting at a sub-path so internal routes match
(`/sign-in/email`, not `/api/auth/sign-in/email`).

## chi

```go
r := chi.NewRouter()
r.Mount("/api/auth", a.Handler())
```

Chi strips the mount prefix automatically — no `StripPrefix` needed.

## Gin

```go
r := gin.Default()
r.Any("/api/auth/*path", func(c *gin.Context) {
    a.Handler().ServeHTTP(c.Writer, c.Request)
})
```

## Echo

```go
e := echo.New()
e.Any("/api/auth/*", echo.WrapHandler(a.Handler()))
```

## Fiber

```go
app := fiber.New()
app.All("/api/auth/*", adaptor.HTTPHandler(a.Handler()))
```

Import `github.com/gofiber/fiber/v2/middleware/adaptor`.

## Base path

If your mount path differs from the default `/api/auth`, set `BasePath` to match:

```go
auth.Config{
    BasePath: "/auth",
}
// mount at /auth/
```

Next: [Clients →](clients.md)
