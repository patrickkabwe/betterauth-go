# Expo client example

Uses `better-auth/client` with **bearer token** auth (not cookies) for React Native.

1. Start the Go server with the bearer plugin: `go run ./examples/basic`
2. Set `EXPO_PUBLIC_AUTH_URL=http://localhost:8080` (or your machine IP for a device)
3. `npm install && npx expo start`

The client persists `set-auth-token` from auth responses in SecureStore (native) or sessionStorage (web).
