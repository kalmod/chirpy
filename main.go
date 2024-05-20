package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
)

// apiConfig
type chirpyHandler struct {
	messageOk        string
	fileserverHits int
}

func (ch *chirpyHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8") // normal header
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(ch.messageOk))
}

func (ch *chirpyHandler) ServeMetrics(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8") // normal header
	w.WriteHeader(http.StatusOK)
  metricsPage := fmt.Sprintf(`
  <html>
  <body>
  <h1>Welcome, Chirpy Admin</h1>
  <p>Chirpy has been visited %d times!</p>
  </body>
  </html>`, ch.fileserverHits)

	w.Write([]byte(metricsPage))
}

func (ch *chirpyHandler) ResetMetrics(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8") // normal header
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(""))
  ch.fileserverHits = 0
}

func respondWithError(w http.ResponseWriter, code int, msg string){
  if code > 499 {
    log.Printf("Responding with 5XX error: %s", msg)
  }

  type errorJson struct {
    Error string `json:"error"`
  }

  respondWithJson(w, code, errorJson{Error:msg})
}

func respondWithJson(w http.ResponseWriter,code int, payload interface{}){ 
  w.Header().Set("Content-Type", "application/json")
  dat, err := json.Marshal(payload)
  if err != nil {
    log.Printf("Error marshalling JSON: %s", err)
    w.WriteHeader(500)
    return 
  }
  w.WriteHeader(code) 
  w.Write(dat)
}

func (ch *chirpyHandler) ValidateChirp(w http.ResponseWriter, r *http.Request){
  // We'll want to use Decoder here since we're reading from a stream
  // We use decorde to unmarshall it, into our struct
  type chirp struct {
    Body string `json:"body"`
  }


  type validJson struct {
    Valid bool `json:"valid"`
  }

  dec := json.NewDecoder(r.Body)
  newChirp := chirp{}
  err := dec.Decode(&newChirp)
  if err != nil {
    respondWithError(w, http.StatusInternalServerError, "Something went wrong")
    return
  }

  if len(newChirp.Body) > 140 {
    respondWithError(w, http.StatusBadRequest, "Chirp is too long")
    return
  }

  respondWithJson(w, http.StatusOK, validJson{true})
}

func (ch *chirpyHandler) middlewareMetricsInc(next http.Handler) http.Handler {
  return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request){
    ch.fileserverHits++
    // Then proceed to next hanlder
    next.ServeHTTP(w, r)
  })
}

func main() {
	mux := http.NewServeMux()
	ch := chirpyHandler{"OK",0}
	mux.Handle("/app/*",
		http.StripPrefix("/app/", ch.middlewareMetricsInc(http.FileServer(http.Dir(".")))),
	)
	mux.HandleFunc("GET /api/healthz", ch.ServeHTTP)
	mux.HandleFunc("GET /admin/metrics", ch.ServeMetrics)
	mux.HandleFunc("/api/reset", ch.ResetMetrics)
	mux.HandleFunc("POST /api/validate_chirp", ch.ValidateChirp)

	port := "8080"

	server := &http.Server{
		Addr:    ":" + port,
		Handler: mux,
	}

	// ListenAndServe starts the server
	// log fatal so that if it crashes, we quit the program
	log.Fatal(
		server.ListenAndServe(),
	)
}
