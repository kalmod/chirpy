package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strconv"
	"time"

	// "io"
	"log"
	"net/http"
	"strings"

	"github.com/golang-jwt/jwt/v5"
	"github.com/joho/godotenv"
	internal "github.com/kalmod/chirpy/internal"
)

// apiConfig
type chirpyHandler struct {
	messageOk      string
	fileserverHits int
	chirpDatabase  *internal.DB
	JWTSECRET      string
	POLKAKEY       string
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

func (ch *chirpyHandler) getChirps(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)

  query_author_id := r.URL.Query().Get("author_id")
  sort_value := r.URL.Query().Get("sort")
  if sort_value == "" { 
    sort_value = "asc"
  }


  var author_ID int
  var err error
  if len(query_author_id) != 0 {
    author_ID, err = strconv.Atoi(query_author_id)
    if err != nil {
      log.Printf("Couldn't parse author id")
    }
  } else {
    author_ID = 0
  }

	allchirps, err := ch.chirpDatabase.GetChirps(author_ID, sort_value)
	if err != nil {
		log.Printf("Couldn't get chirps: %s", err)
	}

	data, err := json.Marshal(allchirps)
	if err != nil {
		log.Printf("Couldn't get chirps: %s", err)
	}
	// fmt.Println(r.URL.Path)
	w.Write(data)
}

func (ch *chirpyHandler) getChirpsWithID(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8") // normal header
	pathSlice := strings.Split(r.URL.Path, "/")

	id, err := strconv.Atoi(pathSlice[len(pathSlice)-1])
	if err != nil {
		log.Printf("Could not parse ID")
		w.WriteHeader(http.StatusNotFound)
		return
	}

	targetChirp, err := ch.chirpDatabase.GetChirpByID(id)
	if err != nil {
		log.Printf("Could not find chirp with ID: %v", id)
		w.WriteHeader(http.StatusNotFound)
		return
	}

	data, err := json.Marshal(targetChirp)
	if err != nil {
		log.Printf("Error marshalling JSON: %s", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	w.Write(data)
}

func (ch *chirpyHandler) ResetMetrics(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8") // normal header
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(""))
	ch.fileserverHits = 0
}

func respondWithError(w http.ResponseWriter, code int, msg string) {
	if code > 499 {
		log.Printf("Responding with 5XX error: %s", msg)
	}

	type errorJson struct {
		Error string `json:"error"`
	}

	respondWithJson(w, code, errorJson{Error: msg})
}

func respondWithJson(w http.ResponseWriter, code int, payload interface{}) {
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

func profanityCheck(sentence string) string {
	splitString := strings.Split(sentence, " ")
	for i, word := range splitString {
		lowerWord := strings.ToLower(word)
		if lowerWord == "kerfuffle" || lowerWord == "sharbert" || lowerWord == "fornax" {
			splitString[i] = "****"
		}
	}
	return strings.Join(splitString, " ")
}

func (ch *chirpyHandler) ValidateChirp(w http.ResponseWriter, r *http.Request) {
	// We'll want to use Decoder here since we're reading from a stream
	// We use decorde to unmarshall it, into our struct

	type cleanChirp struct {
		Body string `json:"cleaned_body"`
	}

	type validJson struct {
		Valid bool `json:"valid"`
	}

	dec := json.NewDecoder(r.Body)
	newChirp := internal.Chirp{}
	err := dec.Decode(&newChirp)

	if err != nil {
		respondWithError(w, http.StatusInternalServerError, "Something went wrong")
		return
	}

	if len(newChirp.Body) > 140 {
		respondWithError(w, http.StatusBadRequest, "Chirp is too long")
		return
	}
	cleaned_chirp := cleanChirp{Body: profanityCheck(newChirp.Body)}

	respondWithJson(w, http.StatusOK, cleaned_chirp)
}

func (ch *chirpyHandler) deleteChrips(w http.ResponseWriter, r *http.Request) {

	type customClaims struct {
		ch string
		jwt.RegisteredClaims
	}

	// GETS CHIRP ID
	pathSlice := strings.Split(r.URL.Path, "/")
	chirpID, err := strconv.Atoi(pathSlice[len(pathSlice)-1])
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, "Couldn't get Chirp ID")
		return
	}

	tokenString := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	// TODO Try to understand what's occuring in this return statement
	token, token_err := jwt.ParseWithClaims(tokenString, &customClaims{}, func(token *jwt.Token) (interface{}, error) {
		return []byte(ch.JWTSECRET), nil
	})
	if token_err != nil {
		respondWithError(w, http.StatusInternalServerError, "Invalid JWT")
		return
	}

	userID, err := getUserIDFromToken(token)
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, "Couldn't parse UserID")
		return
	}

	err = ch.chirpDatabase.DeleteChirpsWithID(userID, chirpID)
	if err != nil {
		respondWithError(w, http.StatusForbidden, "Not authorized to delete chirp")
		return
	}

	respondWithJson(w, http.StatusNoContent, "Chirp Deleted")
	return
}

func getUserIDFromToken(token *jwt.Token) (int, error) {
	tokenUserID, err := token.Claims.GetSubject()
	if err != nil {
		return -1, err
	}

	convertedUserId, err := strconv.Atoi(tokenUserID)
	if err != nil {
		return -1, err
	}

	return convertedUserId, nil
}

// We'll want get the data and validate it before creating the chirp
func (ch *chirpyHandler) postChirps(w http.ResponseWriter, r *http.Request) {

	type tempChirp struct {
		Body string `json:"body"`
	}

	type customClaims struct {
		ch string
		jwt.RegisteredClaims
	}

	tokenString := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	// TODO Try to understand what's occuring in this return statement
	token, token_err := jwt.ParseWithClaims(tokenString, &customClaims{}, func(token *jwt.Token) (interface{}, error) {
		return []byte(ch.JWTSECRET), nil
	})
	if token_err != nil {
		respondWithError(w, http.StatusInternalServerError, "Invalid JWT")
		return
	}

	dec := json.NewDecoder(r.Body)
	newChirp := tempChirp{}
	err := dec.Decode(&newChirp)

	if err != nil {
		respondWithError(w, http.StatusInternalServerError, "Something went wrong")
		return
	}

	if len(newChirp.Body) > 140 {
		respondWithError(w, http.StatusBadRequest, "Chirp is too long")
		return
	}

	userIDString, err := token.Claims.GetSubject()
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, "Could not get UserID from JWT")
	}
	userID, err := strconv.Atoi(userIDString)
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, "Could not get UserID from JWT")
	}

	validChirp, err := ch.chirpDatabase.CreateChirp(profanityCheck(newChirp.Body), userID)
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, "Something went wrong")
		return
	}
	respondWithJson(w, http.StatusCreated, validChirp)
}

// HANDLE USERS
func (ch *chirpyHandler) postUsers(w http.ResponseWriter, r *http.Request) {

	newUser := handlePasswordUser(r)

	_, doesExists := ch.chirpDatabase.CheckIfEmailExists(newUser.Email)
	if doesExists {
		respondWithError(w, http.StatusInternalServerError, "User exists")
		return
	}

	// here we create the user and add to db
	validUser, err := ch.chirpDatabase.CreateUser(newUser.Password, newUser.Email)
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, "Something went wrong creating User")
		return
	}

	respondWithJson(w, http.StatusCreated,
		struct {
			ID            int    `json:"id"`
			Email         string `json:"email"`
			Is_Chirpy_Red bool   `json:"is_chirpy_red"`
		}{
			validUser.ID, validUser.Email, validUser.Is_Chirpy_Red,
		})
}

func (ch *chirpyHandler) postLogin(w http.ResponseWriter, r *http.Request) {

	userRequestData := handlePasswordUser(r)

	id, doesExists := ch.chirpDatabase.CheckIfEmailExists(userRequestData.Email)
	if !doesExists {
		respondWithError(w, http.StatusInternalServerError, "User does not exist")
		return
	}
	validUser, err := ch.chirpDatabase.CheckPasswordMatch(id, userRequestData.Password)

	if err != nil {
		respondWithError(w, http.StatusUnauthorized, "Wrong Password")
		return
	}

	ss, err := ch.CreateJWT(validUser.ID)
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, "Could not create JWT")
		return
	}

	refreshToken, err := ch.chirpDatabase.CreateRefreshToken(validUser.ID)
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, "Could not create Refresh Token")
		return
	}

	respondWithJson(w, http.StatusOK,
		struct {
			ID            int    `json:"id"`
			Email         string `json:"email"`
			Token         string `json:"token"`
			RefreshToken  string `json:"refresh_token"`
			Is_Chirpy_Red bool   `json:"is_chirpy_red"`
		}{
			validUser.ID, validUser.Email, ss, refreshToken, validUser.Is_Chirpy_Red,
		})

	return
}

func (ch *chirpyHandler) CreateJWT(userID int) (string, error) {
	// fmt.Println("CREATING JWT")
	defaultExpiredTime := time.Duration(3600)

	claims := struct {
		ch string
		jwt.RegisteredClaims
	}{
		"chirpy",
		jwt.RegisteredClaims{
			Issuer:    "chirpy",
			IssuedAt:  jwt.NewNumericDate(time.Now().UTC()),
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Second * defaultExpiredTime).UTC()),
			Subject:   strconv.Itoa(userID),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	ss, err := token.SignedString([]byte(ch.JWTSECRET))

	if err != nil {
		return "", err
	}

	return ss, err
}

func handlePasswordUser(r *http.Request) internal.PasswordUser {

	dec := json.NewDecoder(r.Body)
	loggingUser := internal.PasswordUser{}
	err := dec.Decode(&loggingUser)

	if err != nil {
		log.Fatalf("Could not parse json %s", err)
		return internal.PasswordUser{}
	}

	return loggingUser
}

func (ch *chirpyHandler) updateUsers(w http.ResponseWriter, r *http.Request) {
	// type simpleUser struct {
	// 	Email    string `json:"email"`
	// 	Password string `json:"password"`
	// }
	type customClaims struct {
		ch string
		jwt.RegisteredClaims
	}

	tokenString := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")

	decBody := json.NewDecoder(r.Body)
	newUserInfo := internal.User{} //simpleUser{}
	err := decBody.Decode(&newUserInfo)
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, "Could not parse json")
		return
	}

	// TODO Try to understand what's occuring in this return statement
	token, err := jwt.ParseWithClaims(tokenString, &customClaims{}, func(token *jwt.Token) (interface{}, error) {
		return []byte(ch.JWTSECRET), nil
	})

	if err != nil {
		respondWithError(w, http.StatusUnauthorized, "Could not authorize JWT")
		return
	}

	string_id, err := token.Claims.GetSubject()
	if err != nil {
		respondWithError(w, http.StatusUnauthorized, "Could not parse JWT Subject")
		return
	}
	userID, err := strconv.Atoi(string_id)
	if err != nil {
		respondWithError(w, http.StatusUnauthorized, "Could not convert ID")
		return
	}

	newUserInfo.ID = userID
	validUser, err := ch.chirpDatabase.UpdateUsers(userID, newUserInfo)
	if err != nil {
		respondWithError(w, http.StatusUnauthorized, "Could not Update")
		return

	}

	respondWithJson(w, http.StatusOK,
		struct {
			ID            int    `json:"id"`
			Email         string `json:"email"`
			Is_Chirpy_Red bool   `json:"is_chirpy_red"`
		}{
			validUser.ID, validUser.Email, validUser.Is_Chirpy_Red,
		})

	return
}

func (ch *chirpyHandler) middlewareMetricsInc(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ch.fileserverHits++
		// Then proceed to next hanlder
		next.ServeHTTP(w, r)
	})
}

func (ch *chirpyHandler) postCheckRefreshToken(w http.ResponseWriter, r *http.Request) {
	refreshTokenString := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")

	refreshTokenInfo, err := ch.chirpDatabase.CheckRefreshToken(refreshTokenString)
	if err != nil {
		respondWithError(w, http.StatusUnauthorized, "Invalid Refresh Token")
		return
	}

	ss, err := ch.CreateJWT(refreshTokenInfo.ID)
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, "Could not create JWT")
		return
	}

	respondWithJson(w, http.StatusOK,
		struct {
			Token string `json:"token"`
		}{
			ss,
		})
	return
}

func (ch *chirpyHandler) postRevokeRefreshToken(w http.ResponseWriter, r *http.Request) {
	refreshTokenString := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")

	err := ch.chirpDatabase.RevokeRefreshToken(refreshTokenString)
	if err != nil {
		respondWithError(w, http.StatusUnauthorized, "Invalid Refresh Token")
		return
	}

	respondWithJson(w, http.StatusNoContent, "Revoked Refresh Token")
	return
}

func (ch *chirpyHandler) postPolkaWebHookHandler(w http.ResponseWriter, r *http.Request) {

	apiKey := strings.TrimPrefix(r.Header.Get("Authorization"), "ApiKey ")
  if apiKey != ch.POLKAKEY{
    respondWithError(w, http.StatusUnauthorized,"Unauthorized acccess.")
    return
  }

	dec := json.NewDecoder(r.Body)
	eventStruct := internal.Event_Polka{}
	err := dec.Decode(&eventStruct)
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, "Something went wrong")
		return
	}

	if eventStruct.Event != "user.upgraded" {
		respondWithError(w, http.StatusNoContent, "")
		return
	}
	err = ch.chirpDatabase.UpgradeUser(eventStruct.Data.UserID)
	if err != nil {
		respondWithError(w, http.StatusNotFound, fmt.Sprint(err))
		return
	}

	respondWithJson(w, http.StatusNoContent, "")
	return
}

func main() {

	godotenv.Load()
	jwtSecret := os.Getenv("JWT_SECRET")
	polkaKey := os.Getenv("POLKA_KEY")

	// dbg is a pointer to a boolean val
	dbg := flag.Bool("debug", false, "Enable debug mode")
	flag.Parse()

	if *dbg {
		fmt.Println("**Debug mode enabled -- Wiping database.json**")
		os.Remove("./database.json")
	}

	mux := http.NewServeMux()

	// Starts Database
	dbConnection, err := internal.NewDB("./database.json")
	if err != nil {
		log.Fatalf("CANT LOAD FILE: %v\n", err)
	}

	// SERVER CONFIG
	ch := chirpyHandler{"OK", 0, dbConnection, jwtSecret, polkaKey}

	mux.Handle("/app/*",
		http.StripPrefix("/app/", ch.middlewareMetricsInc(http.FileServer(http.Dir(".")))),
	)
	mux.HandleFunc("GET /api/healthz", ch.ServeHTTP)
	mux.HandleFunc("GET /admin/metrics", ch.ServeMetrics)
	mux.HandleFunc("/api/reset", ch.ResetMetrics)
	mux.HandleFunc("POST /api/chirps", ch.postChirps)
	mux.HandleFunc("GET /api/chirps", ch.getChirps)
	mux.HandleFunc("GET /api/chirps/{id}", ch.getChirpsWithID)
	mux.HandleFunc("POST /api/users", ch.postUsers)                        //Create User
	mux.HandleFunc("POST /api/login", ch.postLogin)                        //Log in + Creates JWT
	mux.HandleFunc("PUT /api/users", ch.updateUsers)                       //Update User
	mux.HandleFunc("POST /api/refresh", ch.postCheckRefreshToken)          // validate refreshtoken
	mux.HandleFunc("POST /api/revoke", ch.postRevokeRefreshToken)          // remove refreshtoken
	mux.HandleFunc("DELETE /api/chirps/{id}", ch.deleteChrips)             // Deletes chrips
	mux.HandleFunc("POST /api/polka/webhooks", ch.postPolkaWebHookHandler) //Handle webhook
	port := "8080"

	server := &http.Server{
		Addr:    ":" + port,
		Handler: mux,
	}

	// TODO 2024/06/25
	// We need to create an API endpoint to handle users
	// The easiest way to process this would be to have completely seperate functions to handle writing to the database
	// 1. create User Struct
	// 2. Add a users map to DbStructure
	// 3. Write to file using a createEmail and WriteEmail func
	// 4. Have DBStructure written to file
	// The harder way would be to consolidate this into generic functions, so posting Chirps and Users use the same functions

	// ListenAndServe starts the server
	// log fatal so that if it crashes, we quit the program

	log.Fatal(
		server.ListenAndServe(),
	)
}
