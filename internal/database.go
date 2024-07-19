package internal

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	bcrypt "golang.org/x/crypto/bcrypt"
)

// var GlobalChirpID int = 0
// var GlobalUserID int = 0

var counter GlobalCounter


type DB struct {
	path string
	mux  sync.RWMutex
}

type DBStructure struct {
	Chirps        map[int]Chirp               `json:"chirps"`
	Users         map[int]User                `json:"users"`
	RefreshTokens map[string]RefreshTokenInfo `json:"refresh_tokens"`
}

func (db *DB) PrintPath() string {
	return db.path
}

// NewDB creates a new database connection
// and creates the database file if it doesn't exist
func NewDB(path string) (*DB, error) {
	db := DB{
		path: path, mux: sync.RWMutex{},
	}
	db.ensureDB()

	return &db, nil
}

// ensureDB creates a new database file if it doesn't exist
func (db *DB) ensureDB() error {
	// Both open and create return a file

	// Attempt to open file
	_, err := os.Open(db.path)

	// if fails, create file in current path
	if errors.Is(err, fs.ErrNotExist) {
		fmt.Println("database.json does not exist....creating new file")
		_, err = os.Create(db.path)
		if err != nil {
			return err
		}
	}

	fmt.Println("database found")
	return nil
}

func (db *DB) loadDB() (DBStructure, error) {
	// os.readfile  returns text in bytes

  // db.mux.Lock()
  // defer db.mux.Unlock()

	loadedData := DBStructure{
		make(map[int]Chirp),
		make(map[int]User),
		make(map[string]RefreshTokenInfo),
	}

		data, err := os.ReadFile(db.path)
		if err != nil {
			return DBStructure{}, err
		}
		json.Unmarshal(data, &loadedData)
		getNewestID(loadedData)

	// fmt.Println(loadedData)
	return loadedData, nil
}

func getNewestID(loadedData DBStructure) {
	chirpSlice := []Chirp{}
	userSlice := []User{}

	for _, val := range loadedData.Chirps {
		chirpSlice = append(chirpSlice, val)
	}
	for _, val := range loadedData.Users {
		userSlice = append(userSlice, val)
	}
	if len(chirpSlice) != 0 {
		counter.SetChirpID(chirpSlice[len(chirpSlice)-1].ID)
	}
	if len(userSlice) != 0 {
		counter.SetUserID(userSlice[len(userSlice)-1].ID)
	}
}

func (db *DB) GetChirps(author_id int, sortDir string) ([]Chirp, error) {

	loadedDBData, err := db.loadDB()
	if err != nil {
		return []Chirp{}, nil
	}

	chirpSlice := []Chirp{}
	for _, val := range loadedDBData.Chirps {
    if author_id == 0 {
      chirpSlice = append(chirpSlice, val)
    } else {
      if val.AuthorID == author_id{
        chirpSlice = append(chirpSlice, val)
      }
    }
	}

  if sortDir == "asc" {
    sort.Slice(chirpSlice, func(i, j int) bool {
      return chirpSlice[i].ID < chirpSlice[j].ID
      }) // Sorting function | asc
  } else {
    sort.Slice(chirpSlice, func(i, j int) bool {
      return chirpSlice[i].ID > chirpSlice[j].ID
      }) // Sorting function | desc
  }

	if len(chirpSlice) != 0 {
		counter.SetChirpID(chirpSlice[len(chirpSlice)-1].ID)
	}

	// fmt.Println("CHIRPS: ",chirpSlice)
	return chirpSlice, nil
}

func (db *DB) GetChirpByID(id int) (Chirp, error) {
	loadedDBData, err := db.loadDB()
	if err != nil {
		return Chirp{}, err
	}

	targetChirp, ok := loadedDBData.Chirps[id]
	if ok == false {
		return Chirp{}, errors.New("ID does not exist")
	}

	return targetChirp, nil
}

func (db *DB) CreateChirp(body string, userID int) (Chirp, error) {
  db.mux.Lock()
  defer db.mux.Unlock()

	loadedDBData, err := db.loadDB()
	if err != nil {
		return Chirp{}, err
	}

	counter.IncrementChirpID()
	officialChirp := Chirp{ID: counter.GetChirpID(), Body: body, AuthorID: userID}

	loadedDBData.Chirps[officialChirp.ID] = officialChirp

	err = db.writeDB(loadedDBData)
	if err != nil {
		return Chirp{}, err
	}

	return officialChirp, nil
}

func (db *DB) CreateUser(password, body string) (User, error) {
  db.mux.Lock()
  defer db.mux.Unlock()

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), 1)
	if err != nil {
		return User{}, err
	}

	loadedDBData, err := db.loadDB()
	if err != nil {
		return User{}, err
	}

  counter.IncrementUserID()
	officialUser := User{ID: counter.GetUserID(), Password: string(hashedPassword), Email: body}


	loadedDBData.Users[officialUser.ID] = officialUser
	err = db.writeDB(loadedDBData)
	if err != nil {
		return User{}, err
	}

	return officialUser, nil
}

func (db *DB) writeDB(dbstructure DBStructure) error {
	// db.mux.Lock()
	j, err := json.Marshal(dbstructure)
	if err != nil {
		fmt.Println("mrshl err", j)
		return err
	}

	err = os.WriteFile(db.path, j, 0644)
	if err != nil {
		return err
	}
	// defer db.mux.Unlock()

	return nil
}

func (db *DB) CheckIfEmailExists(email string) (int, bool) {
	loadedDBData, err := db.loadDB()
	if err != nil {
		return -1, false
	}

	for _, user := range loadedDBData.Users {
		emailInDb := strings.ToLower(user.Email)
		if emailInDb == email {
			return user.ID, true
		}
	}

	return -1, false
}

func (db *DB) CheckPasswordMatch(id int, password string) (User, error) {
	loadedDBData, err := db.loadDB()
	if err != nil {
		return User{}, err
	}
	dbUser := loadedDBData.Users[id]

	err = bcrypt.CompareHashAndPassword([]byte(dbUser.Password), []byte(password))
	if err != nil {
		return User{}, err
	}

	return dbUser, nil
}

func (db *DB) UpdateUsers(userID int, newUserInfo User) (User, error) {
	loadedDBData, err := db.loadDB()
	if err != nil {
		return User{}, err
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(newUserInfo.Password), 1)
	if err != nil {
		return User{}, err
	}
	newUserInfo.Password = string(hashedPassword)
	existingID, exists := db.CheckIfEmailExists(newUserInfo.Email)
	if exists && existingID != userID {
		return User{}, errors.New("Email exists")
	}

	loadedDBData.Users[userID] = newUserInfo
	db.writeDB(loadedDBData)

	return newUserInfo, nil
}
func (db *DB) UpgradeUser(userID int) error {
	loadedDBData, err := db.loadDB()
	if err != nil {
		return err
	}

  userInfo, ok := loadedDBData.Users[userID]
  if !ok {
    return errors.New("User Not found")
  }
	userInfo.Is_Chirpy_Red = true
	loadedDBData.Users[userID] = userInfo

	db.writeDB(loadedDBData)
	return nil
}

func (db *DB) CreateRefreshToken(userID int) (string, error) {
	b := make([]byte, 32)
	_, err := rand.Read(b)
	if err != nil {
		return "", nil
	}
	encodedStr := hex.EncodeToString(b)

	expirationDate := time.Now().UTC().AddDate(0, 0, 60)
	loadedData, err := db.loadDB()
	if err != nil {
		return "", nil
	}

	loadedData.RefreshTokens[encodedStr] = RefreshTokenInfo{ID: userID, ExpirationDate: expirationDate}
	db.writeDB(loadedData)

	return encodedStr, nil
}

func (db *DB) CheckRefreshToken(refreshToken string) (RefreshTokenInfo, error) {
	loadedData, err := db.loadDB()
	if err != nil {
		return RefreshTokenInfo{}, err
	}

	if refreshInfo, ok := loadedData.RefreshTokens[refreshToken]; ok {
		return refreshInfo, nil
	}
	return RefreshTokenInfo{}, errors.New("Refresh Token not found")
}

func (db *DB) RevokeRefreshToken(refreshToken string) error {
	loadedData, err := db.loadDB()
	if err != nil {
		return err
	}

	_, ok := loadedData.RefreshTokens[refreshToken]
	if ok {
		delete(loadedData.RefreshTokens, refreshToken)
	} else {
		return errors.New("Refresh Token not found")
	}

	db.writeDB(loadedData)
	return nil
}

func (db *DB) DeleteChirpsWithID(userID, chirpID int) error {
	loadedData, err := db.loadDB()
	if err != nil {
		return err
	}

	val, ok := loadedData.Chirps[chirpID]
	if !ok {
		return errors.New("No chirp found with given ID")
	}

	if userID != val.AuthorID {
		return errors.New("Not author of chirp")
	}

	delete(loadedData.Chirps, chirpID)
	db.writeDB(loadedData)
	return nil
}
