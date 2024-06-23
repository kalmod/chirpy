package internal

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"sort"
	"sync"
)

var GlobalChirpID int = 0

type DB struct {
  path string
  mux sync.RWMutex
}

type DBStructure struct {
  Chirps map[int]Chirp `json:"chirps"`
}

func (db *DB) PrintPath() string {
  return db.path
}

// NewDB creates a new database connection
// and creates the database file if it doesn't exist
func NewDB(path string) (*DB, error){
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
  if errors.Is(err,fs.ErrNotExist) {
    fmt.Println("database.json does not exist....creating new file")
    _, err = os.Create(db.path)
    if err != nil {
      return err
    }
  }
  
  fmt.Println("database found")
  return nil
}

func (db *DB) loadDB() (DBStructure,error) {
  // os.readfile  returns text in bytes
  
  loadedData := DBStructure{}

  var wg sync.WaitGroup
  openFile := func(){ 
      db.mux.Lock()
      data, err := os.ReadFile(db.path) 
      if err != nil {
        wg.Done()
        return 
      }
      defer db.mux.Unlock()
      json.Unmarshal(data, &loadedData)
      wg.Done()
      return 
    }

  
  wg.Add(1)
  go openFile()
  wg.Wait()

  // fmt.Println(loadedData)
  return loadedData, nil
}


func (db *DB) GetChirps() ([]Chirp, error){

  loadedDBData, err := db.loadDB()
  if err != nil {
    return []Chirp{}, nil
  }

  chirpSlice := []Chirp{}
  for _, val := range loadedDBData.Chirps {
    chirpSlice = append(chirpSlice, val)
  }
  sort.Slice(chirpSlice, func(i, j int) bool {
    return chirpSlice[i].ID < chirpSlice[j].ID
  })

  GlobalChirpID = chirpSlice[len(chirpSlice)-1].ID

  // fmt.Println("CHIRPS: ",chirpSlice)
  return chirpSlice,nil
}

func (db *DB) CreateChirp(body string) (Chirp, error) {
  GlobalChirpID++
  officialChirp := Chirp{ID: GlobalChirpID, Body: body}

  loadedDBData, err := db.loadDB()
  if err != nil {
    return Chirp{}, err
  }
  loadedDBData.Chirps[officialChirp.ID] = officialChirp
  err = db.writeDB(loadedDBData)

  return officialChirp, nil
}

func (db *DB) writeDB(dbstructure DBStructure) error {
  j, err := json.Marshal(dbstructure)
  if err != nil {
    fmt.Println("mrshl err", j)
    return err
  }

  err = os.WriteFile(db.path, j, 0644)
  if err != nil {
    return err
  }
  
  return nil
}
