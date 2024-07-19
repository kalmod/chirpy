package internal

import "sync"

type GlobalCounter struct {
  mux sync.Mutex
  GlobalChirpID int
  GlobalUserID int
}

func (c *GlobalCounter) IncrementChirpID(){
  c.mux.Lock()
  defer c.mux.Unlock()
  c.GlobalChirpID++
}

func (c *GlobalCounter) IncrementUserID(){
  c.mux.Lock()
  defer c.mux.Unlock()
  c.GlobalUserID++
}
func (c *GlobalCounter) GetChirpID() int {
  c.mux.Lock()
  val := c.GlobalChirpID
  c.mux.Unlock()
  return val
}

func (c *GlobalCounter) GetUserID() int {
  c.mux.Lock()
  val := c.GlobalUserID
  c.mux.Unlock()
  return val
}

func (c *GlobalCounter) SetChirpID(id int) int {
  c.mux.Lock()
  c.GlobalChirpID = id
  c.mux.Unlock()
  return c.GlobalChirpID
}

func (c *GlobalCounter) SetUserID(id int) int {
  c.mux.Lock()
  c.GlobalUserID = id
  c.mux.Unlock()
  return c.GlobalUserID
}
