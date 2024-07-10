package internal

import (
	"time"
)

type Chirp struct {
	ID       int    `json:"id"`
	Body     string `json:"body"`
	AuthorID int    `json:"author_id"`
}

type RefreshTokenInfo struct {
	ID             int       `json:"id"`
	ExpirationDate time.Time `json:"expiration_date"`
}

// For Webhooks
type Event_Polka struct {
	Event string    `json:"event"`
	Data  EventData `json:"data"`
}
type EventData struct {
	UserID int `json:"user_id"`
}
