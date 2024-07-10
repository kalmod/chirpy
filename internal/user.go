package internal

type User struct {
	ID    int    `json:"id"`
  Password string `json:"password"`
	Email string `json:"email"`
  Is_Chirpy_Red bool `json:"is_chirpy_red"`
}

type PasswordUser struct {
  Password string `json:"password"`
	Email string `json:"email"`
  Expires_in_seconds int `json:"expires_in_seconds,omitempty"`
}

