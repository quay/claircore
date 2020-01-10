package claircore

// Repository is a package repository
type Repository struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	Key  string `json:"key"`
	URI  string `json:"uri"`
}
