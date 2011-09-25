package oauth

import "fmt"

// Something went wrong with the callback (e.g., it wasn't recognized).
type callbackError struct {
	Callback string
}

func (e *callbackError) String() string {
	return fmt.Sprintf("Callback not confirmed: %s", e.Callback)
}

// Something went wrong somewhere in our little dance with the server.
type danceError struct {
	Where string
	What  string
}

func (e *danceError) String() string {
	return fmt.Sprintf("Error in %s: %s", e.Where, e.What)
}

// I was lazy or did something wrong.
type implementationError struct {
	Where string
	What  string
}

func (e *implementationError) String() string {
	return fmt.Sprintf("%s unimplmented for %s", e.What, e.Where)
}
