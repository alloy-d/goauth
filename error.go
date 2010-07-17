package oauth

import "fmt"

// Something went wrong with the callback (e.g., it wasn't recognized).
type CallbackError struct {
    Callback string
}
func (e *CallbackError) String() string {
    return fmt.Sprintf("Callback not confirmed: %s", e.Callback)
}

// Something went wrong somewhere in our little dance with the server.
type DanceError struct {
    Where string
    What string
}
func (e *DanceError) String() string {
    return fmt.Sprintf("Error in %s: %s", e.Where, e.What)
}

// I was lazy or did something wrong.
type ImplementationError struct {
    Where string
    What string
}
func (e *ImplementationError) String() string {
    return fmt.Sprintf("%s unimplmented for %s", e.What, e.Where)
}

