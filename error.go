package oauth

import "fmt"

type CallbackError struct {
    Callback string
}
func (e *CallbackError) String() string {
    return fmt.Sprintf("Callback not confirmed: %s", e.Callback)
}

type DanceError struct {
    Where string
    What string
}
func (e *DanceError) String() string {
    return fmt.Sprintf("Error in %s: %s", e.Where, e.What)
}

type ImplementationError struct {
    Where string
    What string
}
func (e *ImplementationError) String() string {
    return fmt.Sprintf("%s unimplmented for %s", e.What, e.Where)
}

