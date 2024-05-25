//go:build !go1.20
// +build !go1.20

package diag

import "fmt"

func errorsJoin(e1, e2 error) error {
	if e1 == nil {
		return e2
	}
	if e2 == nil {
		return e1
	}
	return fmt.Errorf("%v: %v", e1, e2)
}
