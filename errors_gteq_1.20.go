//go:build go1.20
// +build go1.20

package diag

import "errors"

func errorsJoin(e1, e2 error) error {
	return errors.Join(e1, e2)
}
