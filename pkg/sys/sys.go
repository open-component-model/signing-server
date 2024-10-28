//go:build !unix

package sys

func Detach() error {
	return nil
}
