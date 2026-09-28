// Package paging implements the offset page tokens the list RPCs share.
//
// A list RPC sorts its full result into a stable order, then asks Window which
// slice of it one page covers. The token is the decimal offset of the page's
// first item; clients treat it as opaque and only pass back what a response
// gave them.
package paging

import (
	"errors"
	"strconv"
)

// ErrInvalid reports a negative page size or a page token that is not one
// this package issued for a listing of this length.
var ErrInvalid = errors.New("invalid page_size or page_token")

// Window returns the half-open range [start, end) of a total-item listing
// that the page (size, token) covers, and the token of the next page, which
// is empty on the last one. A size of 0 means every remaining item.
func Window(total int, size int32, token string) (start, end int, next string, err error) {
	if size < 0 {
		return 0, 0, "", ErrInvalid
	}
	if token != "" {
		start, err = strconv.Atoi(token)
		if err != nil || start < 0 || start > total {
			return 0, 0, "", ErrInvalid
		}
	}
	end = total
	if size > 0 && int(size) < total-start {
		end = start + int(size)
	}
	if end < total {
		next = strconv.Itoa(end)
	}
	return start, end, next, nil
}
