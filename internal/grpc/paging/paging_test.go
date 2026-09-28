package paging_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/agile-crypto/citius-server/internal/grpc/paging"
)

func TestWindow(t *testing.T) {
	for name, tc := range map[string]struct {
		total      int
		size       int32
		token      string
		start, end int
		next       string
	}{
		"all at once":      {total: 5, start: 0, end: 5},
		"first page":       {total: 5, size: 2, start: 0, end: 2, next: "2"},
		"middle page":      {total: 5, size: 2, token: "2", start: 2, end: 4, next: "4"},
		"last page":        {total: 5, size: 2, token: "4", start: 4, end: 5},
		"exact fit":        {total: 4, size: 2, token: "2", start: 2, end: 4},
		"empty listing":    {total: 0, size: 3, start: 0, end: 0},
		"token at the end": {total: 3, size: 2, token: "3", start: 3, end: 3},
		"huge page size":   {total: 3, size: 1 << 30, start: 0, end: 3},
	} {
		t.Run(name, func(t *testing.T) {
			start, end, next, err := paging.Window(tc.total, tc.size, tc.token)
			require.NoError(t, err)
			require.Equal(t, []int{tc.start, tc.end}, []int{start, end})
			require.Equal(t, tc.next, next)
		})
	}
}

func TestWindow_Invalid(t *testing.T) {
	for name, tc := range map[string]struct {
		size  int32
		token string
	}{
		"negative size":  {size: -1},
		"garbage token":  {token: "x"},
		"negative token": {token: "-1"},
		"past the end":   {token: "4"},
	} {
		t.Run(name, func(t *testing.T) {
			_, _, _, err := paging.Window(3, tc.size, tc.token)
			require.ErrorIs(t, err, paging.ErrInvalid)
		})
	}
}
