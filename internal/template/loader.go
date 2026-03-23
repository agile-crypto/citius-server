package template

import (
	"context"
	"fmt"
	"os"

	api "github.ibm.com/citius/citius-server/gen/go/types"
	"github.ibm.com/citius/citius-server/internal/errors"
	"google.golang.org/protobuf/encoding/protojson"
)

const opLoad errors.Op = "template.LoadStandardCatalog"

// ParseStandardCatalog parses proto-JSON data into a StandardAlgorithmCatalog.
// Useful when the catalog JSON is embedded or loaded from a non-file source.
func ParseStandardCatalog(data []byte) (*api.StandardAlgorithmCatalog, error) {
	catalog := &api.StandardAlgorithmCatalog{}
	if err := protojson.Unmarshal(data, catalog); err != nil {
		return nil, fmt.Errorf("failed to parse catalog JSON: %w", err)
	}
	return catalog, nil
}

// LoadStandardCatalog reads a proto-JSON catalog file, parses it, and registers
// all templates into the given Registry.
//
// The catalog file must conform to the StandardAlgorithmCatalog proto-JSON
// format (see proto/standard_algorithms.json). Each entry in the catalog's
// templates map is wrapped via NewTemplate() and registered into r.
//
// An empty catalog (no templates) is not an error.
func LoadStandardCatalog(catalogPath string, r Registry) error {
	data, err := os.ReadFile(catalogPath)
	if err != nil {
		return errors.New(context.TODO(), opLoad, errors.CodeInternal,
			"failed to read catalog file: "+err.Error())
	}

	catalog, err := ParseStandardCatalog(data)
	if err != nil {
		return errors.New(context.TODO(), opLoad, errors.CodeInvalidArgument, err.Error())
	}

	ctx := context.Background()
	for _, info := range catalog.GetTemplates() {
		tmpl := NewTemplate(info)
		if regErr := r.Register(ctx, tmpl); regErr != nil {
			return errors.Wrap(context.TODO(), opLoad, regErr)
		}
	}
	return nil
}
