package template

import (
	"context"
	"os"

	api "github.ibm.com/citius/citius-server/gen/go/types"
	"github.ibm.com/citius/citius-server/internal/errors"
	"google.golang.org/protobuf/encoding/protojson"
)

// ParseStandardCatalog parses proto-JSON data into a StandardAlgorithmCatalog.
// Useful when the catalog JSON is embedded or loaded from a non-file source.
func ParseStandardCatalog(data []byte) (*api.StandardAlgorithmCatalog, error) {
	const op = "template.ParseStandardCatalog"
	catalog := &api.StandardAlgorithmCatalog{}
	if err := protojson.Unmarshal(data, catalog); err != nil {
		return nil, errors.Wrap(context.TODO(), op, err)
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
	const op = "template.LoadStandardCatalog"
	data, err := os.ReadFile(catalogPath)
	if err != nil {
		return errors.Wrap(context.TODO(), op, err, errors.WithMessage("failed to read catalog file %s", catalogPath))
	}

	catalog, err := ParseStandardCatalog(data)
	if err != nil {
		return errors.Wrap(context.TODO(), op, err, errors.WithMessage("failed to parse catalog %s", catalogPath))
	}

	ctx := context.Background()
	for _, info := range catalog.GetTemplates() {
		tmpl := NewTemplate(info)
		if regErr := r.Register(ctx, tmpl); regErr != nil {
			return errors.Wrap(context.TODO(), op, regErr, errors.WithMessage("failed to register template %s from catalog", tmpl.TemplateID()))
		}
	}
	return nil
}
