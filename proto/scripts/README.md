# Scripts 

This folder contains scripts used to modify import paths and packages of proto and go files

## 1. Go package option in proto files

- `remove_go_package.py`: remove the `option go_package=` statement of the target `.proto` file(s)
- `add_go_package.py`: add the provided package as `option go_package=...` to the `.proto` file(s)

## 2. Replace import statements in Go files

- `replace_import_go.py`: replace import statements in `.go` files