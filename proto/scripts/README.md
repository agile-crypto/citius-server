# Scripts 

This folder contains scripts used to modify import paths and packages of proto and go files

## 1. Go package option in proto files

- `remove_go_package.py`: remove the `option go_package=` statement of the target `.proto` file(s)
    - Helper: `python remove_go_package.py -h`
    - Standard usage: `python remove_go_package.py -f path_to_file` or `python remove_go_package.py -r path_to_dir`
- `add_go_package.py`: add the provided package as `option go_package=...` to the `.proto` file(s)
    - Helper: `python add_go_package.py -h`
    - Standard usage: `python add_go_package.py -f path_to_file go_package` or `python remove_go_package.py -r path_to_dir go_package` 

## 2. Replace import statements in Go files

- `replace_import_go.py`: replace import statements in `.go` files
    - Helper: `python replace_import_go.py -h`
    - Standard usage: see helper examples

## 3. Update API proto 

- `update_api_proto.py` clone proto files from a Git repository into `proto/api`
    - Parameters: 
        - `repo_url`: URL of the Git repository
        - `proto_folder`: folder of the cloned repository that holds the proto files
    - Options:
        - `--branch BRANCH`: Git branch to check out (default: repository default).
        - `--continue`: Resume a previously interrupted session (re-lint only).
        - `--abort`: Restore the previous state after a failed session.
        - `--debug`: Enable debug-level output (internal step details, paths,
                    per-file actions). Hidden by default.
        - `-h`, `--help`: Show this help message and exit.
        - `--keep-state`: Keep a copy of the old state, even after successful linting. If used, the operation must be terminated with `--continue`, explicitly. This option is used when other checks must be performed on the pulled content before commiting the changes.
        - `--tmp-dir`: Name of the directory in which the old state is kept while the program runs (default: `proto`). This must be changed to a direectory outside of `proto`, if Go code is to be generated with `buf generate`, otherwise the conflicts between the saved state and the pulled proto files will cause an error.
        - `--go-module`: Go module name of the current repo, used to construct go_package options
                    (default: github.ibm.com/citius/citius-server).
        - `--proto-packages`: Comma-separated list of proto packages to copy from the fetched repo and update (default: messages,services,types).
   - Usage to pull proto files from API repo: 
   `python3 update_api_proto.py --branch main --go-module github.ibm.com/citius/citius-server --proto-packages messages,services,types git@github.ibm.com:citius/api.git proto`

