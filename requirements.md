### Setting up SSH for `go mod tidy`

```shell
# Configure GOPRIVATE
go env -w GOPRIVATE='github.ibm.com'

# Show changed Go environment variables
# It should display GOPRIVATE='github.ibm.com'
go env -changed

# Update git config (globally or locally)
git config --global url."git@github.ibm.com:".insteadOf "https://github.ibm.com/"
# or locally
git config url."git@github.ibm.com:".insteadOf "https://github.ibm.com/"

# Tidy
go mod tidy

# If a cached VCS is used and go mod tidy fails, delete the VCS
# In that case, the error trace should contain something similar to:
git ls-remote -q origin in /Users/xxx/go/pkg/mod/cache/vcs/322ccb08548d02fa7461c954bd6a1765db7816e26194acb51316db227d107ea7: exit status 128:
        remote: Anonymous access denied

# Remove the VCS
rm -rf /Users/xxx/go/pkg/mod/cache/vcs/322ccb08548d02fa7461c954bd6a1765db7816e26194acb51316db227d107ea7

# Or clean the entire modcache
go clean -modcache
```

### Setup for protobuf generation

Run the script `./proto/build_proto.sh` and follow the installation requirements

## 2. Tag injection

**Installing go-inject-tag**
```
go install github.com/favadi/protoc-go-inject-tag@latest
```

**Tag generation**
`protoc-go-inject-tag` must be run against existing `.pb.go` files

```
protoc-go-inject-tag -input="gen/go/*.pb.go"
```

## 3. GORM setup with SQLite

```
go get -u gorm.io/gorm
go get -u gorm.io/driver/sqlite
```