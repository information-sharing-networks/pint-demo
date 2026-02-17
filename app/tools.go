//go:build tools

package tools

import (
	_ "github.com/air-verse/air"
	_ "github.com/pressly/goose/v3/cmd/goose"
	_ "github.com/securego/gosec/v2/cmd/gosec"
	_ "github.com/sqlc-dev/sqlc/cmd/sqlc"
	_ "github.com/swaggo/swag/cmd/swag"
	_ "honnef.co/go/tools/cmd/staticcheck"
)
