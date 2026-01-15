# Go pgx Adapter

[![Go](https://github.com/casbin/casbin-pg-adapter/actions/workflows/ci.yml/badge.svg)](https://github.com/casbin/casbin-pg-adapter/actions/workflows/ci.yml)
[![Coverage Status](https://coveralls.io/repos/github/casbin/casbin-pg-adapter/badge.svg?branch=master)](https://coveralls.io/github/casbin/casbin-pg-adapter?branch=master)

Go-pgx Adapter is the [pgx](https://github.com/jackc/pgx) adapter for [Casbin](https://github.com/casbin/casbin). With this library, Casbin can load policy from PostgreSQL or save policy to it.

## Installation

    go get github.com/casbin/casbin-pg-adapter

## Simple Postgres Example

```go
package main

import (
	pgadapter "github.com/casbin/casbin-pg-adapter"
	"github.com/casbin/casbin/v2"
)

func main() {
	// Initialize a pgx adapter and use it in a Casbin enforcer:
	// The adapter will use the Postgres database named "casbin".
	// If it doesn't exist, the adapter will create it automatically.
	a, _ := pgadapter.NewAdapter("postgresql://username:password@postgres:5432/database?sslmode=disable") // Your driver and data source.

	e := casbin.NewEnforcer("examples/rbac_model.conf", a)

	// Load the policy from DB.
	e.LoadPolicy()

	// Check the permission.
	e.Enforce("alice", "data1", "read")

	// Modify the policy.
	// e.AddPolicy(...)
	// e.RemovePolicy(...)

	// Save the policy back to DB.
	e.SavePolicy()
}
```

## Support for FilteredAdapter interface

You can [load a subset of policies](https://casbin.org/docs/policy-subset-loading) with this adapter:

```go
package main

import (
	"github.com/casbin/casbin/v2"
	pgadapter "github.com/casbin/casbin-pg-adapter"
)

func main() {
	a, _ := pgadapter.NewAdapter("postgresql://username:password@postgres:5432/database?sslmode=disable")
	e, _ := casbin.NewEnforcer("examples/rbac_model.conf", a)

	e.LoadFilteredPolicy(&pgadapter.Filter{
		P: []string{"", "data1"},
		G: []string{"alice"},
	})
	...
}
```

## Custom DB Connection

You can provide a custom table or database name with `pgadapter.NewAdapterByDB`

```go
package main

import (
	"github.com/casbin/casbin/v2"
	pgadapter "github.com/casbin/casbin-pg-adapter"
	"github.com/jackc/pgx/v5/pgxpool"
)

func main() {
	db, _ := pgxpool.New(context.Background(), "postgresql://pguser:pgpassword@localhost:5432/pgdb?sslmode=disable")
	defer db.Close()

	a, _ := pgadapter.NewAdapterByDB(db, pgadapter.WithTableName("custom_table"))
	e, _ := casbin.NewEnforcer("examples/rbac_model.conf", a)
    ...
}
```

## Run all tests

    docker-compose run --rm go

## Debug tests

    docker-compose run --rm go dlv test github.com/casbin/casbin-pg-adapter

## Getting Help

-   [Casbin](https://github.com/casbin/casbin)

## License

This project is under Apache 2.0 License. See the [LICENSE](LICENSE) file for the full license text.
