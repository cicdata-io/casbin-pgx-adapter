package main

import (
	"github.com/casbin/casbin/v2"
	pgadapter "github.com/cicdata-io/casbin-pgx-adapter"
)

func main() {
	// Initialize a pgx adapter and use it in a Casbin enforcer:
	// The adapter will use the Postgres database named "casbin".
	// If it doesn't exist, the adapter will create it automatically.
	a, _ := pgadapter.NewAdapter("postgresql://postgres:password@postgres:5432/postgres?sslmode=disable") // Your driver and data source.

	e, _ := casbin.NewEnforcer("examples/rbac_model.conf", a)

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
