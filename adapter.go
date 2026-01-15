package pgadapter

import (
	"context"
	"fmt"
	"strings"

	"github.com/casbin/casbin/v2/model"
	"github.com/casbin/casbin/v2/persist"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/mmcloughlin/meow"
)

const DefaultTableName = "casbin_rule"
const DefaultDatabaseName = "casbin"

// CasbinRule represents a rule in Casbin.
type CasbinRule struct {
	tableName struct{} `pg:"_"`
	ID        string
	Ptype     string
	V0        string
	V1        string
	V2        string
	V3        string
	V4        string
	V5        string
}

type Filter struct {
	P []string
	G []string
}

// Adapter represents the pgx adapter for policy storage.
type Adapter struct {
	db              *pgxpool.Pool
	tableName       string
	skipTableCreate bool
	filtered        bool
}

type Option func(a *Adapter)

// NewAdapter is the constructor for Adapter.
func NewAdapter(connString string, dbname ...string) (*Adapter, error) {
	config, err := pgxpool.ParseConfig(connString)
	if err != nil {
		return nil, fmt.Errorf("pgadapter.NewAdapter: %v", err)
	}

	if len(dbname) > 0 {
		config.ConnConfig.Database = dbname[0]
		createCasbinDatabase(connString, dbname[0])

	} else {
		config.ConnConfig.Database = DefaultDatabaseName
		createCasbinDatabase(connString, DefaultDatabaseName)
	}

	db, err := pgxpool.NewWithConfig(context.Background(), config)
	if err != nil {
		return nil, fmt.Errorf("pgadapter.NewAdapter: %v", err)
	}

	a := &Adapter{db: db, tableName: DefaultTableName}

	if err := a.createTableIfNotExists(); err != nil {
		return nil, fmt.Errorf("pgadapter.NewAdapter: %v", err)
	}

	return a, nil
}

func createCasbinDatabase(arg interface{}, dbname string) error {
	var connString string
	var ok bool

	if connString, ok = arg.(string); !ok {
		return fmt.Errorf("must pass in a PostgreSQL connection string, received %T instead", arg)
	}

	// Connect to the default database
	config, err := pgxpool.ParseConfig(connString)
	if err != nil {
		return fmt.Errorf("failed to parse connection string: %v", err)
	}

	// Temporarily connect to the default database
	tempConfig := *config
	tempConfig.ConnConfig.Database = "postgres"
	tempPool, err := pgxpool.NewWithConfig(context.Background(), &tempConfig)
	if err != nil {
		return fmt.Errorf("failed to connect to default database: %v", err)
	}
	defer tempPool.Close()

	// Check if the database already exists
	var exists bool
	err = tempPool.QueryRow(context.Background(), "SELECT EXISTS(SELECT 1 FROM pg_database WHERE datname = $1)", dbname).Scan(&exists)
	if err != nil {
		return fmt.Errorf("failed to check if database exists: %v", err)
	}

	if exists {
		return nil // Database already exists, no need to create
	}

	// Create the new database
	_, err = tempPool.Exec(context.Background(), fmt.Sprintf("CREATE DATABASE %s", dbname))
	if err != nil && !strings.Contains(err.Error(), "already exists") {
		return fmt.Errorf("failed to create database: %v", err)
	}

	return nil
}

// NewAdapterByDB creates new Adapter by using existing DB connection
// creates table from CasbinRule struct if it doesn't exist
func NewAdapterByDB(db *pgxpool.Pool, opts ...Option) (*Adapter, error) {
	a := &Adapter{db: db, tableName: DefaultTableName}
	for _, opt := range opts {
		opt(a)
	}

	if !a.skipTableCreate {
		if err := a.createTableIfNotExists(); err != nil {
			return nil, fmt.Errorf("pgadapter.NewAdapter: %v", err)
		}
	}
	return a, nil
}

// WithTableName can be used to pass custom table name for Casbin rules
func WithTableName(tableName string) Option {
	return func(a *Adapter) {
		a.tableName = tableName
	}
}

// SkipTableCreate skips the table creation step when the adapter starts
// If the Casbin rules table does not exist, it will lead to issues when using the adapter
func SkipTableCreate() Option {
	return func(a *Adapter) {
		a.skipTableCreate = true
	}
}

// Close closes the database connection.
func (a *Adapter) Close() error {
	if a != nil && a.db != nil {
		a.db.Close()
	}
	return nil
}

func (a *Adapter) createTableIfNotExists() error {
	_, err := a.db.Exec(context.Background(), fmt.Sprintf(`
		CREATE TABLE IF NOT EXISTS %s (
			id TEXT PRIMARY KEY,
			ptype TEXT,
			v0 TEXT,
			v1 TEXT,
			v2 TEXT,
			v3 TEXT,
			v4 TEXT,
			v5 TEXT
		)`, a.tableName))
	return err
}

// getValues returns the V0-V5 values as a slice
func (r *CasbinRule) getValues() []string {
	return []string{r.V0, r.V1, r.V2, r.V3, r.V4, r.V5}
}

// getLastNonEmptyIndex returns the index of the last non-empty value in the given slice
// Returns -1 if all values are empty
func getLastNonEmptyIndex(values []string) int {
	for i := len(values) - 1; i >= 0; i-- {
		if values[i] != "" {
			return i
		}
	}
	return -1
}

func (r *CasbinRule) String() string {
	const prefixLine = ", "
	var sb strings.Builder

	sb.Grow(
		len(r.Ptype) +
			len(r.V0) + len(r.V1) + len(r.V2) +
			len(r.V3) + len(r.V4) + len(r.V5),
	)

	sb.WriteString(r.Ptype)

	values := r.getValues()
	lastIndex := getLastNonEmptyIndex(values)

	// Include all values up to and including the last non-empty one
	// This preserves empty strings in the middle while trimming trailing empty strings
	for i := 0; i <= lastIndex; i++ {
		sb.WriteString(prefixLine)
		sb.WriteString(values[i])
	}

	return sb.String()
}

// LoadPolicy loads policy from the database.
func (a *Adapter) LoadPolicy(model model.Model) error {
	rows, err := a.db.Query(context.Background(), fmt.Sprintf("SELECT id, ptype, v0, v1, v2, v3, v4, v5 FROM %s", a.tableName))
	if err != nil {
		return err
	}
	defer rows.Close()

	for rows.Next() {
		var line CasbinRule
		if err := rows.Scan(&line.ID, &line.Ptype, &line.V0, &line.V1, &line.V2, &line.V3, &line.V4, &line.V5); err != nil {
			return err
		}
		if err := persist.LoadPolicyLine(line.String(), model); err != nil {
			return err
		}
	}

	a.filtered = false
	return nil
}

func policyID(ptype string, rule []string) string {
	data := strings.Join(append([]string{ptype}, rule...), ",")
	sum := meow.Checksum(0, []byte(data))
	return fmt.Sprintf("%x", sum)
}

func savePolicyLine(ptype string, rule []string) *CasbinRule {
	line := &CasbinRule{Ptype: ptype}

	l := len(rule)
	if l > 0 {
		line.V0 = rule[0]
	}
	if l > 1 {
		line.V1 = rule[1]
	}
	if l > 2 {
		line.V2 = rule[2]
	}
	if l > 3 {
		line.V3 = rule[3]
	}
	if l > 4 {
		line.V4 = rule[4]
	}
	if l > 5 {
		line.V5 = rule[5]
	}

	line.ID = policyID(ptype, rule)

	return line
}

// SavePolicy saves policy to database.
func (a *Adapter) SavePolicy(model model.Model) error {
	tx, err := a.db.Begin(context.Background())
	if err != nil {
		return fmt.Errorf("start DB transaction: %v", err)
	}
	defer tx.Rollback(context.Background())

	_, err = tx.Exec(context.Background(), fmt.Sprintf("DELETE FROM %s WHERE id IS NOT NULL", a.tableName))
	if err != nil {
		return err
	}

	var lines []*CasbinRule

	for ptype, ast := range model["p"] {
		for _, rule := range ast.Policy {
			line := savePolicyLine(ptype, rule)
			lines = append(lines, line)
		}
	}

	for ptype, ast := range model["g"] {
		for _, rule := range ast.Policy {
			line := savePolicyLine(ptype, rule)
			lines = append(lines, line)
		}
	}

	for _, line := range lines {
		_, err = tx.Exec(context.Background(), fmt.Sprintf(`
			INSERT INTO %s (id, ptype, v0, v1, v2, v3, v4, v5)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
			ON CONFLICT DO NOTHING`, a.tableName),
			line.ID, line.Ptype, line.V0, line.V1, line.V2, line.V3, line.V4, line.V5)
		if err != nil {
			return err
		}
	}

	err = tx.Commit(context.Background())
	if err != nil {
		return fmt.Errorf("commit DB transaction: %v", err)
	}

	return nil
}

// AddPolicy adds a policy rule to the storage.
func (a *Adapter) AddPolicy(sec string, ptype string, rule []string) error {
	line := savePolicyLine(ptype, rule)
	_, err := a.db.Exec(context.Background(), fmt.Sprintf(`
		INSERT INTO %s (id, ptype, v0, v1, v2, v3, v4, v5)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
		ON CONFLICT DO NOTHING`, a.tableName),
		line.ID, line.Ptype, line.V0, line.V1, line.V2, line.V3, line.V4, line.V5)
	return err
}

// AddPolicies adds policy rules to the storage.
func (a *Adapter) AddPolicies(sec string, ptype string, rules [][]string) error {
	tx, err := a.db.Begin(context.Background())
	if err != nil {
		return err
	}
	defer tx.Rollback(context.Background())

	for _, rule := range rules {
		line := savePolicyLine(ptype, rule)
		_, err := tx.Exec(context.Background(), fmt.Sprintf(`
			INSERT INTO %s (id, ptype, v0, v1, v2, v3, v4, v5)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
			ON CONFLICT DO NOTHING`, a.tableName),
			line.ID, line.Ptype, line.V0, line.V1, line.V2, line.V3, line.V4, line.V5)
		if err != nil {
			return err
		}
	}

	err = tx.Commit(context.Background())
	if err != nil {
		return err
	}

	return nil
}

// RemovePolicy removes a policy rule from the storage.
func (a *Adapter) RemovePolicy(sec string, ptype string, rule []string) error {
	line := savePolicyLine(ptype, rule)
	_, err := a.db.Exec(context.Background(), fmt.Sprintf("DELETE FROM %s WHERE id = $1", a.tableName), line.ID)
	return err
}

// RemovePolicies removes policy rules from the storage.
func (a *Adapter) RemovePolicies(sec string, ptype string, rules [][]string) error {
	tx, err := a.db.Begin(context.Background())
	if err != nil {
		return err
	}
	defer tx.Rollback(context.Background())

	for _, rule := range rules {
		line := savePolicyLine(ptype, rule)
		_, err := tx.Exec(context.Background(), fmt.Sprintf("DELETE FROM %s WHERE id = $1", a.tableName), line.ID)
		if err != nil {
			return err
		}
	}

	err = tx.Commit(context.Background())
	if err != nil {
		return err
	}

	return nil
}

// RemoveFilteredPolicy removes policy rules that match the filter from the storage.
func (a *Adapter) RemoveFilteredPolicy(sec string, ptype string, fieldIndex int, fieldValues ...string) error {
	query := fmt.Sprintf("DELETE FROM %s WHERE ptype = $1", a.tableName)
	args := []interface{}{ptype}

	for i, v := range fieldValues {
		if v != "" {
			query += fmt.Sprintf(" AND v%d = $%d", fieldIndex+i, len(args)+1)
			args = append(args, v)
		}
	}

	_, err := a.db.Exec(context.Background(), query, args...)
	return err
}

func (a *Adapter) LoadFilteredPolicy(model model.Model, filter interface{}) error {
	if filter == nil {
		return a.LoadPolicy(model)
	}

	filterValue, ok := filter.(*Filter)
	if !ok {
		return fmt.Errorf("invalid filter type")
	}
	err := a.loadFilteredPolicy(model, filterValue, persist.LoadPolicyLine)
	if err != nil {
		return err
	}
	a.filtered = true
	return nil
}

func buildQuery(query string, values []string) (string, []interface{}) {
	args := []interface{}{}
	for i, v := range values {
		if v != "" {
			query += fmt.Sprintf(" AND v%d = $%d", i, len(args)+1)
			args = append(args, v)
		}
	}
	return query, args
}

func (a *Adapter) loadFilteredPolicy(model model.Model, filter *Filter, handler func(string, model.Model) error) error {
	if filter.P != nil {
		query := fmt.Sprintf("SELECT id, ptype, v0, v1, v2, v3, v4, v5 FROM %s WHERE ptype = 'p'", a.tableName)
		query, args := buildQuery(query, filter.P)
		rows, err := a.db.Query(context.Background(), query, args...)
		if err != nil {
			return err
		}
		defer rows.Close()

		for rows.Next() {
			var line CasbinRule
			if err := rows.Scan(&line.ID, &line.Ptype, &line.V0, &line.V1, &line.V2, &line.V3, &line.V4, &line.V5); err != nil {
				return err
			}
			if err := handler(line.String(), model); err != nil {
				return err
			}
		}
	}
	if filter.G != nil {
		query := fmt.Sprintf("SELECT id, ptype, v0, v1, v2, v3, v4, v5 FROM %s WHERE ptype = 'g'", a.tableName)
		query, args := buildQuery(query, filter.G)
		rows, err := a.db.Query(context.Background(), query, args...)
		if err != nil {
			return err
		}
		defer rows.Close()

		for rows.Next() {
			var line CasbinRule
			if err := rows.Scan(&line.ID, &line.Ptype, &line.V0, &line.V1, &line.V2, &line.V3, &line.V4, &line.V5); err != nil {
				return err
			}
			if err := handler(line.String(), model); err != nil {
				return err
			}
		}
	}
	return nil
}

func (a *Adapter) IsFiltered() bool {
	return a.filtered
}

// UpdatePolicy updates a policy rule from storage.
// This is part of the Auto-Save feature.
func (a *Adapter) UpdatePolicy(sec string, ptype string, oldRule, newPolicy []string) error {
	return a.UpdatePolicies(sec, ptype, [][]string{oldRule}, [][]string{newPolicy})
}

// UpdatePolicies updates some policy rules to storage, like db, redis.
func (a *Adapter) UpdatePolicies(sec string, ptype string, oldRules, newRules [][]string) error {
	tx, err := a.db.Begin(context.Background())
	if err != nil {
		return err
	}
	defer tx.Rollback(context.Background())

	for i, oldRule := range oldRules {
		oldLine := savePolicyLine(ptype, oldRule)
		newLine := savePolicyLine(ptype, newRules[i])
		_, err := tx.Exec(context.Background(), fmt.Sprintf("UPDATE %s SET ptype = $1, v0 = $2, v1 = $3, v2 = $4, v3 = $5, v4 = $6, v5 = $7 WHERE id = $8", a.tableName),
			newLine.Ptype, newLine.V0, newLine.V1, newLine.V2, newLine.V3, newLine.V4, newLine.V5, oldLine.ID)
		if err != nil {
			return err
		}
	}

	err = tx.Commit(context.Background())
	if err != nil {
		return err
	}

	return nil
}

func (a *Adapter) UpdateFilteredPolicies(sec string, ptype string, newPolicies [][]string, fieldIndex int, fieldValues ...string) ([][]string, error) {
	line := &CasbinRule{}

	line.Ptype = ptype
	if fieldIndex <= 0 && 0 < fieldIndex+len(fieldValues) {
		line.V0 = fieldValues[0-fieldIndex]
	}
	if fieldIndex <= 1 && 1 < fieldIndex+len(fieldValues) {
		line.V1 = fieldValues[1-fieldIndex]
	}
	if fieldIndex <= 2 && 2 < fieldIndex+len(fieldValues) {
		line.V2 = fieldValues[2-fieldIndex]
	}
	if fieldIndex <= 3 && 3 < fieldIndex+len(fieldValues) {
		line.V3 = fieldValues[3-fieldIndex]
	}
	if fieldIndex <= 4 && 4 < fieldIndex+len(fieldValues) {
		line.V4 = fieldValues[4-fieldIndex]
	}
	if fieldIndex <= 5 && 5 < fieldIndex+len(fieldValues) {
		line.V5 = fieldValues[5-fieldIndex]
	}

	newP := make([]CasbinRule, 0, len(newPolicies))
	oldP := make([]CasbinRule, 0)
	for _, newRule := range newPolicies {
		newP = append(newP, *(savePolicyLine(ptype, newRule)))
	}

	tx, err := a.db.Begin(context.Background())
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(context.Background())

	for i := range newP {
		str, args := line.queryString()
		_, err := tx.Exec(context.Background(), fmt.Sprintf("DELETE FROM %s WHERE %s", a.tableName, str), args...)
		if err != nil {
			return nil, err
		}

		_, err = tx.Exec(context.Background(), fmt.Sprintf(`
			INSERT INTO %s (id, ptype, v0, v1, v2, v3, v4, v5)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
			ON CONFLICT DO NOTHING`, a.tableName),
			newP[i].ID, newP[i].Ptype, newP[i].V0, newP[i].V1, newP[i].V2, newP[i].V3, newP[i].V4, newP[i].V5)
		if err != nil {
			return nil, err
		}
	}

	if err = tx.Commit(context.Background()); err != nil {
		return nil, err
	}

	// return deleted rulues
	oldPolicies := make([][]string, 0)
	for _, v := range oldP {
		oldPolicy := v.toStringPolicy()
		oldPolicies = append(oldPolicies, oldPolicy)
	}
	return oldPolicies, err
}
func (c *CasbinRule) queryString() (string, []interface{}) {
	queryArgs := []interface{}{c.Ptype}
	queryStr := "ptype = $1"

	values := c.getValues()
	lastIndex := getLastNonEmptyIndex(values)

	// Include all fields up to and including the last non-empty one
	// This ensures empty strings in the middle are matched explicitly
	fields := []string{"v0", "v1", "v2", "v3", "v4", "v5"}
	for i := 0; i <= lastIndex; i++ {
		queryStr += fmt.Sprintf(" AND %s = $%d", fields[i], len(queryArgs)+1)
		queryArgs = append(queryArgs, values[i])
	}

	return queryStr, queryArgs
}

func (c *CasbinRule) toStringPolicy() []string {
	policy := make([]string, 0)
	if c.Ptype != "" {
		policy = append(policy, c.Ptype)
	}

	values := c.getValues()
	lastIndex := getLastNonEmptyIndex(values)

	// Include all values up to and including the last non-empty one
	// This preserves empty strings in the middle while trimming trailing empty strings
	for i := 0; i <= lastIndex; i++ {
		policy = append(policy, values[i])
	}

	return policy
}

func (a *Adapter) updatePolicies(oldLines, newLines []*CasbinRule) error {
	tx, err := a.db.Begin(context.Background())
	if err != nil {
		return err
	}
	defer tx.Rollback(context.Background())

	for i, line := range oldLines {
		str, _ := line.queryString()
		_, err = tx.Exec(context.Background(), fmt.Sprintf("UPDATE %s SET ptype = $1, v0 = $2, v1 = $3, v2 = $4, v3 = $5, v4 = $6, v5 = $7 WHERE %s", a.tableName, str),
			newLines[i].Ptype, newLines[i].V0, newLines[i].V1, newLines[i].V2, newLines[i].V3, newLines[i].V4, newLines[i].V5)
		if err != nil {
			return err
		}
	}

	if err = tx.Commit(context.Background()); err != nil {
		return err
	}
	return nil
}
