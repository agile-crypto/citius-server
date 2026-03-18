package gorm

import (
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	store "github.ibm.com/citius/citius-server/gen/go/store"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

// setupTemporarySQLiteDB creates a SQLite database file in the same directory as this test file.
func setupTemporarySQLiteDB(filename string) (*gorm.DB, string, error) {
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		return nil, "", fmt.Errorf("failed to resolve caller path")
	}

	if filename == "" {
		return nil, "", fmt.Errorf("filename must not be empty")
	}

	dbPath := filepath.Join(filepath.Dir(thisFile), filename)

	f, err := os.Create(dbPath)
	if err != nil {
		return nil, "", fmt.Errorf("failed to create sqlite file: %w", err)
	}
	if err := f.Close(); err != nil {
		return nil, "", fmt.Errorf("failed to close sqlite file: %w", err)
	}

	db, err := gorm.Open(sqlite.Open(dbPath), &gorm.Config{})
	if err != nil {
		return nil, "", fmt.Errorf("failed to open sqlite database: %w", err)
	}

	return db, dbPath, nil
}

// deleteTemporarySQLiteDB deletes the sqlite database file at dbPath.
func deleteTemporarySQLiteDB(dbPath string) error {
	if dbPath == "" {
		return nil
	}
	if err := os.Remove(dbPath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to delete sqlite db: %w", err)
	}
	return nil
}

// setupSchema creates all required tables. It is backend-agnostic and works with any GORM RDBMS driver.
func setupSchema(db *gorm.DB) error {
	if db == nil {
		return fmt.Errorf("db must not be nil")
	}
	if err := db.AutoMigrate(&store.KeyV3{}, &store.KeyVersionV3{}); err != nil {
		return fmt.Errorf("failed to migrate schema: %w", err)
	}
	return nil
}

// generateKeysAndVersionsWithSeed creates N keys and M versions per key.
// For KeyV3, only PublicId and CurrentVersionId are set explicitly.
// For KeyVersionV3, only Id, Version, and KeyId are set explicitly.
func generateKeysAndVersionsWithSeed(numKeys, maxVersionsPerKey int, seed int64) ([]*store.KeyV3, []*store.KeyVersionV3, error) {
	if numKeys < 0 {
		return nil, nil, fmt.Errorf("numKeys must be >= 0")
	}
	if maxVersionsPerKey < 0 {
		return nil, nil, fmt.Errorf("maxVersionsPerKey must be >= 0")
	}

	rnd := rand.New(rand.NewSource(seed))
	keys := make([]*store.KeyV3, 0, numKeys)
	versions := make([]*store.KeyVersionV3, 0, numKeys*maxVersionsPerKey)
	signature_templates := []string{"ecdsa_p256_sha256", "Ed25519", "Ed448", "mldsa_65", "mldsa-87"}

	var globalVersionID uint32 = 1
	for k := range numKeys {
		keyID := fmt.Sprintf("key_%03d", k)

		key := &store.KeyV3{
			PublicId: keyID,
		}

		var lastVersionID uint32
		numKeyVersions := rnd.Intn(maxVersionsPerKey + 1) // 0 to maxVersionsPerKey inclusive
		for v := range numKeyVersions {
			randomIdx := rnd.Intn(len(signature_templates))
			version := &store.KeyVersionV3{
				Id:         globalVersionID,
				Version:    uint32(v),
				KeyId:      keyID,
				TemplateId: signature_templates[randomIdx],
			}
			versions = append(versions, version)
			lastVersionID = globalVersionID
			globalVersionID++
		}

		key.CurrentVersionId = lastVersionID
		keys = append(keys, key)
	}

	return keys, versions, nil
}

func generateKeysAndVersions(numKeys, versionsPerKey int) ([]*store.KeyV3, []*store.KeyVersionV3, error) {
	return generateKeysAndVersionsWithSeed(numKeys, versionsPerKey, time.Now().UnixNano())
}

// insertKeysAndVersions inserts the supplied keys first and then key versions.
// This insert path uses explicit foreign-key values via KeyVersionV3.KeyId.
func insertKeysAndVersions(db *gorm.DB, keys []*store.KeyV3, versions []*store.KeyVersionV3) error {
	if db == nil {
		return fmt.Errorf("db must not be nil")
	}
	const batchSize = 100
	if len(keys) > 0 {
		if err := db.CreateInBatches(&keys, batchSize).Error; err != nil {
			return fmt.Errorf("failed to insert keys: %w", err)
		}
	}

	if len(versions) > 0 {
		if err := db.CreateInBatches(&versions, batchSize).Error; err != nil {
			return fmt.Errorf("failed to insert versions: %w", err)
		}
	}

	return nil
}

// attachVersionsToKeys links versions to keys through in-memory association data.
func attachVersionsToKeys(keys []*store.KeyV3, versions []*store.KeyVersionV3) {
	byKeyID := make(map[string][]*store.KeyVersionV3, len(keys))
	for _, v := range versions {
		byKeyID[v.KeyId] = append(byKeyID[v.KeyId], v)
	}

	for _, k := range keys {
		k.Versions = byKeyID[k.PublicId]
	}
}

// insertKeysWithAssociatedVersions inserts keys and associated versions together.
// GORM persists the parent rows first, then child rows, and sets child foreign keys (key_id)
// from each KeyVersionV3.KeyId value (or from association linkage when configured) during insert.
func insertKeysWithAssociatedVersions(db *gorm.DB, keys []*store.KeyV3) error {
	if db == nil {
		return fmt.Errorf("db must not be nil")
	}
	if len(keys) == 0 {
		return nil
	}

	if err := db.Session(&gorm.Session{FullSaveAssociations: true}).Create(&keys).Error; err != nil {
		return fmt.Errorf("failed to insert keys with versions: %w", err)
	}

	return nil
}

// getKeyByPublicID fetches a key by its public id.
func getKeyByPublicID(db *gorm.DB, publicID string) (*store.KeyV3, error) {
	if db == nil {
		return nil, fmt.Errorf("db must not be nil")
	}

	var key store.KeyV3
	if err := db.Where("public_id = ?", publicID).First(&key).Error; err != nil {
		return nil, err
	}

	return &key, nil
}

func TestKeyV3AndKeyVersionV3_CRUDHelpers(t *testing.T) {
	db, dbPath, err := setupTemporarySQLiteDB("gorm2_test_main.sqlite")
	if err != nil {
		t.Fatalf("setupTemporarySQLiteDB failed: %v", err)
	}
	t.Cleanup(func() {
		_ = deleteTemporarySQLiteDB(dbPath)
	})

	if err := setupSchema(db); err != nil {
		t.Fatalf("setupSchema failed: %v", err)
	}

	keys, versions, err := generateKeysAndVersions(3, 4)
	if err != nil {
		t.Fatalf("generateKeysAndVersions failed: %v", err)
	}

	if err := insertKeysAndVersions(db, keys, versions); err != nil {
		t.Fatalf("insertKeysAndVersions failed: %v", err)
	}

	found, err := getKeyByPublicID(db, "key_001")
	if err != nil {
		t.Fatalf("getKeyByPublicID failed: %v", err)
	}
	if found.PublicId != "key_001" {
		t.Fatalf("unexpected key id: got %s", found.PublicId)
	}
	if found.CurrentVersionId != 8 {
		t.Fatalf("unexpected current version id: got %d want %d", found.CurrentVersionId, 8)
	}

	var versionCount int64
	if err := db.Model(&store.KeyVersionV3{}).Where("key_id = ?", "key_001").Count(&versionCount).Error; err != nil {
		t.Fatalf("count versions failed: %v", err)
	}
	if versionCount != 4 {
		t.Fatalf("unexpected version count: got %d want %d", versionCount, 4)
	}
}

func TestInsertWithAssociations(t *testing.T) {
	db, dbPath, err := setupTemporarySQLiteDB("gorm2_test_associations.sqlite")
	if err != nil {
		t.Fatalf("setupTemporarySQLiteDB failed: %v", err)
	}
	t.Cleanup(func() {
		_ = deleteTemporarySQLiteDB(dbPath)
	})

	if err := setupSchema(db); err != nil {
		t.Fatalf("setupSchema failed: %v", err)
	}

	keys, versions, err := generateKeysAndVersions(2, 3)
	if err != nil {
		t.Fatalf("generateKeysAndVersions failed: %v", err)
	}
	attachVersionsToKeys(keys, versions)

	if err := insertKeysWithAssociatedVersions(db, keys); err != nil {
		t.Fatalf("insertKeysWithAssociatedVersions failed: %v", err)
	}

	var loaded store.KeyV3
	if err := db.Where("public_id = ?", "key_000").First(&loaded).Error; err != nil {
		t.Fatalf("query with preload failed: %v", err)
	}
	if loaded.Versions != nil {
		t.Fatalf("unexpected non-nil versions slice: got %v want nil", loaded.Versions)
	}
	if len(loaded.Versions) != 0 {
		t.Fatalf("unexpected preloaded versions: got %d want %d", len(loaded.Versions), 3)
	}

	if err := db.Preload("Versions").Where("public_id = ?", "key_000").First(&loaded).Error; err != nil {
		t.Fatalf("query with preload failed: %v", err)
	}
	if len(loaded.Versions) != 3 {
		t.Fatalf("unexpected preloaded versions: got %d want %d", len(loaded.Versions), 3)
	}
}

// PopulateDatabase creates and migrates a SQLite DB file, then inserts synthetic keys/versions.
// It uses a fixed seed (1) so benchmark data is stable between runs.
func PopulateDatabase(numKeys, versionsPerKey int, filename string, b *testing.B) (*gorm.DB, string, error) {
	db, dbPath, err := setupTemporarySQLiteDB(filename)
	if err != nil {
		return nil, "", err
	}

	if err := setupSchema(db); err != nil {
		_ = deleteTemporarySQLiteDB(dbPath)
		return nil, "", err
	}

	keys, versions, err := generateKeysAndVersionsWithSeed(numKeys, versionsPerKey, 1)
	if err != nil {
		_ = deleteTemporarySQLiteDB(dbPath)
		return nil, "", err
	}
	b.Logf("Total number of key versions: %d", len(versions))

	if err := insertKeysAndVersions(db, keys, versions); err != nil {
		_ = deleteTemporarySQLiteDB(dbPath)
		return nil, "", err
	}

	return db, dbPath, nil
}

func benchmarkSQLiteFilename(prefix string) string {
	name := strings.ReplaceAll(prefix, "/", "_")
	name = strings.ReplaceAll(name, " ", "_")
	return fmt.Sprintf("%s.sqlite", name)
}

func tableName(db *gorm.DB, model any) (string, error) {
	stmt := &gorm.Statement{DB: db}
	if err := stmt.Parse(model); err != nil {
		return "", err
	}
	return stmt.Schema.Table, nil
}

type keyWithVersionRow struct {
	KeyPublicID         string `gorm:"column:key_public_id"`
	KeyCurrentVersionID uint32 `gorm:"column:key_current_version_id"`
	VersionID           uint32 `gorm:"column:version_id"`
	VersionNumber       uint32 `gorm:"column:version_number"`
	VersionKeyID        string `gorm:"column:version_key_id"`
	VersionTemplateID   string `gorm:"column:version_template_id"`
}

func rowsToKeys(rows []keyWithVersionRow) []*store.KeyV3 {
	keysByID := make(map[string]*store.KeyV3, len(rows))
	ordered := make([]*store.KeyV3, 0, len(rows))

	for _, row := range rows {
		k, ok := keysByID[row.KeyPublicID]
		if !ok {
			k = &store.KeyV3{
				PublicId:         row.KeyPublicID,
				CurrentVersionId: row.KeyCurrentVersionID,
			}
			keysByID[row.KeyPublicID] = k
			ordered = append(ordered, k)
		}

		if row.VersionKeyID == "" {
			continue
		}

		k.Versions = append(k.Versions, &store.KeyVersionV3{
			Id:         row.VersionID,
			Version:    row.VersionNumber,
			KeyId:      row.VersionKeyID,
			TemplateId: row.VersionTemplateID,
		})
	}

	return ordered
}

func loadKeysWithLeftJoin(db *gorm.DB, templateFilter string) ([]*store.KeyV3, error) {
	keyTable, err := tableName(db, &store.KeyV3{})
	if err != nil {
		return nil, err
	}
	versionTable, err := tableName(db, &store.KeyVersionV3{})
	if err != nil {
		return nil, err
	}

	join := fmt.Sprintf("LEFT JOIN %s v ON v.key_id = k.public_id", versionTable)
	args := []any{}
	if templateFilter != "" {
		join = fmt.Sprintf("%s AND v.template_id = ?", join)
		args = append(args, templateFilter)
	}

	var rows []keyWithVersionRow
	err = db.Table(fmt.Sprintf("%s k", keyTable)).
		Select([]string{
			"k.public_id AS key_public_id",
			"k.current_version_id AS key_current_version_id",
			"v.id AS version_id",
			"v.version AS version_number",
			"v.key_id AS version_key_id",
			"v.template_id AS version_template_id",
		}).
		Joins(join, args...).
		Order("k.public_id").
		Find(&rows).Error
	if err != nil {
		return nil, err
	}

	return rowsToKeys(rows), nil
}

func loadKeysWithInnerJoin(db *gorm.DB, templateFilter string) ([]*store.KeyV3, error) {
	keyTable, err := tableName(db, &store.KeyV3{})
	if err != nil {
		return nil, err
	}
	versionTable, err := tableName(db, &store.KeyVersionV3{})
	if err != nil {
		return nil, err
	}

	join := fmt.Sprintf("INNER JOIN %s v ON v.key_id = k.public_id", versionTable)
	args := []any{}
	if templateFilter != "" {
		join = fmt.Sprintf("%s AND v.template_id = ?", join)
		args = append(args, templateFilter)
	}

	var rows []keyWithVersionRow
	err = db.Table(fmt.Sprintf("%s k", keyTable)).
		Select([]string{
			"k.public_id AS key_public_id",
			"k.current_version_id AS key_current_version_id",
			"v.id AS version_id",
			"v.version AS version_number",
			"v.key_id AS version_key_id",
			"v.template_id AS version_template_id",
		}).
		Joins(join, args...).
		Order("k.public_id").
		Find(&rows).Error
	if err != nil {
		return nil, err
	}

	return rowsToKeys(rows), nil
}

const (
	benchmarkNumKeys           = 5
	benchmarkMaxVersionsPerKey = 1000
)

func BenchmarkLoadKeysWithPreload(b *testing.B) {
	db, dbPath, err := PopulateDatabase(benchmarkNumKeys, benchmarkMaxVersionsPerKey, benchmarkSQLiteFilename(b.Name()), b)
	if err != nil {
		b.Fatalf("PopulateDatabase failed: %v", err)
	}
	b.Cleanup(func() {
		_ = deleteTemporarySQLiteDB(dbPath)
	})

	for b.Loop() {
		var keys []*store.KeyV3
		if err := db.Preload("Versions").Find(&keys).Error; err != nil {
			b.Fatalf("Preload query failed: %v", err)
		}
	}
}

func BenchmarkLoadKeysWithLeftJoin(b *testing.B) {
	db, dbPath, err := PopulateDatabase(benchmarkNumKeys, benchmarkMaxVersionsPerKey, benchmarkSQLiteFilename(b.Name()), b)
	if err != nil {
		b.Fatalf("PopulateDatabase failed: %v", err)
	}
	b.Cleanup(func() {
		_ = deleteTemporarySQLiteDB(dbPath)
	})

	b.ResetTimer()
	for b.Loop() {
		if _, err := loadKeysWithLeftJoin(db, ""); err != nil {
			b.Fatalf("LEFT JOIN query failed: %v", err)
		}
	}
}

func BenchmarkLoadKeysWithInnerJoin(b *testing.B) {
	db, dbPath, err := PopulateDatabase(benchmarkNumKeys, benchmarkMaxVersionsPerKey, benchmarkSQLiteFilename(b.Name()), b)
	if err != nil {
		b.Fatalf("PopulateDatabase failed: %v", err)
	}
	b.Cleanup(func() {
		_ = deleteTemporarySQLiteDB(dbPath)
	})

	b.ResetTimer()
	for b.Loop() {
		if _, err := loadKeysWithInnerJoin(db, ""); err != nil {
			b.Fatalf("INNER JOIN query failed: %v", err)
		}
	}
}

func BenchmarkLoadKeysWithEd25519Preload(b *testing.B) {
	db, dbPath, err := PopulateDatabase(benchmarkNumKeys, benchmarkMaxVersionsPerKey, benchmarkSQLiteFilename(b.Name()), b)
	if err != nil {
		b.Fatalf("PopulateDatabase failed: %v", err)
	}
	b.Cleanup(func() {
		_ = deleteTemporarySQLiteDB(dbPath)
	})

	b.ResetTimer()
	for b.Loop() {
		var keys []*store.KeyV3
		if err := db.Preload("Versions", "template_id = ?", "Ed25519").Find(&keys).Error; err != nil {
			b.Fatalf("Preload filtered query failed: %v", err)
		}
	}
}

func BenchmarkLoadKeysWithEd25519LeftJoin(b *testing.B) {
	db, dbPath, err := PopulateDatabase(benchmarkNumKeys, benchmarkMaxVersionsPerKey, benchmarkSQLiteFilename(b.Name()), b)
	if err != nil {
		b.Fatalf("PopulateDatabase failed: %v", err)
	}
	b.Cleanup(func() {
		_ = deleteTemporarySQLiteDB(dbPath)
	})

	b.ResetTimer()
	for b.Loop() {
		if _, err := loadKeysWithLeftJoin(db, "Ed25519"); err != nil {
			b.Fatalf("LEFT JOIN filtered query failed: %v", err)
		}
	}
}

func BenchmarkLoadKeysWithEd25519InnerJoin(b *testing.B) {
	db, dbPath, err := PopulateDatabase(benchmarkNumKeys, benchmarkMaxVersionsPerKey, benchmarkSQLiteFilename(b.Name()), b)
	if err != nil {
		b.Fatalf("PopulateDatabase failed: %v", err)
	}
	b.Cleanup(func() {
		_ = deleteTemporarySQLiteDB(dbPath)
	})

	b.ResetTimer()
	for b.Loop() {
		if _, err := loadKeysWithInnerJoin(db, "Ed25519"); err != nil {
			b.Fatalf("INNER JOIN filtered query failed: %v", err)
		}
	}
}
