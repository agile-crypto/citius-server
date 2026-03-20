package gorm

import (
	"context"
	"fmt"
	"math/rand"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/runtime/protoimpl"
	"gorm.io/driver/postgres"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

// Key represents a cryptographic key stored in the database
type KeyTest struct {
	state protoimpl.MessageState `protogen:"open.v1"`
	// @gotags: gorm:"primary_key"
	PublicId string `protobuf:"bytes,1,opt,name=public_id,json=publicId,proto3" json:"public_id,omitempty" gorm:"primary_key"`
	// @gotags: gorm:"not_null"
	KeyName string `protobuf:"bytes,2,opt,name=key_name,json=keyName,proto3" json:"key_name,omitempty" gorm:"not_null"`
	// @gotags: gorm:"not_null"
	Primitive string `protobuf:"bytes,3,opt,name=primitive,proto3" json:"primitive,omitempty" gorm:"not_null"`
	// @gotags: gorm:"not_null"
	ScopeSpecification []byte `protobuf:"bytes,4,opt,name=scope_specification,json=scopeSpecification,proto3" json:"scope_specification,omitempty" gorm:"not_null"`
	// @gotags: gorm:"not_null"
	PolicyId string `protobuf:"bytes,5,opt,name=policy_id,json=policyId,proto3" json:"policy_id,omitempty" gorm:"not_null"`
	// key's versions
	// @gotags: gorm:"foreignkey:key_id"
	Versions []*KeyVersionTest `protobuf:"bytes,6,rep,name=versions,proto3" json:"versions,omitempty" gorm:"foreignkey:key_id"`
	// id of the current version of the key
	// @gotags: gorm:"not_null"
	CurrentVersionId uint32 `protobuf:"varint,7,opt,name=current_version_id,json=currentVersionId,proto3" json:"current_version_id,omitempty" gorm:"not_null"`
	unknownFields    protoimpl.UnknownFields
	sizeCache        protoimpl.SizeCache
}

// Status enumerates the lifecycle statuses of a key
type KeyTestStatus int32

const (
	StatusV3_STATUSV3_UNSPECIFIED           KeyTestStatus = 0
	StatusV3_STATUSV3_ACTIVE                KeyTestStatus = 1
	StatusV3_STATUSV3_SUSPENDED             KeyTestStatus = 2
	StatusV3_STATUSV3_DESTROYED             KeyTestStatus = 3
	StatusV3_STATUSV3_PRE_ACTIVE            KeyTestStatus = 4
	StatusV3_STATUSV3_DEACTIVATED           KeyTestStatus = 5
	StatusV3_STATUSV3_COMPROMISED           KeyTestStatus = 6
	StatusV3_STATUSV3_DESTROYED_COMPROMISED KeyTestStatus = 7
)

// KeyVersion represents a version of a key with its material
type KeyVersionTest struct {
	state protoimpl.MessageState `protogen:"open.v1"`
	// @gotags: gorm:"primary_key"
	Id uint32 `protobuf:"varint,1,opt,name=id,proto3" json:"id,omitempty" gorm:"primary_key"`
	// version number
	// @gotags: gorm:"not_null;uniqueIndex:key_version_idx"
	Version uint32 `protobuf:"varint,2,opt,name=version,proto3" json:"version,omitempty" gorm:"not_null;uniqueIndex:key_version_idx"`
	// the public id of the key to which this version belongs
	// @gotags: gorm:"not_null,index;uniqueIndex:key_version_idx"
	KeyId string `protobuf:"bytes,3,opt,name=key_id,json=keyId,proto3" json:"key_id,omitempty" gorm:"not_null,index;uniqueIndex:key_version_idx"`
	// the key to which this version belongs
	// use GORM foreign key
	// @gotags: gorm:"foreignkey:KeyId"
	Key *KeyTest `protobuf:"bytes,4,opt,name=key,proto3" json:"key,omitempty" gorm:"foreignkey:KeyId"`
	// ciphertext key material stored in the database
	// @gotags: gorm:"column:key_material;not_null" wrapping:"ct,key_material"
	CtKeyMaterial []byte `protobuf:"bytes,5,opt,name=ct_key_material,json=ctKeyMaterial,proto3" json:"ct_key_material,omitempty" gorm:"column:key_material;not_null" wrapping:"ct,key_material"`
	// plain text version of the decrypted key material
	// we are NOT storing this plain-text key material in the db
	// @gotags: gorm:"-" wrapping:"pt,key_material"
	KeyMaterial []byte `protobuf:"bytes,6,opt,name=key_material,json=keyMaterial,proto3" json:"key_material,omitempty" gorm:"-" wrapping:"pt,key_material"`
	// Template associated with the key material
	// @gotags: gorm:"not_null"
	TemplateId string `protobuf:"bytes,7,opt,name=template_id,json=templateId,proto3" json:"template_id,omitempty" gorm:"not_null"`
	// digest used for integrity checks
	// @gotags: gorm:"not_null"
	Digest []byte `protobuf:"bytes,8,opt,name=digest,proto3" json:"digest,omitempty" gorm:"not_null"`
	// digest algorithm used to calculate the digest
	// @gotags: gorm:"not_null"
	DigestAlgorithm string `protobuf:"bytes,9,opt,name=digest_algorithm,json=digestAlgorithm,proto3" json:"digest_algorithm,omitempty" gorm:"not_null"`
	// id of the key used to encrypt the key material
	// @gotags: gorm:"not_null"
	WrappingKeyId string `protobuf:"bytes,10,opt,name=wrapping_key_id,json=wrappingKeyId,proto3" json:"wrapping_key_id,omitempty" gorm:"not_null"`
	// id of the provider where the key lives
	// @gotags: gorm:"not_null"
	ProviderId string `protobuf:"bytes,11,opt,name=provider_id,json=providerId,proto3" json:"provider_id,omitempty" gorm:"not_null"`
	// Lifecycle state of the key version
	// @gotags: gorm:"not_null"
	Status        KeyTestStatus `protobuf:"varint,12,opt,name=status,proto3,enum=caas.storage.v1.StatusV3" json:"status,omitempty" gorm:"not_null"`
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

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

const psUser = "postgres"
const psPassword = "postgres"
const psDBName = "postgres"
const containerPort = 5432

// openPostgreSQL connects to the postgres container from docker-compose.yml.
func openPostgreSQL(port int) (*gorm.DB, error) {
	dsn := fmt.Sprintf("host=localhost user=%s password=%s dbname=%s port=%d sslmode=disable TimeZone=UTC", psUser, psPassword, psDBName, port)

	var lastErr error
	for i := 0; i < 30; i++ {
		db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{})
		if err != nil {
			lastErr = err
			time.Sleep(500 * time.Millisecond)
			continue
		}

		sqlDB, err := db.DB()
		if err != nil {
			lastErr = err
			time.Sleep(500 * time.Millisecond)
			continue
		}

		if err := sqlDB.Ping(); err != nil {
			lastErr = err
			time.Sleep(500 * time.Millisecond)
			continue
		}

		return db, nil
	}

	return nil, fmt.Errorf("failed to connect to postgres after retries: %w", lastErr)
}

func startPostgreSQLContainer(image, containerName, volumeName string, port int) error {
	volumeCmd := exec.Command("docker", "volume", "create", volumeName)
	if out, err := volumeCmd.CombinedOutput(); err != nil {
		return fmt.Errorf("docker volume create failed: %w: %s", err, strings.TrimSpace(string(out)))
	}

	runCmd := exec.Command(
		"docker", "run", "-d",
		"--name", containerName,
		"--restart", "unless-stopped",
		"-e", fmt.Sprintf("POSTGRES_DB=%s", psDBName),
		"-e", fmt.Sprintf("POSTGRES_USER=%s", psUser),
		"-e", fmt.Sprintf("POSTGRES_PASSWORD=%s", psPassword),
		"-p", fmt.Sprintf("%d:%d", port, containerPort),
		"-v", fmt.Sprintf("%s:/var/lib/postgresql", volumeName),
		image,
	)
	if out, err := runCmd.CombinedOutput(); err != nil {
		outStr := strings.TrimSpace(string(out))
		if !strings.Contains(outStr, "already in use") {
			return fmt.Errorf("docker run failed: %w: %s", err, outStr)
		}
	}

	psCmd := exec.Command("sh", "-c", fmt.Sprintf("docker ps | grep %s", containerName))
	out, err := psCmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("docker ps check failed: %w: %s", err, strings.TrimSpace(string(out)))
	}

	line := strings.TrimSpace(string(out))
	if !strings.Contains(line, "Up") {
		return fmt.Errorf("container is not Up: %s", line)
	}

	return nil
}

func stopPostgreSQLContainer(containerName, volumeName string) error {
	stopCmd := exec.Command("docker", "stop", containerName)
	if out, err := stopCmd.CombinedOutput(); err != nil {
		outStr := strings.TrimSpace(string(out))
		if !strings.Contains(outStr, "No such container") {
			return fmt.Errorf("docker stop failed: %w: %s", err, outStr)
		}
	}

	rmCmd := exec.Command("docker", "rm", containerName)
	if out, err := rmCmd.CombinedOutput(); err != nil {
		outStr := strings.TrimSpace(string(out))
		if !strings.Contains(outStr, "No such container") {
			return fmt.Errorf("docker rm failed: %w: %s", err, outStr)
		}
	}

	volRmCmd := exec.Command("docker", "volume", "rm", volumeName)
	if out, err := volRmCmd.CombinedOutput(); err != nil {
		outStr := strings.TrimSpace(string(out))
		if !strings.Contains(outStr, "No such volume") {
			return fmt.Errorf("docker volume rm failed: %w: %s", err, outStr)
		}
	}

	return nil
}

func TestOpenPostgeSQL(t *testing.T) {
	name := "gorm_test_postgres"
	volume := "gorm_test_pgdata"
	image := "postgres"
	hostPort := 5433
	defer stopPostgreSQLContainer(name, volume)
	err := startPostgreSQLContainer(image, name, volume, hostPort)
	if err != nil {
		t.Fatalf("startPostgreSQLContainer failed: %v", err)
	}
	_, err = openPostgreSQL(containerPort)
	if err != nil {
		t.Fatalf("openPostgreSQL failed: %v", err)
	}
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
	if err := db.AutoMigrate(&KeyTest{}, &KeyVersionTest{}); err != nil {
		return fmt.Errorf("failed to migrate schema: %w", err)
	}
	return nil
}

func setupSchemaFor(db *gorm.DB, models ...interface{}) error {
	if db == nil {
		return fmt.Errorf("db must not be nil")
	}
	if err := db.AutoMigrate(models...); err != nil {
		return fmt.Errorf("failed to migrate schema: %w", err)
	}
	return nil
}

// generateKeysAndVersionsWithSeed creates N keys and M versions per key.
// For KeyV3, only PublicId and CurrentVersionId are set explicitly.
// For KeyVersionV3, only Id, Version, and KeyId are set explicitly.
func generateKeysAndVersionsWithSeed(numKeys, maxVersionsPerKey int, seed int64) ([]*KeyTest, []*KeyVersionTest, error) {
	if numKeys < 0 {
		return nil, nil, fmt.Errorf("numKeys must be >= 0")
	}
	if maxVersionsPerKey < 0 {
		return nil, nil, fmt.Errorf("maxVersionsPerKey must be >= 0")
	}

	rnd := rand.New(rand.NewSource(seed))
	keys := make([]*KeyTest, 0, numKeys)
	versions := make([]*KeyVersionTest, 0, numKeys*maxVersionsPerKey)
	signature_templates := []string{"ecdsa_p256_sha256", "Ed25519", "Ed448", "mldsa_65", "mldsa-87"}

	var globalVersionID uint32 = 1
	var lastVersionID uint32 = 0
	for k := range numKeys {
		keyID := fmt.Sprintf("key_%d", k)

		key := &KeyTest{
			PublicId: keyID,
		}

		numKeyVersions := rnd.Intn(maxVersionsPerKey + 1) // 0 to maxVersionsPerKey inclusive
		for v := range numKeyVersions {
			randomIdx := rnd.Intn(len(signature_templates))
			version := &KeyVersionTest{
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

func generateKeysAndVersions(numKeys, maxVersionsPerKey int) ([]*KeyTest, []*KeyVersionTest, error) {
	return generateKeysAndVersionsWithSeed(numKeys, maxVersionsPerKey, time.Now().UnixNano())
}

// insertKeysAndVersions inserts the supplied keys first and then key versions.
// This insert path uses explicit foreign-key values via KeyVersionV3.KeyId.
func insertKeysAndVersions(db *gorm.DB, keys []*KeyTest, versions []*KeyVersionTest) error {
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
func attachVersionsToKeys(keys []*KeyTest, versions []*KeyVersionTest) {
	byKeyID := make(map[string][]*KeyVersionTest, len(keys))
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
func insertKeysWithAssociatedVersions(db *gorm.DB, keys []*KeyTest) error {
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
func getKeyByPublicID(db *gorm.DB, publicID string) (*KeyTest, error) {
	if db == nil {
		return nil, fmt.Errorf("db must not be nil")
	}

	var key KeyTest
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

	found, err := getKeyByPublicID(db, "key_1")
	if err != nil {
		t.Fatalf("getKeyByPublicID failed: %v", err)
	}
	if found.PublicId != "key_1" {
		t.Fatalf("unexpected key id: got %s", found.PublicId)
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

	var loaded KeyTest
	if err := db.Where("public_id = ?", "key_0").First(&loaded).Error; err != nil {
		t.Fatalf("query with preload failed: %v", err)
	}
	if loaded.Versions != nil {
		t.Fatalf("unexpected non-nil versions slice: got %v want nil", loaded.Versions)
	}
	if len(loaded.Versions) != 0 {
		t.Fatalf("unexpected preloaded versions: got %d want %d", len(loaded.Versions), 3)
	}

	if err := db.Preload("Versions").Where("public_id = ?", "key_0").First(&loaded).Error; err != nil {
		t.Fatalf("query with preload failed: %v", err)
	}
	if loaded.Versions == nil {
		t.Fatalf("unexpected nil versions slice: got nil want non-nil")
	}
}

// PopulateDatabaseSQLite creates and migrates a SQLite DB file, then inserts synthetic keys/versions.
// It uses a fixed seed (1) so benchmark data is stable between runs.
func PopulateDatabaseSQLite(numKeys, versionsPerKey int, filename string, b *testing.B) (*gorm.DB, string, error) {
	db, dbPath, err := setupTemporarySQLiteDB(filename)
	if err != nil {
		return nil, "", err
	}

	err = PopulateDatabase(numKeys, versionsPerKey, db, b)
	if err != nil {
		_ = deleteTemporarySQLiteDB(dbPath)
		return nil, "", err
	}

	return db, dbPath, nil
}

// PopulateDatabase creates and migrates a SQLL DB, then inserts synthetic keys/versions.
// It uses a fixed seed (1) so benchmark data is stable between runs.
func PopulateDatabase(numKeys, versionsPerKey int, db *gorm.DB, b *testing.B) error {
	if err := setupSchema(db); err != nil {
		return err
	}

	keys, versions, err := generateKeysAndVersionsWithSeed(numKeys, versionsPerKey, 1)
	if err != nil {
		return err
	}
	b.Logf("Total number of key versions: %d", len(versions))

	if err := insertKeysAndVersions(db, keys, versions); err != nil {
		return err
	}

	return nil
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

func rowsToKeys(rows []keyWithVersionRow) []*KeyTest {
	keysByID := make(map[string]*KeyTest, len(rows))
	ordered := make([]*KeyTest, 0, len(rows))

	for _, row := range rows {
		k, ok := keysByID[row.KeyPublicID]
		if !ok {
			k = &KeyTest{
				PublicId:         row.KeyPublicID,
				CurrentVersionId: row.KeyCurrentVersionID,
			}
			keysByID[row.KeyPublicID] = k
			ordered = append(ordered, k)
		}

		if row.VersionKeyID == "" {
			continue
		}

		k.Versions = append(k.Versions, &KeyVersionTest{
			Id:         row.VersionID,
			Version:    row.VersionNumber,
			KeyId:      row.VersionKeyID,
			TemplateId: row.VersionTemplateID,
		})
	}

	return ordered
}

func loadKeysWithLeftJoin(db *gorm.DB, templateFilter string) ([]*KeyTest, error) {
	keyTable, err := tableName(db, &KeyTest{})
	if err != nil {
		return nil, err
	}
	versionTable, err := tableName(db, &KeyVersionTest{})
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

func loadKeysWithInnerJoin(db *gorm.DB, templateFilter string) ([]*KeyTest, error) {
	keyTable, err := tableName(db, &KeyTest{})
	if err != nil {
		return nil, err
	}
	versionTable, err := tableName(db, &KeyVersionTest{})
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

func countVersions(keys []*KeyTest) int {
	total := 0
	for _, k := range keys {
		total += len(k.Versions)
	}
	return total
}

func reportLoadedMetrics(b *testing.B, keys []*KeyTest) {
	b.ReportMetric(float64(len(keys)), "keys/op")
	b.ReportMetric(float64(countVersions(keys)), "versions/op")
}

const (
	benchmarkNumKeys           = 200
	benchmarkMaxVersionsPerKey = 1000
)

func benchmarkLoadKeysWithPreload(b *testing.B, nKeys int, maxVersionsPerKeys int, db *gorm.DB) {
	err := PopulateDatabase(nKeys, maxVersionsPerKeys, db, b)
	if err != nil {
		b.Fatalf("PopulateDatabase failed: %v", err)
	}

	for b.Loop() {
		var keys []*KeyTest
		if err := db.
			// Select("public_id", "current_version_id").
			// Preload("Versions", func(tx *gorm.DB) *gorm.DB {
			// 	return tx.Select("id", "version", "key_id", "template_id")
			// }).
			Preload("Versions").
			Find(&keys).Error; err != nil {
			b.Fatalf("Preload query failed: %v", err)
		}
		reportLoadedMetrics(b, keys)
	}
}

func BenchmarkLoadKeysWithPreloadSQLite(b *testing.B) {
	db, dbPath, err := setupTemporarySQLiteDB(benchmarkSQLiteFilename(b.Name()))
	if err != nil {
		b.Fatalf("Failed to setup temporary SQLite DB: %v", err)
	}
	b.Cleanup(func() {
		_ = deleteTemporarySQLiteDB(dbPath)
	})

	benchmarkLoadKeysWithPreload(b, benchmarkNumKeys, benchmarkMaxVersionsPerKey, db)
}

func BenchmarkLoadKeysWithPreloadPostgres(b *testing.B) {
	port := b.N%1000 + 5432
	err := startPostgreSQLContainer("postgres", b.Name(), b.Name(), port)
	if err != nil {
		b.Fatalf("Failed to setup temporary PostgreSQL DB: %v", err)
	}
	b.Cleanup(func() {
		_ = stopPostgreSQLContainer(b.Name(), b.Name())
	})
	waitTime := 2 * time.Second
	time.Sleep(waitTime)

	db, err := openPostgreSQL(port)
	if err != nil {
		b.Fatalf("Failed to open PostgreSQL DB: %v", err)
	}
	benchmarkLoadKeysWithPreload(b, benchmarkNumKeys, benchmarkMaxVersionsPerKey, db)
}

func benchmarkLoadKeysWithLeftJoin(b *testing.B, nKeys int, maxVersionsPerKeys int, db *gorm.DB) {
	err := PopulateDatabase(nKeys, maxVersionsPerKeys, db, b)
	if err != nil {
		b.Fatalf("PopulateDatabase failed: %v", err)
	}

	b.ResetTimer()
	for b.Loop() {
		keys, err := loadKeysWithLeftJoin(db, "")
		if err != nil {
			b.Fatalf("LEFT JOIN query failed: %v", err)
		}
		reportLoadedMetrics(b, keys)
	}
}
func BenchmarkLoadKeysWithLeftJoinSQLite(b *testing.B) {
	db, dbPath, err := setupTemporarySQLiteDB(benchmarkSQLiteFilename(b.Name()))
	if err != nil {
		b.Fatalf("Failed to setup temporary SQLite DB: %v", err)
	}
	b.Cleanup(func() {
		_ = deleteTemporarySQLiteDB(dbPath)
	})

	benchmarkLoadKeysWithLeftJoin(b, benchmarkNumKeys, benchmarkMaxVersionsPerKey, db)
}

func BenchmarkLoadKeysWithLeftJoinPostgres(b *testing.B) {
	port := b.N%1000 + 5432
	err := startPostgreSQLContainer("postgres", b.Name(), b.Name(), port)
	if err != nil {
		b.Fatalf("Failed to setup temporary PostgreSQL DB: %v", err)
	}
	b.Cleanup(func() {
		_ = stopPostgreSQLContainer(b.Name(), b.Name())
	})
	waitTime := 2 * time.Second
	time.Sleep(waitTime)

	db, err := openPostgreSQL(port)
	if err != nil {
		b.Fatalf("Failed to open PostgreSQL DB: %v", err)
	}
	benchmarkLoadKeysWithLeftJoin(b, benchmarkNumKeys, benchmarkMaxVersionsPerKey, db)
}
func BenchmarkLoadKeysWithInnerJoin(b *testing.B) {
	db, dbPath, err := PopulateDatabaseSQLite(benchmarkNumKeys, benchmarkMaxVersionsPerKey, benchmarkSQLiteFilename(b.Name()), b)
	if err != nil {
		b.Fatalf("PopulateDatabase failed: %v", err)
	}
	b.Cleanup(func() {
		_ = deleteTemporarySQLiteDB(dbPath)
	})

	b.ResetTimer()
	for b.Loop() {
		keys, err := loadKeysWithInnerJoin(db, "")
		if err != nil {
			b.Fatalf("INNER JOIN query failed: %v", err)
		}
		reportLoadedMetrics(b, keys)
	}
}

func BenchmarkLoadKeysWithEd25519Preload(b *testing.B) {
	db, dbPath, err := PopulateDatabaseSQLite(benchmarkNumKeys, benchmarkMaxVersionsPerKey, benchmarkSQLiteFilename(b.Name()), b)
	if err != nil {
		b.Fatalf("PopulateDatabase failed: %v", err)
	}
	b.Cleanup(func() {
		_ = deleteTemporarySQLiteDB(dbPath)
	})

	b.ResetTimer()
	for b.Loop() {
		var keys []*KeyTest
		if err := db.
			Select("public_id", "current_version_id").
			Preload("Versions", func(tx *gorm.DB) *gorm.DB {
				return tx.Select("id", "version", "key_id", "template_id").Where("template_id = ?", "Ed25519")
			}).
			Find(&keys).Error; err != nil {
			b.Fatalf("Preload filtered query failed: %v", err)
		}
		reportLoadedMetrics(b, keys)
	}
}

func BenchmarkLoadKeysWithEd25519LeftJoin(b *testing.B) {
	db, dbPath, err := PopulateDatabaseSQLite(benchmarkNumKeys, benchmarkMaxVersionsPerKey, benchmarkSQLiteFilename(b.Name()), b)
	if err != nil {
		b.Fatalf("PopulateDatabase failed: %v", err)
	}
	b.Cleanup(func() {
		_ = deleteTemporarySQLiteDB(dbPath)
	})

	b.ResetTimer()
	for b.Loop() {
		keys, err := loadKeysWithLeftJoin(db, "Ed25519")
		if err != nil {
			b.Fatalf("LEFT JOIN filtered query failed: %v", err)
		}
		reportLoadedMetrics(b, keys)
	}
}

func BenchmarkLoadKeysWithEd25519InnerJoin(b *testing.B) {
	db, dbPath, err := PopulateDatabaseSQLite(benchmarkNumKeys, benchmarkMaxVersionsPerKey, benchmarkSQLiteFilename(b.Name()), b)
	if err != nil {
		b.Fatalf("PopulateDatabase failed: %v", err)
	}
	b.Cleanup(func() {
		_ = deleteTemporarySQLiteDB(dbPath)
	})

	b.ResetTimer()
	for b.Loop() {
		keys, err := loadKeysWithInnerJoin(db, "Ed25519")
		if err != nil {
			b.Fatalf("INNER JOIN filtered query failed: %v", err)
		}
		reportLoadedMetrics(b, keys)
	}
}

func BenchmarkLoadAllVersionsOfKeyPreload(b *testing.B) {
	db, dbPath, err := PopulateDatabaseSQLite(benchmarkNumKeys, benchmarkMaxVersionsPerKey, benchmarkSQLiteFilename(b.Name()), b)
	if err != nil {
		b.Fatalf("PopulateDatabase failed: %v", err)
	}
	b.Cleanup(func() {
		_ = deleteTemporarySQLiteDB(dbPath)
	})

	i := rand.Intn(benchmarkNumKeys)
	keyId := fmt.Sprintf("key_%d", i)
	b.ResetTimer()
	for b.Loop() {
		var keys []*KeyTest
		if err := db.
			Where("public_id = ?", keyId).
			Preload("Versions").
			Find(&keys).Error; err != nil {
			b.Fatalf("Preload query failed: %v", err)
		}
		reportLoadedMetrics(b, keys)
	}
}

func BenchmarkLoadAllVersionsOfKeyLeftJoin(b *testing.B) {
	db, dbPath, err := PopulateDatabaseSQLite(benchmarkNumKeys, benchmarkMaxVersionsPerKey, benchmarkSQLiteFilename(b.Name()), b)
	if err != nil {
		b.Fatalf("PopulateDatabase failed: %v", err)
	}
	b.Cleanup(func() {
		_ = deleteTemporarySQLiteDB(dbPath)
	})

	i := rand.Intn(benchmarkNumKeys)
	keyId := fmt.Sprintf("key_%d", i)
	b.ResetTimer()

	for b.Loop() {
		var keys []*KeyTest
		var keyVersions []*KeyVersionTest
		if err := db.
			Where("public_id = ?", keyId).
			Find(&keys).Error; err != nil {
			b.Fatalf("Key query failed: %v", err)
		}

		if err := db.
			Where("key_id = ?", keyId).
			Find(&keyVersions).Error; err != nil {
			b.Fatalf("Preload query failed: %v", err)
		}
		keys[0].Versions = keyVersions
		reportLoadedMetrics(b, keys)
	}
}

func BenchmarkLoadAllVersionsOfKeyLeftJoinGenerics(b *testing.B) {
	db, dbPath, err := PopulateDatabaseSQLite(benchmarkNumKeys, benchmarkMaxVersionsPerKey, benchmarkSQLiteFilename(b.Name()), b)
	if err != nil {
		b.Fatalf("PopulateDatabase failed: %v", err)
	}
	b.Cleanup(func() {
		_ = deleteTemporarySQLiteDB(dbPath)
	})

	i := rand.Intn(benchmarkNumKeys)
	keyId := fmt.Sprintf("key_%d", i)
	b.ResetTimer()

	ctx := context.Background()
	for b.Loop() {
		var keys []*KeyTest
		var keyVersions []*KeyVersionTest
		keys, err := gorm.G[*KeyTest](db).Where("public_id = ?", keyId).Find(ctx)
		if err != nil {
			b.Fatalf("Key query failed: %v", err)
		}

		keyVersions, err = gorm.G[*KeyVersionTest](db).Where("key_id = ?", keyId).Find(ctx)
		if err != nil {
			b.Fatalf("Preload query failed: %v", err)
		}
		keys[0].Versions = keyVersions
		reportLoadedMetrics(b, keys)
	}
}

func BenchmarkLoadAllVersionsLeftJoinPreloading(b *testing.B) {
	db, dbPath, err := PopulateDatabaseSQLite(benchmarkNumKeys, benchmarkMaxVersionsPerKey, benchmarkSQLiteFilename(b.Name()), b)
	if err != nil {
		b.Fatalf("PopulateDatabase failed: %v", err)
	}
	b.Cleanup(func() {
		_ = deleteTemporarySQLiteDB(dbPath)
	})
	b.ResetTimer()

	ctx := context.Background()
	for b.Loop() {
		var keys []*KeyTest
		keys, err := gorm.G[*KeyTest](db).Joins(clause.JoinTarget{Association: "Versions"}, nil).Find(ctx)
		if err != nil {
			b.Fatalf("Key query failed: %v", err)
		}
		reportLoadedMetrics(b, keys)
	}
}

func ListModelAssociations(db *gorm.DB, models []any) (map[string][]string, error) {
	out := make(map[string][]string)

	for _, m := range models {
		stmt := &gorm.Statement{DB: db}
		if err := stmt.Parse(m); err != nil {
			return nil, err
		}

		modelName := stmt.Schema.Name
		for name, rel := range stmt.Schema.Relationships.Relations {
			constraints := rel.ParseConstraint()
			fks := "None"
			if constraints != nil {
				fks0 := make([]string, len(constraints.ForeignKeys))
				for i, fk := range constraints.ForeignKeys {
					fks0[i] = fk.Name
				}
				fks = fmt.Sprintf("%v", strings.Join(fks0, ", "))
			}
			line := fmt.Sprintf("%s (%s) fk=%v ref=%v",
				name, rel.Type, fks, rel.References)
			out[modelName] = append(out[modelName], line)
		}
	}
	return out, nil
}

func TestPrintModelAssociations(t *testing.T) {
	db, dbPath, err := setupTemporarySQLiteDB("gorm2_test_associations.sqlite")
	if err != nil {
		t.Fatalf("setupTemporarySQLiteDB failed: %v", err)
	}
	t.Cleanup(func() {
		_ = deleteTemporarySQLiteDB(dbPath)
	})

	type KeyBelongsTo struct {
		PublicId string `gorm:"primaryKey"`
	}

	type KeyVersionBelongsTo struct {
		Version uint32
		KeyId   string
		Key     *KeyBelongsTo `gorm:"foreignKey:KeyId"`
	}

	type KeyVersionHasMany struct {
		Id      uint32 `gorm:"primaryKey"`
		Version uint32
		KeyId   string
	}

	type KeyHasMany struct {
		PublicId string              `gorm:"primaryKey"`
		Versions []KeyVersionHasMany `gorm:"foreignKey:id"`
	}

	if err := setupSchemaFor(db, &KeyBelongsTo{}, &KeyVersionBelongsTo{}, &KeyVersionHasMany{}, &KeyHasMany{}); err != nil {
		t.Fatalf("setupSchema failed: %v", err)
	}

	assocs, err := ListModelAssociations(db, []any{
		&KeyBelongsTo{},
		&KeyVersionBelongsTo{},
		&KeyVersionHasMany{},
		&KeyHasMany{},
	})
	if err != nil {
		t.Fatalf("ListModelAssociations failed: %v", err)
	}

	res := make([]string, 0)
	for model, rels := range assocs {
		lines := []string{fmt.Sprintf("Model: %s", model)}
		for _, r := range rels {
			lines = append(lines, fmt.Sprintf("  %s", r))
		}
		res = append(res, strings.Join(lines, "\n"))
	}
	t.Logf("Model Associations:\n%s", strings.Join(res, "\n"))

}

type CompanyBelongsTo struct {
	ID   uint `gorm:"primaryKey"`
	Name string
}

type UserBelongsTo struct {
	ID        uint `gorm:"primaryKey"`
	Name      string
	CompanyID uint
	Company   CompanyBelongsTo `gorm:"foreignKey:CompanyID"`
}

type ProfileHasOne struct {
	ID     uint `gorm:"primaryKey"`
	UserID uint
	Bio    string
}

type UserHasOne struct {
	ID      uint `gorm:"primaryKey"`
	Name    string
	Profile ProfileHasOne `gorm:"foreignKey:id"`
}

type OrderHasMany struct {
	ID     uint `gorm:"primaryKey"`
	UserID uint
	Amount int64
}

type UserHasMany struct {
	ID     uint `gorm:"primaryKey"`
	Name   string
	Orders []OrderHasMany `gorm:"foreignKey:id"`
}

type RoleMany2Many struct {
	ID   uint `gorm:"primaryKey"`
	Name string
}

type UserMany2Many struct {
	ID    uint `gorm:"primaryKey"`
	Name  string
	Roles []RoleMany2Many `gorm:"many2many:user_roles;"`
}

func TestAssociationTypes(t *testing.T) {
	db, dbPath, err := setupTemporarySQLiteDB("gorm2_test_associations.sqlite")
	if err != nil {
		t.Fatalf("setupTemporarySQLiteDB failed: %v", err)
	}
	t.Cleanup(func() {
		_ = deleteTemporarySQLiteDB(dbPath)
	})

	models := []any{
		&CompanyBelongsTo{},
		&UserBelongsTo{},
		&ProfileHasOne{},
		&UserHasOne{},
		&OrderHasMany{},
		&UserHasMany{},
		&RoleMany2Many{},
		&UserMany2Many{},
	}
	if err := setupSchemaFor(db, models...); err != nil {
		t.Fatalf("setupSchema failed: %v", err)
	}

	assocs, err := ListModelAssociations(db, models)
	if err != nil {
		t.Fatalf("ListModelAssociations failed: %v", err)
	}

	res := make([]string, 0)
	for model, rels := range assocs {
		lines := []string{fmt.Sprintf("Model: %s", model)}
		for _, r := range rels {
			lines = append(lines, fmt.Sprintf("  %s", r))
		}
		res = append(res, strings.Join(lines, "\n"))
	}
	t.Logf("Model Associations:\n%s", strings.Join(res, "\n"))

}

func TestAtomicityOfAssociationUpdate(t *testing.T) {
	db, dbPath, err := setupTemporarySQLiteDB("gorm_test_atomicity.sqlite")
	if err != nil {
		t.Fatalf("setupTemporarySQLiteDB failed: %v", err)
	}
	t.Cleanup(func() {
		_ = deleteTemporarySQLiteDB(dbPath)
	})

	models := []any{
		&UserBelongsTo{},
		&CompanyBelongsTo{},
	}
	if err := setupSchemaFor(db, models...); err != nil {
		t.Fatalf("setupSchema failed: %v", err)
	}

	db0 := db.Session(&gorm.Session{})
	// db0 := db.Session(&gorm.Session{Logger: logger.Default.LogMode(logger.Info)})

	company := &CompanyBelongsTo{
		ID:   1,
		Name: "Test Company",
	}

	user1 := &UserBelongsTo{
		ID:        1,
		Name:      "Alice",
		CompanyID: company.ID,
		Company:   *company,
	}

	modifiedCompany := &CompanyBelongsTo{
		ID:   1,
		Name: "Modified Company",
	}

	user2 := &UserBelongsTo{
		ID:        2,
		Name:      "Bob",
		CompanyID: company.ID,
		Company:   *modifiedCompany,
	}

	if err := db0.Create(&user1).Error; err != nil {
		t.Fatalf("create user1 failed: %v", err)
	}

	var users []*UserBelongsTo
	if err := db0.Preload("Company").Find(&users).Error; err != nil {
		t.Fatalf("find users failed: %v", err)
	}
	if len(users) != 1 {
		t.Fatalf("unexpected user count: got %d want %d", len(users), 1)
	}
	if users[0].Company.Name != "Test Company" {
		t.Fatalf("unexpected company name after user1 insert: got %s want %s", users[0].Company.Name, "Test Company")
	}

	if err := db0.Create(&user2).Error; err != nil {
		t.Fatalf("create user2 failed: %v", err)
	}
	if err := db0.Preload("Company").Find(&users).Error; err != nil {
		t.Fatalf("find users failed: %v", err)
	}
	if len(users) != 2 {
		t.Fatalf("unexpected user count: got %d want %d", len(users), 2)
	}
	for _, u := range users {
		// Company is not updated by user2 insert
		if u.Company.Name != "Test Company" {
			t.Fatalf("unexpected company name after user2 insert: got %s want %s", u.Company.Name, "Test Company")
		}
	}
}

func TestAssociationLoading(t *testing.T) {
	db, dbPath, err := setupTemporarySQLiteDB("gorm_test_atomicity.sqlite")
	if err != nil {
		t.Fatalf("setupTemporarySQLiteDB failed: %v", err)
	}
	t.Cleanup(func() {
		_ = deleteTemporarySQLiteDB(dbPath)
	})

	models := []any{
		&UserBelongsTo{},
		&CompanyBelongsTo{},
	}
	if err := setupSchemaFor(db, models...); err != nil {
		t.Fatalf("setupSchema failed: %v", err)
	}

	companies := make([]*CompanyBelongsTo, 10)
	for i := range companies {
		companies[i] = &CompanyBelongsTo{
			ID:   uint(i + 1),
			Name: fmt.Sprintf("Company %d", i+1),
		}
	}
	users := make([]*UserBelongsTo, 100)
	for i := range users {
		users[i] = &UserBelongsTo{
			ID:        uint(i + 1),
			Name:      fmt.Sprintf("User %d", i+1),
			CompanyID: companies[i%len(companies)].ID,
		}
	}

	if err := db.Create(&companies).Error; err != nil {
		t.Fatalf("failed to create companies: %v", err)
	}
	if err := db.Create(&users).Error; err != nil {
		t.Fatalf("failed to create users: %v", err)
	}

	// Find all users associated with "Company 1"
	var foundUsers []UserBelongsTo
	err = db.Where("company_id = ?", 1).Find(&foundUsers).Error
	if err != nil {
		t.Fatalf("failed to find users for company: %v", err)
	}
	if len(foundUsers) != 10 {
		t.Fatalf("unexpected number of users found: got %d want %d", len(foundUsers), 10)
	}

}
