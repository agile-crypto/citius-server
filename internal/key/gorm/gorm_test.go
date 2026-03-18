package gorm_test

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	storepb "github.ibm.com/citius/citius-server/gen/go/store"
	"google.golang.org/protobuf/types/known/timestamppb"
	"gorm.io/driver/sqlite"
	gormlib "gorm.io/gorm"
)

const (
	keyTableName        = "key_v2"
	keyVersionTableName = "key_version_v2"
)

type keyV2Record struct {
	PublicId           string               `gorm:"column:public_id;primaryKey"`
	KeyName            string               `gorm:"column:key_name;not null"`
	CreateTime         *time.Time           `gorm:"column:create_time"`
	UpdateTime         *time.Time           `gorm:"column:update_time"`
	DestroyTime        *time.Time           `gorm:"column:destroy_time"`
	Primitive          string               `gorm:"column:primitive;not null"`
	ScopeSpecification []byte               `gorm:"column:scope_specification;not null"`
	PolicyId           string               `gorm:"column:policy_id;not null"`
	Versions           []keyVersionV2Record `gorm:"foreignKey:KeyId;references:PublicId;constraint:OnUpdate:CASCADE,OnDelete:CASCADE"`
	CurrentVersionId   uint32               `gorm:"column:current_version_id;not null"`
	Labels             map[string]string    `gorm:"column:labels;serializer:json;type:text"`
}

func (keyV2Record) TableName() string {
	return keyTableName
}

type keyVersionV2Record struct {
	Id              uint32       `gorm:"column:id;primaryKey"`
	Version         uint32       `gorm:"column:version;not null;uniqueIndex:key_version_idx"`
	KeyId           string       `gorm:"column:key_id;not null;index;uniqueIndex:key_version_idx"`
	Key             *keyV2Record `gorm:"foreignKey:KeyId;references:PublicId"`
	CreateTime      *time.Time   `gorm:"column:create_time"`
	UpdateTime      *time.Time   `gorm:"column:update_time"`
	CtKeyMaterial   []byte       `gorm:"column:key_material;not null"`
	TemplateId      string       `gorm:"column:template_id;not null"`
	Digest          []byte       `gorm:"column:digest;not null"`
	DigestAlgorithm string       `gorm:"column:digest_algorithm;not null"`
	WrappingKeyId   string       `gorm:"column:wrapping_key_id;not null"`
	ProviderId      string       `gorm:"column:provider_id;not null"`
	Status          int32        `gorm:"column:status;not null"`
}

func (keyVersionV2Record) TableName() string {
	return keyVersionTableName
}

func setupTemporarySQLiteDatabase(filename string) (*gormlib.DB, string, error) {
	if filename == "" {
		return nil, "", errors.New("filename must not be empty")
	}

	dir, err := currentTestDirectory()
	if err != nil {
		return nil, "", err
	}

	dbPath := filepath.Join(dir, filename)
	file, err := os.Create(dbPath)
	if err != nil {
		return nil, "", fmt.Errorf("create sqlite file: %w", err)
	}
	if err := file.Close(); err != nil {
		return nil, "", fmt.Errorf("close sqlite file: %w", err)
	}

	db, err := gormlib.Open(sqlite.Open(dbPath), &gormlib.Config{})
	if err != nil {
		return nil, "", fmt.Errorf("open sqlite database: %w", err)
	}

	return db, dbPath, nil
}

func deleteSQLiteDatabase(filename string) error {
	if filename == "" {
		return errors.New("filename must not be empty")
	}

	dir, err := currentTestDirectory()
	if err != nil {
		return err
	}

	dbPath := filepath.Join(dir, filename)
	if err := os.Remove(dbPath); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("remove sqlite file: %w", err)
	}

	if walErr := os.Remove(dbPath + "-wal"); walErr != nil && !errors.Is(walErr, os.ErrNotExist) {
		return fmt.Errorf("remove sqlite wal file: %w", walErr)
	}
	if shmErr := os.Remove(dbPath + "-shm"); shmErr != nil && !errors.Is(shmErr, os.ErrNotExist) {
		return fmt.Errorf("remove sqlite shm file: %w", shmErr)
	}

	return nil
}

func migrateKeyTables(db *gormlib.DB) error {
	if db == nil {
		return errors.New("db must not be nil")
	}

	return db.AutoMigrate(&keyV2Record{}, &keyVersionV2Record{})
}

func buildKeysAndVersions(keyCount, versionsPerKey int) ([]*storepb.KeyV2, []*storepb.KeyVersionV2, error) {
	if keyCount < 0 {
		return nil, nil, errors.New("keyCount must be >= 0")
	}
	if versionsPerKey < 0 {
		return nil, nil, errors.New("versionsPerKey must be >= 0")
	}

	keys := make([]*storepb.KeyV2, 0, keyCount)
	versions := make([]*storepb.KeyVersionV2, 0, keyCount*versionsPerKey)

	var nextVersionID uint32 = 1
	for keyIndex := 0; keyIndex < keyCount; keyIndex++ {
		publicID := fmt.Sprintf("key_%03d", keyIndex)
		currentVersionID := uint32(0)
		if versionsPerKey > 0 {
			currentVersionID = nextVersionID + uint32(versionsPerKey) - 1
		}

		key := &storepb.KeyV2{
			PublicId:         publicID,
			CurrentVersionId: currentVersionID,
		}
		keys = append(keys, key)

		for versionIndex := 0; versionIndex < versionsPerKey; versionIndex++ {
			version := &storepb.KeyVersionV2{
				Id:      nextVersionID,
				Version: uint32(versionIndex),
				KeyId:   publicID,
			}
			versions = append(versions, version)
			nextVersionID++
		}
	}

	return keys, versions, nil
}

func populateKeyTables(db *gormlib.DB, keys []*storepb.KeyV2, versions []*storepb.KeyVersionV2) error {
	if db == nil {
		return errors.New("db must not be nil")
	}

	return db.Transaction(func(tx *gormlib.DB) error {
		if len(keys) > 0 {
			keyRows := make([]keyV2Record, 0, len(keys))
			for _, key := range keys {
				keyRows = append(keyRows, keyRecordFromProto(key))
			}
			if err := tx.Create(&keyRows).Error; err != nil {
				return fmt.Errorf("insert keys: %w", err)
			}
		}

		if len(versions) > 0 {
			versionRows := make([]keyVersionV2Record, 0, len(versions))
			for _, version := range versions {
				versionRows = append(versionRows, keyVersionRecordFromProto(version))
			}
			if err := tx.Create(&versionRows).Error; err != nil {
				return fmt.Errorf("insert versions: %w", err)
			}
		}

		return nil
	})
}

// populateKeyTablesWithAssociations stores keys and their Versions associations in one step.
// With GORM has-many relationships, the parent row is inserted first and the child rows are then
// created with their foreign-key column (`key_id`) set to the parent's primary key (`public_id`).
func populateKeyTablesWithAssociations(db *gormlib.DB, keys []*storepb.KeyV2) error {
	if db == nil {
		return errors.New("db must not be nil")
	}

	keyRows := make([]keyV2Record, 0, len(keys))
	for _, key := range keys {
		record := keyRecordFromProto(key)
		record.Versions = make([]keyVersionV2Record, 0, len(key.GetVersions()))
		for _, version := range key.GetVersions() {
			versionRow := keyVersionRecordFromProto(version)
			if versionRow.KeyId == "" {
				versionRow.KeyId = key.PublicId
			}
			record.Versions = append(record.Versions, versionRow)
		}
		keyRows = append(keyRows, record)
	}

	return db.Transaction(func(tx *gormlib.DB) error {
		if len(keyRows) == 0 {
			return nil
		}
		if err := tx.Create(&keyRows).Error; err != nil {
			return fmt.Errorf("insert keys with versions: %w", err)
		}
		return nil
	})
}

func attachVersionsToKeys(keys []*storepb.KeyV2, versions []*storepb.KeyVersionV2) []*storepb.KeyV2 {
	versionsByKey := make(map[string][]*storepb.KeyVersionV2, len(keys))
	for _, version := range versions {
		versionsByKey[version.GetKeyId()] = append(versionsByKey[version.GetKeyId()], version)
	}

	for _, key := range keys {
		key.Versions = versionsByKey[key.GetPublicId()]
	}

	return keys
}

func loadKeyByPublicID(db *gormlib.DB, publicID string) (*storepb.KeyV2, error) {
	if db == nil {
		return nil, errors.New("db must not be nil")
	}

	var row keyV2Record
	err := db.Preload("Versions", func(tx *gormlib.DB) *gormlib.DB {
		return tx.Order("version ASC")
	}).First(&row, "public_id = ?", publicID).Error
	if err != nil {
		return nil, err
	}

	return row.toProto(), nil
}

func currentTestDirectory() (string, error) {
	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		return "", errors.New("unable to resolve gorm_test.go path")
	}
	return filepath.Dir(filename), nil
}

func keyRecordFromProto(key *storepb.KeyV2) keyV2Record {
	if key == nil {
		return keyV2Record{}
	}

	return keyV2Record{
		PublicId:           key.GetPublicId(),
		KeyName:            key.GetKeyName(),
		CreateTime:         timestampToTimePtr(key.GetCreateTime()),
		UpdateTime:         timestampToTimePtr(key.GetUpdateTime()),
		DestroyTime:        timestampToTimePtr(key.GetDestroyTime()),
		Primitive:          key.GetPrimitive(),
		ScopeSpecification: normalizeBytes(key.GetScopeSpecification()),
		PolicyId:           key.GetPolicyId(),
		CurrentVersionId:   key.GetCurrentVersionId(),
		Labels:             cloneStringMap(key.GetLabels()),
	}
}

func keyVersionRecordFromProto(version *storepb.KeyVersionV2) keyVersionV2Record {
	if version == nil {
		return keyVersionV2Record{}
	}

	return keyVersionV2Record{
		Id:              version.GetId(),
		Version:         version.GetVersion(),
		KeyId:           version.GetKeyId(),
		CreateTime:      timestampToTimePtr(version.GetCreateTime()),
		UpdateTime:      timestampToTimePtr(version.GetUpdateTime()),
		CtKeyMaterial:   normalizeBytes(version.GetCtKeyMaterial()),
		TemplateId:      version.GetTemplateId(),
		Digest:          normalizeBytes(version.GetDigest()),
		DigestAlgorithm: version.GetDigestAlgorithm(),
		WrappingKeyId:   version.GetWrappingKeyId(),
		ProviderId:      version.GetProviderId(),
		Status:          int32(version.GetStatus()),
	}
}

func (record keyV2Record) toProto() *storepb.KeyV2 {
	versions := make([]*storepb.KeyVersionV2, 0, len(record.Versions))
	for _, version := range record.Versions {
		versions = append(versions, version.toProto())
	}

	return &storepb.KeyV2{
		PublicId:           record.PublicId,
		KeyName:            record.KeyName,
		CreateTime:         timeToTimestampPtr(record.CreateTime),
		UpdateTime:         timeToTimestampPtr(record.UpdateTime),
		DestroyTime:        timeToTimestampPtr(record.DestroyTime),
		Primitive:          record.Primitive,
		ScopeSpecification: normalizeBytes(record.ScopeSpecification),
		PolicyId:           record.PolicyId,
		Versions:           versions,
		CurrentVersionId:   record.CurrentVersionId,
		Labels:             cloneStringMap(record.Labels),
	}
}

func (record keyVersionV2Record) toProto() *storepb.KeyVersionV2 {
	return &storepb.KeyVersionV2{
		Id:              record.Id,
		Version:         record.Version,
		KeyId:           record.KeyId,
		CreateTime:      timeToTimestampPtr(record.CreateTime),
		UpdateTime:      timeToTimestampPtr(record.UpdateTime),
		CtKeyMaterial:   normalizeBytes(record.CtKeyMaterial),
		TemplateId:      record.TemplateId,
		Digest:          normalizeBytes(record.Digest),
		DigestAlgorithm: record.DigestAlgorithm,
		WrappingKeyId:   record.WrappingKeyId,
		ProviderId:      record.ProviderId,
		Status:          storepb.StatusV2(record.Status),
	}
}

func timestampToTimePtr(ts *timestamppb.Timestamp) *time.Time {
	if ts == nil {
		return nil
	}
	t := ts.AsTime()
	return &t
}

func timeToTimestampPtr(t *time.Time) *timestamppb.Timestamp {
	if t == nil {
		return nil
	}
	return timestamppb.New(*t)
}

func cloneStringMap(in map[string]string) map[string]string {
	if len(in) == 0 {
		return nil
	}

	out := make(map[string]string, len(in))
	for key, value := range in {
		out[key] = value
	}
	return out
}

func normalizeBytes(in []byte) []byte {
	if in == nil {
		return []byte{}
	}
	return append([]byte(nil), in...)
}

func TestPopulateAndQueryKeyByPublicID(t *testing.T) {
	const dbFilename = "gorm_key_v2_test.sqlite"

	db, _, err := setupTemporarySQLiteDatabase(dbFilename)
	if err != nil {
		t.Fatalf("setup sqlite database: %v", err)
	}
	t.Cleanup(func() {
		sqlDB, sqlErr := db.DB()
		if sqlErr == nil {
			_ = sqlDB.Close()
		}
		if removeErr := deleteSQLiteDatabase(dbFilename); removeErr != nil {
			t.Fatalf("delete sqlite database: %v", removeErr)
		}
	})

	if err := migrateKeyTables(db); err != nil {
		t.Fatalf("migrate schema: %v", err)
	}

	keys, versions, err := buildKeysAndVersions(2, 3)
	if err != nil {
		t.Fatalf("build dataset: %v", err)
	}

	if err := populateKeyTables(db, keys, versions); err != nil {
		t.Fatalf("populate tables: %v", err)
	}

	loadedKey, err := loadKeyByPublicID(db, "key_001")
	if err != nil {
		t.Fatalf("load key: %v", err)
	}

	if loadedKey.GetPublicId() != "key_001" {
		t.Fatalf("unexpected public id: %s", loadedKey.GetPublicId())
	}
	if loadedKey.GetCurrentVersionId() != 6 {
		t.Fatalf("unexpected current version id: %d", loadedKey.GetCurrentVersionId())
	}
	if len(loadedKey.GetVersions()) != 3 {
		t.Fatalf("unexpected version count: %d", len(loadedKey.GetVersions()))
	}
	for index, version := range loadedKey.GetVersions() {
		if version.GetVersion() != uint32(index) {
			t.Fatalf("unexpected version number at index %d: %d", index, version.GetVersion())
		}
		if version.GetKeyId() != loadedKey.GetPublicId() {
			t.Fatalf("unexpected version key id at index %d: %s", index, version.GetKeyId())
		}
	}
}

func TestPopulateWithAssociations(t *testing.T) {
	const dbFilename = "gorm_key_v2_assoc_test.sqlite"

	db, _, err := setupTemporarySQLiteDatabase(dbFilename)
	if err != nil {
		t.Fatalf("setup sqlite database: %v", err)
	}
	t.Cleanup(func() {
		sqlDB, sqlErr := db.DB()
		if sqlErr == nil {
			_ = sqlDB.Close()
		}
		if removeErr := deleteSQLiteDatabase(dbFilename); removeErr != nil {
			t.Fatalf("delete sqlite database: %v", removeErr)
		}
	})

	if err := migrateKeyTables(db); err != nil {
		t.Fatalf("migrate schema: %v", err)
	}

	keys, versions, err := buildKeysAndVersions(1, 2)
	if err != nil {
		t.Fatalf("build dataset: %v", err)
	}
	keys = attachVersionsToKeys(keys, versions)

	if err := populateKeyTablesWithAssociations(db, keys); err != nil {
		t.Fatalf("populate tables with associations: %v", err)
	}

	loadedKey, err := loadKeyByPublicID(db, "key_000")
	if err != nil {
		t.Fatalf("load key: %v", err)
	}

	if len(loadedKey.GetVersions()) != 2 {
		t.Fatalf("unexpected version count: %d", len(loadedKey.GetVersions()))
	}
	if loadedKey.GetVersions()[0].GetKeyId() != loadedKey.GetPublicId() {
		t.Fatalf("foreign key was not persisted correctly: got %s want %s", loadedKey.GetVersions()[0].GetKeyId(), loadedKey.GetPublicId())
	}
}
