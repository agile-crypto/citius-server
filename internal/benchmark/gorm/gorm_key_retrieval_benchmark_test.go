package gorm

import (
	"fmt"
	"strings"
	"testing"

	"gorm.io/gorm"
)

type Key struct {
	PublicID       string `gorm:"primaryKey"`
	CurrentVersion uint32
	Metadata       string
}

type KeyVersion struct {
	Version uint32 `gorm:"uniqueIndex:idx_key_version"`
	KeyId   string `gorm:"uniqueIndex:idx_key_version"`
}

type KeyVersionsWithPrimaryKey struct {
	ID      uint   `gorm:"primaryKey"`
	Version uint32 `gorm:"uniqueIndex:idx_key_version_pk"`
	KeyId   string `gorm:"uniqueIndex:idx_key_version_pk"`
}

type KeyWithRef struct {
	PublicID       string `gorm:"primaryKey"`
	CurrentVersion uint32
	Version        KeyVersionsWithPrimaryKey `gorm:"foreignKey:CurrentVersion;references:ID"`
}

const numKeys = 10000
const versionsPerKey = 25

var prefix string = strings.Repeat("x", 300)

func pkKeyId(id int) string {
	return fmt.Sprintf("%s_pk-key-%d", prefix, id)
}

func keyId(id int) string {
	return fmt.Sprintf("%s_key-%d", prefix, id)
}

func setupForBenchmarkVersionRetrieval(tb testing.TB) (db *gorm.DB) {
	db, dbPath, err := setupTemporarySQLiteDB(tb.Name() + ".sqlite")
	if err != nil {
		tb.Fatalf("setupTemporarySQLiteDB failed: %v", err)
	}
	tb.Cleanup(func() {
		_ = deleteTemporarySQLiteDB(dbPath)
	})

	models := []any{
		&KeyVersion{},
		&KeyVersionsWithPrimaryKey{},
		&Key{},
		&KeyWithRef{},
	}
	if err := setupSchemaFor(db, models...); err != nil {
		tb.Fatalf("setupSchema failed: %v", err)
	}

	// CurrentVersion --> version number
	keys := make([]*Key, numKeys)
	// CurrentVersion --> primary key ID of version
	keysWithPKRef := make([]*Key, numKeys)
	keysWithRef := make([]*KeyWithRef, numKeys)
	versions := make([]*KeyVersion, numKeys*versionsPerKey)
	versionsWithPK := make([]*KeyVersionsWithPrimaryKey, numKeys*versionsPerKey)
	vID := 1
	kID := 1
	for i := range keys {
		keys[i] = &Key{
			PublicID:       keyId(kID),
			CurrentVersion: versionsPerKey,
		}

		for v := range versionsPerKey {
			versionNum := uint32(v + 1)
			keyId := keys[i].PublicID
			versions[i*versionsPerKey+v] = &KeyVersion{
				Version: versionNum,
				KeyId:   keyId,
			}
			versionsWithPK[i*versionsPerKey+v] = &KeyVersionsWithPrimaryKey{
				ID:      uint(vID),
				Version: versionNum,
				KeyId:   pkKeyId(kID),
			}
			vID += 1
		}
		keysWithPKRef[i] = &Key{
			PublicID:       pkKeyId(kID),
			CurrentVersion: uint32(vID) - 1,
		}
		keysWithRef[i] = &KeyWithRef{
			PublicID:       pkKeyId(kID),
			CurrentVersion: uint32(vID) - 1,
		}
		kID += 1
	}

	if err := db.CreateInBatches(&keys, 1000).Error; err != nil {
		tb.Fatalf("failed to create keys: %v", err)
	}
	if err := db.CreateInBatches(&keysWithPKRef, 1000).Error; err != nil {
		tb.Fatalf("failed to create keys with PK ref: %v", err)
	}
	if err := db.CreateInBatches(&versions, 1000).Error; err != nil {
		tb.Fatalf("failed to create versions: %v", err)
	}
	if err := db.CreateInBatches(&versionsWithPK, 1000).Error; err != nil {
		tb.Fatalf("failed to create versions with PK: %v", err)
	}
	if err := db.CreateInBatches(&keysWithRef, 1000).Error; err != nil {
		tb.Fatalf("failed to create keys with ref: %v", err)
	}
	return db
}

func TestReduceJoinDataBySelectingOnlyNeededColumns(t *testing.T) {
	keyId := keyId(numKeys / 2)
	db := setupForBenchmarkVersionRetrieval(t)

	var result KeyVersion
	tx := db.Debug().
		Model(&Key{}).
		Select("public_id", "current_version").
		Where("public_id = ?", keyId).
		Joins("LEFT JOIN key_versions v ON v.key_id = keys.public_id AND v.version = keys.current_version").
		Select("v.key_id", "v.version").
		First(&result)
	if err := tx.Error; err != nil {
		t.Fatalf("failed to find record: %v", err)
	}
}

func BenchmarkVersionRetrievalByKeyIdAndVersionNumber(b *testing.B) {
	keyId := keyId(numKeys / 2)
	versionNum := uint32(versionsPerKey)
	db := setupForBenchmarkVersionRetrieval(b)

	b.ResetTimer()
	for b.Loop() {
		var result KeyVersion
		if err := db.Where("key_id = ? AND version = ?", keyId, versionNum).First(&result).Error; err != nil {
			b.Fatalf("failed to find record: %v", err)
		}
	}
}

func BenchmarkVersionRetrievalByPrimaryKeyWithJoins(b *testing.B) {
	keyId := pkKeyId(numKeys / 2)
	db := setupForBenchmarkVersionRetrieval(b)

	b.ResetTimer()
	for b.Loop() {
		var result KeyVersion
		tx := db.Model(&Key{}).
			Where("public_id = ?", keyId).
			Joins("LEFT JOIN key_versions_with_primary_keys v ON v.id = keys.current_version").
			Select("v.*").
			First(&result)
		if err := tx.Error; err != nil {
			b.Fatalf("failed to find record: %v", err)
		}
		if result.KeyId != keyId {
			b.Fatalf("unexpected key id: got %s, want %s", result.KeyId, keyId)
		}
	}
}

func BenchmarkVersionRetrievalByKeyIdAndVersionNumberWithJoins(b *testing.B) {
	keyId := keyId(numKeys / 2)
	db := setupForBenchmarkVersionRetrieval(b)

	b.ResetTimer()
	for b.Loop() {
		var result KeyVersion
		tx := db.Model(&Key{}).
			Where("public_id = ?", keyId).
			Joins("LEFT JOIN key_versions v ON v.key_id = keys.public_id AND v.version = keys.current_version").
			Select("v.*").
			First(&result)
		if err := tx.Error; err != nil {
			b.Fatalf("failed to find record: %v", err)
		}
		if result.KeyId != keyId {
			b.Fatalf("unexpected key id: got %s, want %s", result.KeyId, keyId)
		}
	}
}

func BenchmarkVersionRetrievalByPrimaryKeyTwoQueries(b *testing.B) {
	keyId := pkKeyId(numKeys / 2)
	db := setupForBenchmarkVersionRetrieval(b)

	b.ResetTimer()
	for b.Loop() {
		var key Key
		if err := db.Where("public_id = ?", keyId).First(&key).Error; err != nil {
			b.Fatalf("failed to find key: %v", err)
		}
		if key.PublicID != keyId {
			b.Fatalf("unexpected key id: got %s, want %s", key.PublicID, keyId)
		}

		var version KeyVersionsWithPrimaryKey
		if err := db.Where("id = ?", key.CurrentVersion).First(&version).Error; err != nil {
			b.Fatalf("failed to find version: %v", err)
		}
		if version.KeyId != keyId {
			b.Fatalf("unexpected key id in version: got %s, want %s", version.KeyId, keyId)
		}
	}
}

func BenchmarkVersionRetrievalByVersionNumberTwoQueries(b *testing.B) {
	keyId := keyId(numKeys / 2)
	db := setupForBenchmarkVersionRetrieval(b)

	b.ResetTimer()
	for b.Loop() {
		var key Key
		if err := db.Where("public_id = ?", keyId).First(&key).Error; err != nil {
			b.Fatalf("failed to find key: %v", err)
		}
		if key.PublicID != keyId {
			b.Fatalf("unexpected key id: got %s, want %s", key.PublicID, keyId)
		}

		var version KeyVersion
		if err := db.Where("key_id = ? AND version = ?", key.PublicID, key.CurrentVersion).First(&version).Error; err != nil {
			b.Fatalf("failed to find version: %v", err)
		}
		if version.KeyId != keyId {
			b.Fatalf("unexpected key id in version: got %s, want %s", version.KeyId, keyId)
		}
	}
}

func BenchmarkVersionRetrievalPreload(b *testing.B) {
	keyId := pkKeyId(numKeys / 2)
	db := setupForBenchmarkVersionRetrieval(b)

	b.ResetTimer()
	for b.Loop() {
		var result KeyWithRef
		tx := db.Preload("Version").Where("public_id = ?", keyId).First(&result)
		if err := tx.Error; err != nil {
			b.Fatalf("failed to find record: %v", err)
		}
		if result.PublicID != keyId {
			b.Fatalf("unexpected key id: got %s, want %s", result.PublicID, keyId)
		}
		if result.Version.KeyId != keyId {
			b.Fatalf("unexpected key id in version: got %s, want %s", result.Version.KeyId, keyId)
		}
	}
}
