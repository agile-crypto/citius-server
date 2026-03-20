package gorm

import (
	"fmt"
	"strings"
	"testing"
)

const numRecords = 100000

func benchmarkSearchWithIntegralID(b *testing.B, n int, idFn func(i int) int) {
	db, dbPath, err := setupTemporarySQLiteDB("gorm_bench_integral_id.sqlite")
	if err != nil {
		b.Fatalf("setupTemporarySQLiteDB failed: %v", err)
	}
	b.Cleanup(func() {
		_ = deleteTemporarySQLiteDB(dbPath)
	})

	type Model struct {
		ID   uint `gorm:"primaryKey"`
		Name string
	}
	if err := setupSchemaFor(db, &Model{}); err != nil {
		b.Fatalf("setupSchema failed: %v", err)
	}

	records := make([]*Model, n)
	for i := range records {
		records[i] = &Model{
			ID:   uint(idFn(i)),
			Name: fmt.Sprintf("Record %d", idFn(i)),
		}
	}
	if err := db.CreateInBatches(&records, 1000).Error; err != nil {
		b.Fatalf("failed to create records: %v", err)
	}

	b.ResetTimer()
	id := 0
	for b.Loop() {
		var result Model
		if err := db.Where("id = ?", idFn(id)).First(&result).Error; err != nil {
			b.Fatalf("failed to find record: %v", err)
		}
		id = (id % n)
	}
}
func BenchmarkSearchWithIntegralID(b *testing.B) {
	idFn := func(i int) int {
		return i + 1
	}
	benchmarkSearchWithIntegralID(b, numRecords, idFn)
}

func BenchmarkSearchWithLargeIntegralID(b *testing.B) {
	start := 1 << 30
	idFn := func(i int) int {
		return i + start
	}
	benchmarkSearchWithIntegralID(b, numRecords, idFn)
}

func benchmarkSearchStringId(b *testing.B, n int, idValueFunc func(i int) string, benchmarkName string) {
	db, dbPath, err := setupTemporarySQLiteDB(benchmarkName + ".sqlite")
	if err != nil {
		b.Fatalf("setupTemporarySQLiteDB failed: %v", err)
	}
	b.Cleanup(func() {
		_ = deleteTemporarySQLiteDB(dbPath)
	})

	type Model struct {
		ID   string `gorm:"primaryKey"`
		Name string
	}
	if err := setupSchemaFor(db, &Model{}); err != nil {
		b.Fatalf("setupSchema failed: %v", err)
	}

	records := make([]*Model, n)
	for i := range records {
		records[i] = &Model{
			ID:   idValueFunc(i),
			Name: fmt.Sprintf("Record %d", i),
		}
	}
	if err := db.CreateInBatches(&records, 1000).Error; err != nil {
		b.Fatalf("failed to create records: %v", err)
	}

	b.ResetTimer()
	id := 0
	for b.Loop() {
		var result Model
		if err := db.Where("id = ?", idValueFunc(id)).First(&result).Error; err != nil {
			b.Fatalf("failed to find record: %v", err)
		}
		id = (id % n)
	}
}

func BenchmarkSearchWithIntStringID(b *testing.B) {
	idValueFunc := func(i int) string {
		return fmt.Sprintf("%d", i+1)
	}
	benchmarkSearchStringId(b, numRecords, idValueFunc, b.Name())
}

func BenchmarkSearchWithLargeIntStringID(b *testing.B) {
	start := 1 << 30
	idValueFunc := func(i int) string {
		return fmt.Sprintf("%d", i+start)
	}
	benchmarkSearchStringId(b, numRecords, idValueFunc, b.Name())
}

func BenchmarkSearchWithMidSizeStringID(b *testing.B) {
	prefix := strings.Repeat("x", 1000)
	idValueFunc := func(i int) string {
		return fmt.Sprintf("%s_%d", prefix, i+1)
	}
	benchmarkSearchStringId(b, numRecords, idValueFunc, b.Name())
}

func BenchmarkSearchWithLargeStringID(b *testing.B) {
	prefix := strings.Repeat("x", 10000)
	idValueFunc := func(i int) string {
		return fmt.Sprintf("%s_%d", prefix, i+1)
	}
	benchmarkSearchStringId(b, numRecords, idValueFunc, b.Name())
}
