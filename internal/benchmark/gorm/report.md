# Loading associations in GORM

## 1. Associations

An association in GORM is a relationship between two model structs that maps to foreign-key relationships between database tables. Associations let you express and navigate relational data as Go objects.

Common association types:

- Belongs To
- Has One
- Has Many
- Many To Many

### Belongs To

A `belongs to` association means this model stores the foreign key pointing to another model.

```go
type Company struct {
    ID   uint `gorm:"primaryKey"`
    Name string
}

type User struct {
    ID        uint `gorm:"primaryKey"`
    Name      string
    CompanyID uint    
    Company   Company `gorm:"foreignKey:CompanyID"`
}
```

Notes:

- `users.company_id` references `companies.id`.
- Each `User` belongs to exactly one `Company` (logically).

### Has One

A `has one` association means the related model stores a foreign key pointing back to this model, and cardinality is one-to-one.

```go
type User struct {
    ID      uint `gorm:"primaryKey"`
    Name    string
    Profile Profile `gorm:"foreignKey:id"`
}

type Profile struct {
    ID     uint `gorm:"primaryKey"`
    UserID uint 
    Bio    string
}
```

Notes:

- `profiles.user_id` references `users.id`.
- Each `User` has at most one `Profile`.

### Has Many

A `has many` association means one parent row is linked to multiple child rows.

```go
type User struct {
    ID     uint `gorm:"primaryKey"`
    Name   string
    Orders []Order `gorm:"foreignKey:id"` // has many Orders
}

type Order struct {
    ID     uint `gorm:"primaryKey"`
    UserID uint 
    Amount int64
}
```

Notes:

- `orders.user_id` references `users.id`.
- One `User` can have many `Order` rows.

### Many To Many

A `many to many` association is represented through a join table containing foreign keys to both sides.

```go
type User struct {
    ID    uint `gorm:"primaryKey"`
    Name  string
    Roles []Role `gorm:"many2many:user_roles;"`
}

type Role struct {
    ID   uint `gorm:"primaryKey"`
    Name string
}
```

Notes:

- GORM uses `user_roles` as a join table.
- A `User` can have many `Role`s, and a `Role` can belong to many users.

## 2. Loading associations

Associations can be loaded mainly in two ways:

- Preload: eager loading with additional SQL queries.
- Join: SQL join(s) in one query result set.

### Preload

`Preload` loads parent rows first, then issues one or more additional queries for associations.

```go
var users []User
err := db.Preload("Orders").Find(&users).Error
```

Typical SQL pattern:

- `SELECT * FROM users`
- `SELECT * FROM orders WHERE user_id IN (...)`

Filtered preload example:

```go
err := db.Preload("Orders", "amount > ?", 100).Find(&users).Error
```

Characteristics:

- Multiple queries.
- Natural object graph hydration (`User{Orders: ...}`).
- Avoids duplicating parent columns per child row.

### Join

`Joins` loads data by combining tables in one SQL query.

```go
var users []User
err := db.Joins("LEFT JOIN orders ON orders.user_id = users.id").Find(&users).Error
```

Filtered join example:

```go
err := db.Joins("JOIN orders ON orders.user_id = users.id").
    Where("orders.amount > ?", 100).
    Find(&users).Error
```

Characteristics:

- Single query.
- Better for filtering/sorting/aggregating using associated table columns.
- Result rows are flattened and can duplicate parent data.

### Preload vs Join: key differences

- Query count:
  - Preload: usually 2+ queries.
  - Join: usually 1 query.
- Result shape:
  - Preload: parent and child loaded separately, then assembled.
  - Join: flat rows from SQL joins.
- Parent row duplication:
  - Preload: no parent duplication in SQL result.
  - Join: parent columns repeat once per matching child row.
- Best fit:
  - Preload: loading object graphs.
  - Join: relational filtering, ordering, and aggregation.

## 3. Performance tradeoffs

Rule of thumb:

- Use Preload for loading rich association graphs.
- Use Join for relational querying on associated data (filter/sort/group).

### Scenarios where Preload is often preferred

| Scenario | Why Preload is often better |
| --- | --- |
| Parent with many children (`has many`) | Avoids repeating parent columns for every child in one flat result |
| Multiple `has many` relationships loaded together | Prevents join row multiplication across associations |
| API response hydration | Simple and direct model graph assembly |
| Wide parent tables | Reduces duplicated parent payload transfer |

### Scenarios where Join is often preferred

| Scenario | Why Join is often better |
| --- | --- |
| Filter parents by child columns | Expresses predicates directly in SQL (`WHERE child...`) |
| Sort parents by child columns | Natural SQL ordering on joined tables |
| Aggregations and grouping | SQL `COUNT/SUM/GROUP BY` is straightforward with joins |
| Existence checks | Efficient `JOIN`/`EXISTS`-style relational constraints |

### Important benchmarking guidance

The performance of Join vs Preload is very dependent on the final use case. Benchmarks should be run for specific queries, comparing Preload and Join. When comparing, one should use projections and semantics equivalent.

In practice, ensure benchmark fairness by:

- Selecting equivalent columns on both approaches.
- Returning equivalent parent sets (`LEFT JOIN` semantics vs `INNER JOIN` semantics).
- Applying equivalent filters and association constraints.
- Measuring both time and result shape (parents loaded, children loaded).
