//! Database access layer with a rusqlite-compatible API over two backends:
//! SQLite (always) and PostgreSQL (`postgres` cargo feature).
//!
//! All SQL in the code base is written in SQLite dialect with `?N` placeholders.
//! On PostgreSQL the statement is translated (`pg::translate`) and parameters are
//! bound by the types the server infers (ms → TIMESTAMP(3), 0/1 → BOOLEAN, …);
//! result values are normalised back to the SQLite value model (timestamps as
//! integer ms, booleans as 0/1), so the same row-reading code serves both.
#[cfg(feature = "postgres")]
pub mod pg;

use std::cell::RefCell;

pub mod types {
    /// Owned SQL value (rusqlite's `types::Value` model).
    #[derive(Clone, Debug, PartialEq)]
    pub enum Value {
        Null,
        Integer(i64),
        Real(f64),
        Text(String),
        Blob(Vec<u8>),
    }

    /// Borrowed SQL value.
    #[derive(Clone, Copy, Debug, PartialEq)]
    pub enum ValueRef<'a> {
        Null,
        Integer(i64),
        Real(f64),
        Text(&'a [u8]),
        Blob(&'a [u8]),
    }

    impl Value {
        pub fn as_ref(&self) -> ValueRef<'_> {
            match self {
                Value::Null => ValueRef::Null,
                Value::Integer(i) => ValueRef::Integer(*i),
                Value::Real(f) => ValueRef::Real(*f),
                Value::Text(s) => ValueRef::Text(s.as_bytes()),
                Value::Blob(b) => ValueRef::Blob(b),
            }
        }
    }

    impl From<String> for Value {
        fn from(v: String) -> Self {
            Value::Text(v)
        }
    }
    impl From<&str> for Value {
        fn from(v: &str) -> Self {
            Value::Text(v.to_string())
        }
    }
    impl From<i64> for Value {
        fn from(v: i64) -> Self {
            Value::Integer(v)
        }
    }
    impl From<i32> for Value {
        fn from(v: i32) -> Self {
            Value::Integer(v as i64)
        }
    }
    impl From<bool> for Value {
        fn from(v: bool) -> Self {
            Value::Integer(v as i64)
        }
    }
    impl From<f64> for Value {
        fn from(v: f64) -> Self {
            Value::Real(v)
        }
    }
    impl From<Vec<u8>> for Value {
        fn from(v: Vec<u8>) -> Self {
            Value::Blob(v)
        }
    }
    impl<T: Into<Value>> From<Option<T>> for Value {
        fn from(v: Option<T>) -> Self {
            v.map(Into::into).unwrap_or(Value::Null)
        }
    }

    impl ValueRef<'_> {
        pub fn to_owned(&self) -> Value {
            match *self {
                ValueRef::Null => Value::Null,
                ValueRef::Integer(i) => Value::Integer(i),
                ValueRef::Real(f) => Value::Real(f),
                ValueRef::Text(t) => Value::Text(String::from_utf8_lossy(t).into_owned()),
                ValueRef::Blob(b) => Value::Blob(b.to_vec()),
            }
        }
    }

    /// A value that can be bound as a statement parameter.
    pub trait ToSql {
        fn to_sql(&self) -> ValueRef<'_>;
    }

    macro_rules! int_to_sql {
        ($($t:ty),*) => {$(
            impl ToSql for $t {
                fn to_sql(&self) -> ValueRef<'_> {
                    ValueRef::Integer(*self as i64)
                }
            }
        )*};
    }
    int_to_sql!(i8, i16, i32, i64, u8, u16, u32, u64, usize, isize);

    impl ToSql for bool {
        fn to_sql(&self) -> ValueRef<'_> {
            ValueRef::Integer(*self as i64)
        }
    }
    impl ToSql for f64 {
        fn to_sql(&self) -> ValueRef<'_> {
            ValueRef::Real(*self)
        }
    }
    impl ToSql for f32 {
        fn to_sql(&self) -> ValueRef<'_> {
            ValueRef::Real(*self as f64)
        }
    }
    impl ToSql for str {
        fn to_sql(&self) -> ValueRef<'_> {
            ValueRef::Text(self.as_bytes())
        }
    }
    impl ToSql for String {
        fn to_sql(&self) -> ValueRef<'_> {
            ValueRef::Text(self.as_bytes())
        }
    }
    impl ToSql for [u8] {
        fn to_sql(&self) -> ValueRef<'_> {
            ValueRef::Blob(self)
        }
    }
    impl ToSql for Vec<u8> {
        fn to_sql(&self) -> ValueRef<'_> {
            ValueRef::Blob(self)
        }
    }
    impl ToSql for bytes::Bytes {
        fn to_sql(&self) -> ValueRef<'_> {
            ValueRef::Blob(self)
        }
    }
    impl ToSql for Value {
        fn to_sql(&self) -> ValueRef<'_> {
            self.as_ref()
        }
    }
    impl<T: ToSql + ?Sized> ToSql for &T {
        fn to_sql(&self) -> ValueRef<'_> {
            (**self).to_sql()
        }
    }
    impl<T: ToSql + ?Sized> ToSql for Box<T> {
        fn to_sql(&self) -> ValueRef<'_> {
            (**self).to_sql()
        }
    }
    impl<T: ToSql> ToSql for Option<T> {
        fn to_sql(&self) -> ValueRef<'_> {
            match self {
                Some(v) => v.to_sql(),
                None => ValueRef::Null,
            }
        }
    }
    impl ToSql for std::borrow::Cow<'_, str> {
        fn to_sql(&self) -> ValueRef<'_> {
            ValueRef::Text(self.as_bytes())
        }
    }
}

pub use types::{ToSql, Value, ValueRef};

// ---------------------------------------------------------------------------
// Errors

#[derive(Debug)]
pub enum Error {
    Sqlite(rusqlite::Error),
    #[cfg(feature = "postgres")]
    Postgres(postgres::Error),
    QueryReturnedNoRows,
    InvalidColumnType(String),
    InvalidColumnIndex(String),
    Other(String),
}

pub type Result<T, E = Error> = std::result::Result<T, E>;

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Sqlite(e) => write!(f, "{e}"),
            #[cfg(feature = "postgres")]
            Error::Postgres(e) => match e.as_db_error() {
                Some(db) => write!(f, "{}: {}", db.code().code(), db.message()),
                None => write!(f, "{e}"),
            },
            Error::QueryReturnedNoRows => f.write_str("Query returned no rows"),
            Error::InvalidColumnType(m) => write!(f, "Invalid column type: {m}"),
            Error::InvalidColumnIndex(m) => write!(f, "Invalid column index: {m}"),
            Error::Other(m) => f.write_str(m),
        }
    }
}
impl std::error::Error for Error {}

impl From<rusqlite::Error> for Error {
    fn from(e: rusqlite::Error) -> Self {
        match e {
            rusqlite::Error::QueryReturnedNoRows => Error::QueryReturnedNoRows,
            other => Error::Sqlite(other),
        }
    }
}

#[cfg(feature = "postgres")]
impl From<postgres::Error> for Error {
    fn from(e: postgres::Error) -> Self {
        Error::Postgres(e)
    }
}

impl Error {
    /// UNIQUE / PRIMARY KEY violation (Prisma P2002).
    pub fn is_unique_violation(&self) -> bool {
        match self {
            Error::Sqlite(rusqlite::Error::SqliteFailure(e, _)) => {
                e.extended_code == rusqlite::ffi::SQLITE_CONSTRAINT_UNIQUE
                    || e.extended_code == rusqlite::ffi::SQLITE_CONSTRAINT_PRIMARYKEY
            }
            #[cfg(feature = "postgres")]
            Error::Postgres(e) => e.code() == Some(&postgres::error::SqlState::UNIQUE_VIOLATION),
            _ => false,
        }
    }
    /// "no such table" / undefined table.
    pub fn is_missing_table(&self) -> bool {
        match self {
            Error::Sqlite(e) => e.to_string().contains("no such table"),
            #[cfg(feature = "postgres")]
            Error::Postgres(e) => e.code() == Some(&postgres::error::SqlState::UNDEFINED_TABLE),
            _ => false,
        }
    }
}

pub trait OptionalExtension<T> {
    fn optional(self) -> Result<Option<T>>;
}

impl<T> OptionalExtension<T> for Result<T> {
    fn optional(self) -> Result<Option<T>> {
        match self {
            Ok(v) => Ok(Some(v)),
            Err(Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(e),
        }
    }
}

// ---------------------------------------------------------------------------
// Parameters

pub trait Params {
    fn values(&self) -> Vec<ValueRef<'_>>;
}

impl Params for () {
    fn values(&self) -> Vec<ValueRef<'_>> {
        vec![]
    }
}
impl Params for &[&dyn ToSql] {
    fn values(&self) -> Vec<ValueRef<'_>> {
        self.iter().map(|p| p.to_sql()).collect()
    }
}
impl Params for [&dyn ToSql; 0] {
    fn values(&self) -> Vec<ValueRef<'_>> {
        vec![]
    }
}
macro_rules! array_params {
    ($($n:literal),*) => {$(
        impl<T: ToSql> Params for [T; $n] {
            fn values(&self) -> Vec<ValueRef<'_>> {
                self.iter().map(|p| p.to_sql()).collect()
            }
        }
        impl<T: ToSql> Params for &[T; $n] {
            fn values(&self) -> Vec<ValueRef<'_>> {
                self.iter().map(|p| p.to_sql()).collect()
            }
        }
    )*};
}
array_params!(1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16);
impl Params for Vec<&dyn ToSql> {
    fn values(&self) -> Vec<ValueRef<'_>> {
        self.iter().map(|p| p.to_sql()).collect()
    }
}
impl Params for &Vec<&dyn ToSql> {
    fn values(&self) -> Vec<ValueRef<'_>> {
        self.iter().map(|p| p.to_sql()).collect()
    }
}

/// rusqlite::params_from_iter
pub struct ParamsFromIter<T>(Vec<T>);

pub fn params_from_iter<I>(iter: I) -> ParamsFromIter<I::Item>
where
    I: IntoIterator,
    I::Item: ToSql,
{
    ParamsFromIter(iter.into_iter().collect())
}

impl<T: ToSql> Params for ParamsFromIter<T> {
    fn values(&self) -> Vec<ValueRef<'_>> {
        self.0.iter().map(|p| p.to_sql()).collect()
    }
}

#[macro_export]
macro_rules! sql_params {
    () => { &[] as &[&dyn $crate::sql::ToSql] };
    ($($p:expr),+ $(,)?) => { &[$(&$p as &dyn $crate::sql::ToSql),+] as &[&dyn $crate::sql::ToSql] };
}
pub use crate::sql_params as params;

fn sqlite_params<'a>(values: &'a [ValueRef<'a>]) -> impl rusqlite::Params + 'a {
    rusqlite::params_from_iter(values.iter().map(|v| {
        rusqlite::types::ToSqlOutput::Borrowed(match *v {
            ValueRef::Null => rusqlite::types::ValueRef::Null,
            ValueRef::Integer(i) => rusqlite::types::ValueRef::Integer(i),
            ValueRef::Real(f) => rusqlite::types::ValueRef::Real(f),
            ValueRef::Text(t) => rusqlite::types::ValueRef::Text(t),
            ValueRef::Blob(b) => rusqlite::types::ValueRef::Blob(b),
        })
    }))
}

// ---------------------------------------------------------------------------
// Rows

pub trait RowIndex {
    fn idx(&self, names: &dyn Fn(&str) -> Option<usize>) -> Result<usize>;
}
impl RowIndex for usize {
    fn idx(&self, _: &dyn Fn(&str) -> Option<usize>) -> Result<usize> {
        Ok(*self)
    }
}
impl RowIndex for &str {
    fn idx(&self, names: &dyn Fn(&str) -> Option<usize>) -> Result<usize> {
        names(self).ok_or_else(|| Error::InvalidColumnIndex(self.to_string()))
    }
}

pub trait FromSql: Sized {
    fn from_sql(v: ValueRef<'_>) -> Result<Self>;
}

fn type_err(want: &str, v: ValueRef<'_>) -> Error {
    Error::InvalidColumnType(format!("expected {want}, got {v:?}"))
}

impl FromSql for i64 {
    fn from_sql(v: ValueRef<'_>) -> Result<Self> {
        match v {
            ValueRef::Integer(i) => Ok(i),
            other => Err(type_err("integer", other)),
        }
    }
}
macro_rules! int_from_sql {
    ($($t:ty),*) => {$(
        impl FromSql for $t {
            fn from_sql(v: ValueRef<'_>) -> Result<Self> {
                let i = i64::from_sql(v)?;
                <$t>::try_from(i).map_err(|_| Error::InvalidColumnType(format!("integer {i} out of range")))
            }
        }
    )*};
}
int_from_sql!(i32, u32, u64, usize, i16, u16, u8, i8);
impl FromSql for bool {
    fn from_sql(v: ValueRef<'_>) -> Result<Self> {
        Ok(i64::from_sql(v)? != 0)
    }
}
impl FromSql for f64 {
    fn from_sql(v: ValueRef<'_>) -> Result<Self> {
        match v {
            ValueRef::Real(f) => Ok(f),
            ValueRef::Integer(i) => Ok(i as f64),
            other => Err(type_err("real", other)),
        }
    }
}
impl FromSql for String {
    fn from_sql(v: ValueRef<'_>) -> Result<Self> {
        match v {
            ValueRef::Text(t) => String::from_utf8(t.to_vec()).map_err(|e| Error::Other(e.to_string())),
            other => Err(type_err("text", other)),
        }
    }
}
impl FromSql for Vec<u8> {
    fn from_sql(v: ValueRef<'_>) -> Result<Self> {
        match v {
            ValueRef::Blob(b) | ValueRef::Text(b) => Ok(b.to_vec()),
            other => Err(type_err("blob", other)),
        }
    }
}
impl FromSql for Value {
    fn from_sql(v: ValueRef<'_>) -> Result<Self> {
        Ok(v.to_owned())
    }
}
impl<T: FromSql> FromSql for Option<T> {
    fn from_sql(v: ValueRef<'_>) -> Result<Self> {
        match v {
            ValueRef::Null => Ok(None),
            other => T::from_sql(other).map(Some),
        }
    }
}

pub enum Row<'r> {
    Sqlite(&'r rusqlite::Row<'r>),
    Owned(Vec<Value>, std::rc::Rc<Vec<String>>),
    #[cfg(feature = "postgres")]
    Pg(&'r postgres::Row),
}

impl<'r> Row<'r> {
    fn index(&self, idx: impl RowIndex) -> Result<usize> {
        match self {
            Row::Sqlite(r) => idx.idx(&|n| r.as_ref().column_index(n).ok()),
            Row::Owned(_, names) => idx.idx(&|n| names.iter().position(|c| c == n)),
            #[cfg(feature = "postgres")]
            Row::Pg(r) => idx.idx(&|n| r.columns().iter().position(|c| c.name() == n)),
        }
    }

    pub fn get_ref(&self, idx: impl RowIndex) -> Result<ValueRef<'_>> {
        let i = self.index(idx)?;
        match self {
            Row::Sqlite(r) => Ok(match r.get_ref(i)? {
                rusqlite::types::ValueRef::Null => ValueRef::Null,
                rusqlite::types::ValueRef::Integer(v) => ValueRef::Integer(v),
                rusqlite::types::ValueRef::Real(v) => ValueRef::Real(v),
                rusqlite::types::ValueRef::Text(v) => ValueRef::Text(v),
                rusqlite::types::ValueRef::Blob(v) => ValueRef::Blob(v),
            }),
            Row::Owned(v, _) => v.get(i).map(Value::as_ref).ok_or_else(|| Error::InvalidColumnIndex(i.to_string())),
            #[cfg(feature = "postgres")]
            Row::Pg(r) => pg::value_ref(r, i),
        }
    }

    pub fn get<I: RowIndex, T: FromSql>(&self, idx: I) -> Result<T> {
        T::from_sql(self.get_ref(idx)?)
    }

    pub fn column_count(&self) -> usize {
        match self {
            Row::Sqlite(r) => r.as_ref().column_count(),
            Row::Owned(v, _) => v.len(),
            #[cfg(feature = "postgres")]
            Row::Pg(r) => r.len(),
        }
    }

    pub fn column_name(&self, i: usize) -> String {
        match self {
            Row::Sqlite(r) => r.as_ref().column_name(i).map(str::to_string).unwrap_or_default(),
            Row::Owned(_, names) => names.get(i).cloned().unwrap_or_default(),
            #[cfg(feature = "postgres")]
            Row::Pg(r) => r.columns().get(i).map(|c| c.name().to_string()).unwrap_or_default(),
        }
    }
}

// ---------------------------------------------------------------------------
// Connection

pub enum SqliteHandle {
    Pooled(r2d2::PooledConnection<r2d2_sqlite::SqliteConnectionManager>),
    Owned(rusqlite::Connection),
}

impl std::ops::Deref for SqliteHandle {
    type Target = rusqlite::Connection;
    fn deref(&self) -> &rusqlite::Connection {
        match self {
            SqliteHandle::Pooled(c) => c,
            SqliteHandle::Owned(c) => c,
        }
    }
}

enum Inner {
    Sqlite(SqliteHandle),
    #[cfg(feature = "postgres")]
    Pg(RefCell<pg::PgConn>),
}

pub struct Connection {
    inner: Inner,
    #[allow(dead_code)]
    marker: std::marker::PhantomData<RefCell<()>>,
}

#[derive(Clone, Copy, Debug)]
pub enum TransactionBehavior {
    Deferred,
    Immediate,
    Exclusive,
}

impl Connection {
    pub fn from_sqlite(h: SqliteHandle) -> Connection {
        Connection { inner: Inner::Sqlite(h), marker: Default::default() }
    }

    #[cfg(feature = "postgres")]
    pub fn from_pg(c: pg::PgConn) -> Connection {
        Connection { inner: Inner::Pg(RefCell::new(c)), marker: Default::default() }
    }

    /// Open a SQLite file (tests, tools).
    pub fn open(path: impl AsRef<std::path::Path>) -> Result<Connection> {
        Ok(Self::from_sqlite(SqliteHandle::Owned(rusqlite::Connection::open(path)?)))
    }

    pub fn open_in_memory() -> Result<Connection> {
        Ok(Self::from_sqlite(SqliteHandle::Owned(rusqlite::Connection::open_in_memory()?)))
    }

    /// Open by database URL (`file:` or, with the feature, `postgresql://`).
    pub fn open_url(url: &str) -> Result<Connection> {
        if let Some(path) = url.strip_prefix("file:") {
            return Self::open(path.split('?').next().unwrap_or(path));
        }
        #[cfg(feature = "postgres")]
        if pg::is_postgres_url(url) {
            return Ok(Self::from_pg(pg::PgConn::connect(url)?));
        }
        Err(Error::Other(format!("unsupported database URL: {url}")))
    }

    pub fn is_postgres(&self) -> bool {
        !matches!(self.inner, Inner::Sqlite(_))
    }

    /// The underlying SQLite connection (SQLite-only features: PRAGMAs, backups).
    pub fn as_sqlite(&self) -> Option<&rusqlite::Connection> {
        match &self.inner {
            Inner::Sqlite(c) => Some(c),
            #[allow(unreachable_patterns)]
            _ => None,
        }
    }

    #[allow(irrefutable_let_patterns)]
    pub fn busy_timeout(&self, d: std::time::Duration) -> Result<()> {
        if let Inner::Sqlite(c) = &self.inner {
            c.busy_timeout(d)?;
        }
        Ok(())
    }

    pub fn execute(&self, sql: &str, params: impl Params) -> Result<usize> {
        match &self.inner {
            Inner::Sqlite(c) => Ok(c.execute(sql, sqlite_params(&params.values()))?),
            #[cfg(feature = "postgres")]
            Inner::Pg(c) => c.borrow_mut().execute(sql, &params.values()),
        }
    }

    pub fn query_row<T, F>(&self, sql: &str, params: impl Params, f: F) -> Result<T>
    where
        F: FnOnce(&Row<'_>) -> Result<T>,
    {
        match &self.inner {
            Inner::Sqlite(c) => {
                let mut stmt = c.prepare(sql)?;
                let values = params.values();
                let mut rows = stmt.query(sqlite_params(&values))?;
                match rows.next()? {
                    Some(r) => f(&Row::Sqlite(r)),
                    None => Err(Error::QueryReturnedNoRows),
                }
            }
            #[cfg(feature = "postgres")]
            Inner::Pg(c) => {
                let rows = c.borrow_mut().query(sql, &params.values())?;
                match rows.first() {
                    Some(r) => f(&Row::Pg(r)),
                    None => Err(Error::QueryReturnedNoRows),
                }
            }
        }
    }

    pub fn prepare(&self, sql: &str) -> Result<Statement<'_>> {
        Ok(Statement { conn: self, sql: sql.to_string() })
    }

    pub fn execute_batch(&self, sql: &str) -> Result<()> {
        match &self.inner {
            Inner::Sqlite(c) => Ok(c.execute_batch(sql)?),
            #[cfg(feature = "postgres")]
            Inner::Pg(c) => c.borrow_mut().execute_batch(sql),
        }
    }

    /// Execute native SQL for the active backend without dialect translation.
    pub fn execute_batch_raw(&self, sql: &str) -> Result<()> {
        match &self.inner {
            Inner::Sqlite(c) => Ok(c.execute_batch(sql)?),
            #[cfg(feature = "postgres")]
            Inner::Pg(c) => c.borrow_mut().batch_execute_raw(sql),
        }
    }

    pub fn transaction_with_behavior(&mut self, behavior: TransactionBehavior) -> Result<Transaction<'_>> {
        let begin = match (&self.inner, behavior) {
            (Inner::Sqlite(_), TransactionBehavior::Deferred) => "BEGIN DEFERRED",
            (Inner::Sqlite(_), TransactionBehavior::Immediate) => "BEGIN IMMEDIATE",
            (Inner::Sqlite(_), TransactionBehavior::Exclusive) => "BEGIN EXCLUSIVE",
            #[allow(unreachable_patterns)]
            _ => "BEGIN",
        };
        self.execute_batch_raw(begin)?;
        Ok(Transaction { conn: self, done: false })
    }

    pub fn transaction(&mut self) -> Result<Transaction<'_>> {
        self.transaction_with_behavior(TransactionBehavior::Deferred)
    }

    fn query_all<T>(&self, sql: &str, values: &[ValueRef<'_>], mut f: impl FnMut(&Row<'_>) -> Result<T>) -> Result<Vec<Result<T>>> {
        match &self.inner {
            Inner::Sqlite(c) => {
                let mut stmt = c.prepare(sql)?;
                let mut rows = stmt.query(sqlite_params(values))?;
                let mut out = vec![];
                while let Some(r) = rows.next()? {
                    out.push(f(&Row::Sqlite(r)));
                }
                Ok(out)
            }
            #[cfg(feature = "postgres")]
            Inner::Pg(c) => {
                let rows = c.borrow_mut().query(sql, values)?;
                Ok(rows.iter().map(|r| f(&Row::Pg(r))).collect())
            }
        }
    }
}

/// A prepared statement (lazy: the SQL is prepared per execution, cached by the backend).
pub struct Statement<'c> {
    conn: &'c Connection,
    sql: String,
}

impl Statement<'_> {
    pub fn query_map<T, F>(&mut self, params: impl Params, f: F) -> Result<std::vec::IntoIter<Result<T>>>
    where
        F: FnMut(&Row<'_>) -> Result<T>,
    {
        Ok(self.conn.query_all(&self.sql, &params.values(), f)?.into_iter())
    }

    pub fn query_row<T, F>(&mut self, params: impl Params, f: F) -> Result<T>
    where
        F: FnOnce(&Row<'_>) -> Result<T>,
    {
        self.conn.query_row(&self.sql, params, f)
    }

    pub fn execute(&mut self, params: impl Params) -> Result<usize> {
        self.conn.execute(&self.sql, params)
    }

    /// Materialised rows (`while let Some(row) = rows.next()?`).
    pub fn query(&mut self, params: impl Params) -> Result<Rows> {
        let mut names = None;
        let rows = self.conn.query_all(&self.sql, &params.values(), |r| {
            if names.is_none() {
                names = Some((0..r.column_count()).map(|i| r.column_name(i)).collect::<Vec<_>>());
            }
            (0..r.column_count()).map(|i| r.get_ref(i).map(|v| v.to_owned())).collect::<Result<Vec<Value>>>()
        })?;
        let rows: Vec<Vec<Value>> = rows.into_iter().collect::<Result<_>>()?;
        Ok(Rows { rows: rows.into_iter(), current: None, names: std::rc::Rc::new(names.unwrap_or_default()) })
    }
}

/// Owned row set returned by [`Statement::query`].
pub struct Rows {
    rows: std::vec::IntoIter<Vec<Value>>,
    current: Option<Row<'static>>,
    names: std::rc::Rc<Vec<String>>,
}

impl Rows {
    #[allow(clippy::should_implement_trait)]
    pub fn next(&mut self) -> Result<Option<&Row<'static>>> {
        self.current = self.rows.next().map(|v| Row::Owned(v, self.names.clone()));
        Ok(self.current.as_ref())
    }
}

pub struct Transaction<'c> {
    conn: &'c mut Connection,
    done: bool,
}

impl std::ops::Deref for Transaction<'_> {
    type Target = Connection;
    fn deref(&self) -> &Connection {
        self.conn
    }
}

impl Transaction<'_> {
    pub fn commit(mut self) -> Result<()> {
        self.done = true;
        self.conn.execute_batch_raw("COMMIT")
    }
    pub fn rollback(mut self) -> Result<()> {
        self.done = true;
        self.conn.execute_batch_raw("ROLLBACK")
    }
}

impl Drop for Transaction<'_> {
    fn drop(&mut self) {
        if !self.done {
            let _ = self.conn.execute_batch_raw("ROLLBACK");
        }
    }
}
