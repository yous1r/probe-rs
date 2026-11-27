//! The registry and latest accepted report are committed before publishing in-memory state.
use anyhow::{bail, Context, Result};
use fs2::FileExt;
use rprobe_common::{AgentHello, Group, HostSnapshot};
use sqlx::sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions, SqliteSynchronous};
use sqlx::{Connection, Row, SqliteConnection, SqlitePool};
use std::fs::{self, File, OpenOptions};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::Duration;

pub struct Storage {
    pool: SqlitePool,
    lock: Mutex<Option<File>>,
}

pub struct LoadedState {
    pub hosts: Vec<HostSnapshot>,
    pub groups: Vec<Group>,
}

impl Storage {
    pub async fn open(path: &Path) -> Result<Self> {
        let name = path.to_string_lossy();
        if name.is_empty()
            || name == ":memory:"
            || name.starts_with("file:")
            || name.starts_with("sqlite:")
        {
            bail!("RPROBE_DB_PATH must be a local file path; memory databases and database URLs are not allowed");
        }
        let mut lock_name = path.as_os_str().to_os_string();
        lock_name.push(".lock");
        let lock_path = PathBuf::from(lock_name);
        prepare_file(&lock_path).context("prepare registry lock file")?;
        let lock = OpenOptions::new().read(true).write(true).open(&lock_path)?;
        lock.try_lock_exclusive()
            .context("registry already in use; only one server may open a database")?;
        prepare_file(path).with_context(|| format!("prepare database {}", path.display()))?;
        Self::connect(
            SqliteConnectOptions::new()
                .filename(path)
                .create_if_missing(false),
            Some(lock),
        )
        .await
    }

    async fn connect(options: SqliteConnectOptions, lock: Option<File>) -> Result<Self> {
        let options = options
            .foreign_keys(true)
            .busy_timeout(Duration::from_secs(5));
        // Validate before requesting WAL, so a rejected foreign database remains unchanged.
        let mut inspection = SqliteConnection::connect_with(&options)
            .await
            .context("inspect SQLite database")?;
        let version: i64 = sqlx::query_scalar("PRAGMA user_version")
            .fetch_one(&mut inspection)
            .await?;
        match version {
            0 => {
                let objects: i64 = sqlx::query_scalar(
                    "SELECT count(*) FROM sqlite_master WHERE name NOT GLOB 'sqlite_*'",
                )
                .fetch_one(&mut inspection)
                .await?;
                if objects != 0 {
                    bail!("unrecognized nonempty database; refusing to replace its schema");
                }
            }
            1 => {
                sqlx::query("SELECT id, parent_id, name, sort, color FROM groups LIMIT 0")
                    .fetch_all(&mut inspection)
                    .await?;
                sqlx::query("SELECT id, hello_json, report_json, last_seen_at, group_id, clock_skew_secs FROM hosts LIMIT 0")
                    .fetch_all(&mut inspection).await?;
            }
            _ => bail!("unsupported database schema version {version}"),
        }
        let integrity: String = sqlx::query_scalar("PRAGMA quick_check")
            .fetch_one(&mut inspection)
            .await?;
        if integrity != "ok" {
            bail!("SQLite integrity check failed; restore a verified backup");
        }
        if sqlx::query("PRAGMA foreign_key_check")
            .fetch_optional(&mut inspection)
            .await?
            .is_some()
        {
            bail!("SQLite foreign key check failed");
        }
        inspection.close().await?;
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .acquire_timeout(Duration::from_secs(6))
            .connect_with(
                options
                    .journal_mode(SqliteJournalMode::Wal)
                    .synchronous(SqliteSynchronous::Full),
            )
            .await
            .context("open SQLite database; no in-memory fallback is available")?;
        let store = Self {
            pool,
            lock: Mutex::new(lock),
        };
        if version == 0 {
            let mut transaction = store.pool.begin().await?;
            sqlx::raw_sql(include_str!("../migrations/0001_registry.sql"))
                .execute(&mut *transaction)
                .await?;
            transaction.commit().await?;
        }
        Ok(store)
    }

    pub async fn load(&self) -> Result<LoadedState> {
        let mut transaction = self.pool.begin().await?;
        let host_count: i64 = sqlx::query_scalar("SELECT count(*) FROM hosts")
            .fetch_one(&mut *transaction)
            .await?;
        let group_count: i64 = sqlx::query_scalar("SELECT count(*) FROM groups")
            .fetch_one(&mut *transaction)
            .await?;
        if host_count > 1000 || group_count > 500 {
            bail!("stored registry exceeds configured capacity");
        }
        let mut groups = Vec::new();
        for row in sqlx::query("SELECT id, parent_id, name, sort, color FROM groups")
            .fetch_all(&mut *transaction)
            .await?
        {
            groups.push(Group {
                id: row.try_get("id")?,
                parent_id: row.try_get("parent_id")?,
                name: row.try_get("name")?,
                sort: row.try_get("sort")?,
                color: row.try_get("color")?,
            });
        }
        let mut hosts = Vec::new();
        for row in sqlx::query("SELECT id, hello_json, report_json, last_seen_at, group_id, clock_skew_secs FROM hosts")
            .fetch_all(&mut *transaction).await? {
            let hello: AgentHello = serde_json::from_str(row.try_get::<&str, _>("hello_json")?).context("decode saved host information")?;
            if hello.agent_id != row.try_get::<String, _>("id")? { bail!("saved host identity mismatch"); }
            let report = row.try_get::<Option<String>, _>("report_json")?
                .map(|text| serde_json::from_str(&text)).transpose().context("decode saved latest report")?;
            hosts.push(HostSnapshot { hello, report, last_seen_at: row.try_get("last_seen_at")?, online: false,
                group_id: row.try_get("group_id")?, clock_skew_secs: row.try_get("clock_skew_secs")? });
        }
        transaction.commit().await?;
        Ok(LoadedState { hosts, groups })
    }

    pub async fn save_host(&self, host: &HostSnapshot, new_group: Option<&Group>) -> Result<()> {
        let hello = serde_json::to_string(&host.hello)?;
        let report = host
            .report
            .as_ref()
            .map(serde_json::to_string)
            .transpose()?;
        let mut transaction = self.pool.begin().await?;
        if let Some(group) = new_group {
            sqlx::query(
                "INSERT INTO groups (id, parent_id, name, sort, color) VALUES (?, ?, ?, ?, ?)",
            )
            .bind(&group.id)
            .bind(&group.parent_id)
            .bind(&group.name)
            .bind(group.sort)
            .bind(&group.color)
            .execute(&mut *transaction)
            .await?;
        }
        sqlx::query("INSERT INTO hosts (id, hello_json, report_json, last_seen_at, group_id, clock_skew_secs) VALUES (?, ?, ?, ?, ?, ?)
            ON CONFLICT(id) DO UPDATE SET hello_json=excluded.hello_json, report_json=excluded.report_json,
            last_seen_at=excluded.last_seen_at, group_id=excluded.group_id, clock_skew_secs=excluded.clock_skew_secs")
            .bind(&host.hello.agent_id).bind(hello).bind(report).bind(host.last_seen_at)
            .bind(&host.group_id).bind(host.clock_skew_secs).execute(&mut *transaction).await?;
        transaction.commit().await?;
        Ok(())
    }

    pub async fn create_group(&self, group: &Group) -> Result<()> {
        sqlx::query("INSERT INTO groups (id, parent_id, name, sort, color) VALUES (?, ?, ?, ?, ?)")
            .bind(&group.id)
            .bind(&group.parent_id)
            .bind(&group.name)
            .bind(group.sort)
            .bind(&group.color)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    pub async fn assign_group(&self, id: &str, group_id: Option<&str>) -> Result<()> {
        let result = sqlx::query("UPDATE hosts SET group_id = ? WHERE id = ?")
            .bind(group_id)
            .bind(id)
            .execute(&self.pool)
            .await?;
        if result.rows_affected() != 1 {
            bail!("stored host missing during group assignment");
        }
        Ok(())
    }

    pub async fn close(&self) {
        self.pool.close().await;
        if let Ok(mut lock) = self.lock.lock() {
            lock.take();
        }
    }

    #[cfg(test)]
    pub async fn for_test() -> Self {
        Self::connect(SqliteConnectOptions::new().in_memory(true), None)
            .await
            .unwrap()
    }
}

fn prepare_file(path: &Path) -> Result<()> {
    if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
        let mut builder = fs::DirBuilder::new();
        builder.recursive(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            builder.mode(0o700);
        }
        builder.create(parent)?;
    }
    let mut options = OpenOptions::new();
    options.create_new(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    match options.open(path) {
        Ok(file) => {
            file.sync_all()?;
        }
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(error) => return Err(error.into()),
    }
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.is_file() {
        bail!("database path must be a regular file, not a directory or symlink");
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o077 != 0 {
            bail!("database permissions must be 0600 or stricter");
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn host_and_initial_group_are_atomic() {
        let storage = Storage::for_test().await;
        let rprobe_common::ClientMessage::Hello { hello } = crate::state::test_hello() else {
            unreachable!()
        };
        let host = HostSnapshot {
            hello,
            report: None,
            last_seen_at: 1,
            online: false,
            group_id: Some("missing".into()),
            clock_skew_secs: None,
        };
        let group = Group {
            id: "new".into(),
            parent_id: None,
            name: "New".into(),
            sort: 0,
            color: None,
        };
        assert!(storage.save_host(&host, Some(&group)).await.is_err());
        let saved = storage.load().await.unwrap();
        assert!(saved.hosts.is_empty());
        assert!(saved.groups.is_empty()); // Group insertion rolls back with the failed host FK.
    }

    #[tokio::test]
    async fn refuses_volatile_or_foreign_schema_without_overwriting() {
        assert!(Storage::open(Path::new(":memory:")).await.is_err());
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("registry.sqlite");
        let storage = Storage::open(&path).await.unwrap();
        sqlx::query("PRAGMA user_version = 99")
            .execute(&storage.pool)
            .await
            .unwrap();
        storage.close().await;
        assert!(Storage::open(&path).await.is_err());
        assert!(path.exists());
    }

    #[tokio::test]
    async fn second_server_is_rejected_and_rejected_foreign_databases_remain_unchanged() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("registry.sqlite");
        let owner = Storage::open(&path).await.unwrap();
        assert!(Storage::open(&path).await.is_err());
        owner.close().await;
        Storage::open(&path).await.unwrap().close().await;

        for (i, schema) in [
            "CREATE TABLE sqliteData (value TEXT)",
            "CREATE VIEW external_view AS SELECT 1",
            "PRAGMA user_version = 99",
        ]
        .iter()
        .enumerate()
        {
            let foreign = temp.path().join(format!("foreign-{i}.sqlite"));
            prepare_file(&foreign).unwrap();
            let mut connection =
                SqliteConnection::connect_with(&SqliteConnectOptions::new().filename(&foreign))
                    .await
                    .unwrap();
            sqlx::query(schema).execute(&mut connection).await.unwrap();
            connection.close().await.unwrap();
            let original = fs::read(&foreign).unwrap();
            assert!(Storage::open(&foreign).await.is_err());
            assert_eq!(fs::read(&foreign).unwrap(), original);
        }
    }
}
