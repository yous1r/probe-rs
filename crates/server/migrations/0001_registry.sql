CREATE TABLE groups (
    id TEXT PRIMARY KEY NOT NULL CHECK(length(id) BETWEEN 1 AND 64),
    parent_id TEXT REFERENCES groups(id) ON DELETE RESTRICT,
    name TEXT NOT NULL,
    sort INTEGER NOT NULL DEFAULT 0,
    color TEXT,
    CHECK(parent_id IS NULL OR parent_id <> id)
);

CREATE TABLE hosts (
    id TEXT PRIMARY KEY NOT NULL CHECK(length(id) BETWEEN 1 AND 100),
    hello_json TEXT NOT NULL CHECK(length(hello_json) <= 16384),
    report_json TEXT CHECK(report_json IS NULL OR length(report_json) <= 16384),
    last_seen_at INTEGER NOT NULL,
    group_id TEXT REFERENCES groups(id) ON DELETE RESTRICT,
    clock_skew_secs INTEGER
);

CREATE INDEX hosts_group_id ON hosts(group_id);
PRAGMA user_version = 1;
