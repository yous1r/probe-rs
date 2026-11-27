use super::*;

async fn open(path: &Path) -> AppState {
    AppState::new(
        "node-a=test-agent-credential-12345",
        "test-admin-credential-12345".to_owned(),
        30,
        5,
        Storage::open(path).await.unwrap(),
    )
    .await
    .unwrap()
}

fn group(id: &str, parent: Option<&str>) -> Group {
    Group {
        id: id.to_owned(),
        name: format!("Group {id}"),
        parent_id: parent.map(str::to_owned),
        sort: 12,
        color: Some("#123456".to_owned()),
    }
}

#[tokio::test]
async fn reopens_hosts_latest_report_hierarchy_and_explicit_ungrouped_assignment() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("registry.sqlite");
    let state = open(&path).await;
    state.ingest("node-a", test_hello(), 1000).await.unwrap();
    state
        .ingest("node-a", test_report(1000), 1000)
        .await
        .unwrap();
    state.create_group(group("parent", None)).await.unwrap();
    state
        .create_group(group("child", Some("parent")))
        .await
        .unwrap();
    state
        .assign_group("node-a", Some("child".to_owned()))
        .await
        .unwrap();
    let (mut before_hosts, before_groups) = state.overview(1000).await;
    assert!(before_hosts[0].online);
    before_hosts[0].online = false;
    state.close().await;

    let restored = open(&path).await;
    let (hosts, groups) = restored.overview(1000).await;
    assert_eq!(hosts, before_hosts);
    assert_eq!(groups, before_groups);
    restored.ingest("node-a", test_hello(), 1001).await.unwrap();
    assert_eq!(
        restored.overview(1001).await.0[0].group_id.as_deref(),
        Some("child")
    );
    restored
        .ingest("node-a", test_report(1000), 1001)
        .await
        .unwrap();
    assert!(!restored.overview(1001).await.0[0].online);
    restored
        .ingest("node-a", test_report(1002), 1002)
        .await
        .unwrap();
    assert!(restored.overview(1002).await.0[0].online);
    restored.assign_group("node-a", None).await.unwrap();
    restored.close().await;

    let again = open(&path).await;
    again.ingest("node-a", test_hello(), 1003).await.unwrap();
    assert!(again.overview(1003).await.0[0].group_id.is_none());
    assert_eq!(again.overview(1003).await.0.len(), 1);
    again.close().await;
}

#[tokio::test]
async fn failed_database_writes_never_publish_success_to_cache() {
    let state = test_state().await;
    state.ingest("node-a", test_hello(), 1000).await.unwrap();
    state
        .ingest("node-a", test_report(1000), 1000)
        .await
        .unwrap();
    let before = state.overview(1000).await;
    state.close().await; // Closed storage is a deterministic write failure.
    assert_eq!(
        state.assign_group("node-a", None).await,
        Err(IngestError::StorageUnavailable)
    );
    assert_eq!(
        state.create_group(group("not-saved", None)).await,
        Err(IngestError::StorageUnavailable)
    );
    assert_eq!(
        state.ingest("node-a", test_report(1001), 1001).await,
        Err(IngestError::StorageUnavailable)
    );
    assert_eq!(state.overview(1000).await, before);
}

#[tokio::test]
async fn caller_cancellation_does_not_split_disk_commit_and_cache_update() {
    use tokio::sync::oneshot;
    let state = test_state().await;
    let (started_tx, started_rx) = oneshot::channel();
    let (resume_tx, resume_rx) = oneshot::channel();
    let (finished_tx, finished_rx) = oneshot::channel();
    let caller_state = state.clone();
    let caller = tokio::spawn(async move {
        caller_state
            .mutate(move |worker| async move {
                started_tx.send(()).unwrap();
                resume_rx.await.unwrap();
                let result = worker.create_group_committed(group("saved", None)).await;
                finished_tx.send(()).unwrap();
                result
            })
            .await
    });
    started_rx.await.unwrap();
    caller.abort();
    assert!(caller.await.unwrap_err().is_cancelled());
    resume_tx.send(()).unwrap();
    finished_rx.await.unwrap();
    assert_eq!(state.overview(1).await.1, vec![group("saved", None)]);
    assert_eq!(
        state.0.storage.load().await.unwrap().groups,
        vec![group("saved", None)]
    );
}
