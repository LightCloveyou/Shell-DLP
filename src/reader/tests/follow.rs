use std::{
    fs::{self, OpenOptions},
    io::{BufRead, BufReader, Write},
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::mpsc::{self, Receiver},
    thread,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

struct Fixture {
    dir: PathBuf,
    log: PathBuf,
    child: Option<Child>,
}

impl Drop for Fixture {
    fn drop(&mut self) {
        if let Some(child) = &mut self.child {
            let _ = child.kill();
            let _ = child.wait();
        }
        let _ = fs::remove_file(&self.log);
        let _ = fs::remove_dir(&self.dir);
    }
}

fn record(sequence: usize) -> String {
    format!("{{\"schema\":1,\"decision\":\"NotDetected\",\"process\":{{\"pid\":25}},\"amsi\":{{\"scanSequence\":{sequence}}}}}\n")
}

fn append(log: &Path, bytes: &[u8]) {
    let mut f = OpenOptions::new()
        .create(true)
        .append(true)
        .open(log)
        .unwrap();
    f.write_all(bytes).unwrap();
}

fn next(rx: &Receiver<String>) -> String {
    rx.recv_timeout(Duration::from_secs(6))
        .expect("watcher did not output the next record")
}

#[test]
fn follows_creation_append_partial_and_compaction() {
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("ps7guard-follow-{}-{unique}", std::process::id()));
    fs::create_dir(&dir).unwrap();
    let log = dir.join("events.jsonl");
    let mut guard = Fixture {
        dir,
        log: log.clone(),
        child: None,
    };
    let mut start = Command::new(env!("CARGO_BIN_EXE_guard-log"));
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        start.creation_flags(0x08000000); // CREATE_NO_WINDOW
    }
    guard.child = Some(
        start
            .arg("--file")
            .arg(&log)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap(),
    );
    let child = guard.child.as_mut().unwrap();
    let out = child.stdout.take().unwrap();
    let err = child.stderr.take().unwrap();
    let (tx, rx) = mpsc::channel();
    let (err_tx, err_rx) = mpsc::channel();
    thread::spawn(move || {
        for line in BufReader::new(err).lines().map_while(Result::ok) {
            if err_tx.send(line).is_err() {
                break;
            }
        }
    });
    thread::spawn(move || {
        for line in BufReader::new(out).lines().map_while(Result::ok) {
            if line.starts_with("扫描序号: ") && tx.send(line).is_err() {
                break;
            }
        }
    });
    assert!(next(&err_rx).contains("正在跟踪"));
    append(&log, record(1).as_bytes());
    assert_eq!(next(&rx), "扫描序号: 1");
    append(&log, record(2).as_bytes());
    assert_eq!(next(&rx), "扫描序号: 2");
    let third = record(3);
    append(&log, &third.as_bytes()[..third.len() - 1]);
    assert!(matches!(
        rx.recv_timeout(Duration::from_millis(500)),
        Err(mpsc::RecvTimeoutError::Timeout)
    ));
    append(&log, b"\n");
    assert_eq!(next(&rx), "扫描序号: 3");
    fs::write(&log, [record(2), record(3), record(4)].concat()).unwrap();
    assert_eq!(next(&rx), "扫描序号: 4");
    fs::remove_file(&log).unwrap();
    append(&log, record(5).as_bytes());
    assert_eq!(next(&rx), "扫描序号: 5");
}
