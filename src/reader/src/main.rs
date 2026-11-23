use serde_json::Value;
use std::{
    collections::{hash_map::RandomState, HashSet, VecDeque},
    env,
    fs::{self, File, Metadata},
    hash::BuildHasher,
    io::{self, Read, Write},
    path::{Path, PathBuf},
    process::ExitCode,
    thread,
    time::{Duration, SystemTime},
};

const MAX_READ: u64 = 8 * 1024 * 1024;
const POLL_INTERVAL: Duration = Duration::from_millis(200);
// Enough for a whole bounded journal plus a recent generation after retention.
const MAX_SEEN: usize = 256 * 1024;

#[derive(Debug)]
struct Args {
    file: PathBuf,
    debug: bool,
    tail: usize,
    once: bool,
}

fn args() -> Result<Option<Args>, String> {
    let mut file = None;
    let mut debug = false;
    let mut tail = 20;
    let mut once = false;
    let mut positional = false;
    let mut it = env::args_os().skip(1);
    while let Some(arg) = it.next() {
        match if positional { None } else { arg.to_str() } {
            Some("--") => positional = true,
            Some("--help" | "-h") => return Ok(None),
            Some("--debug" | "-d") => debug = true,
            Some("--once") => once = true,
            Some("--all") => tail = usize::MAX,
            Some("--tail" | "-n") => {
                tail = it
                    .next()
                    .and_then(|n| n.to_str()?.parse::<usize>().ok())
                    .filter(|n| *n > 0)
                    .ok_or("--tail 后面需要一个正整数")?;
            }
            Some("--file") => {
                if file.is_some() {
                    return Err("只接受一个日志文件".into());
                }
                let path = it
                    .next()
                    .filter(|p| !p.is_empty() && !p.to_string_lossy().starts_with('-'))
                    .ok_or("--file 缺少路径")?;
                file = Some(PathBuf::from(path));
            }
            Some(s) if s.starts_with('-') => return Err(format!("未知选项：{s}")),
            _ if arg.is_empty() => return Err("日志文件路径不能为空".into()),
            _ if file.is_none() => file = Some(PathBuf::from(arg)),
            _ => return Err("只接受一个日志文件".into()),
        }
    }
    let file = file.unwrap_or_else(|| {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .ancestors()
            .nth(2)
            .expect("reader project must be under <project>/src/reader")
            .join("logs")
            .join("events.jsonl")
    });
    Ok(Some(Args {
        file,
        debug,
        tail,
        once,
    }))
}

fn safe(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            _ if c.is_control()
                || matches!(c, '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}' | '\u{2028}' | '\u{2029}') =>
            {
                use std::fmt::Write as _;
                let _ = write!(out, "\\u{{{:04X}}}", c as u32);
            }
            _ => out.push(c),
        }
    }
    out
}

fn scalar(v: &Value) -> Option<String> {
    match v {
        Value::String(s) if !s.trim().is_empty() => Some(safe(s)),
        Value::Bool(b) => Some(if *b { "是" } else { "否" }.to_owned()),
        Value::Number(n) => Some(n.to_string()),
        _ => None,
    }
}

fn field(out: &mut impl Write, name: &str, v: &Value) -> io::Result<()> {
    if let Some(s) = scalar(v) {
        writeln!(out, "{name}: {s}")?;
    }
    Ok(())
}

fn label(key: &str) -> &str {
    match key {
        "schema" => "日志版本",
        "timestamp" => "时间 UTC",
        "decision" => "判定",
        "severity" => "级别",
        "message" => "提示",
        "reason" => "原因",
        "result" => "AMSI 返回码",
        "dropped" => "丢失记录",
        "process" => "进程",
        "pid" => "PID",
        "tid" => "线程 ID",
        "ppid" => "父 PID",
        "image" => "映像",
        "commandLine" => "启动命令行",
        "cwd" => "工作目录",
        "windowsSession" => "Windows 会话",
        "userSid" => "用户 SID",
        "userName" => "用户名",
        "elevated" => "已提升",
        "integrity" => "完整性级别 RID",
        "architecture" => "进程架构",
        "nativeArchitecture" => "系统架构",
        "created" => "进程创建时间",
        "parentCreated" => "父进程创建时间",
        "parentImage" => "父进程映像",
        "parentCommandLine" => "父进程启动命令行",
        "amsi" => "AMSI",
        "appName" => "应用",
        "contentName" => "来源",
        "content" => "脚本源码",
        "appNameState" => "应用名状态",
        "contentNameState" => "来源名状态",
        "contentSize" => "内容字节数",
        "contentInput" => "读取方式",
        "session" => "会话 ID",
        "sessionPresent" => "会话存在",
        "scanSequence" => "扫描序号",
        "redirectChainSize" => "重定向链大小",
        "allSize" => "整体缓冲区大小",
        "redirectChainAddressPresent" => "重定向链地址存在",
        "allAddressPresent" => "整体缓冲区地址存在",
        "quiet" => "静默标记",
        "ast" => "AST",
        "status" => "解析状态",
        "truncated" => "已截断",
        "commands" => "命令",
        "filePaths" => "文件路径",
        "urls" => "URL",
        "ipAddresses" => "IP",
        "domains" => "域名",
        "pipelines" => "管道",
        "variables" => "变量",
        "stringLiterals" => "字符串",
        "expandableStrings" => "可展开字符串",
        "dynamicExecution" => "动态执行",
        "externalCommands" => "外部命令",
        "encodingCalls" => "编码调用",
        "parseErrors" => "解析错误",
        "dataFlow" => "变量数据流",
        "runspaceId" => "Runspace ID",
        "runspaceState" => "Runspace 状态",
        "availability" => "Runspace 可用性",
        "postUpdate" => "执行后更新",
        "cacheHits" => "状态表命中数",
        "cacheRevalidations" => "缓存核对次数",
        "policy" => "规则",
        "evidence" => "判定依据",
        "previousPolicyUpdates" => "状态确认",
        "ruleId" => "规则 ID",
        "endpoint" => "发送目标",
        "route" => "传播路径",
        "flow" => "数据流",
        "runtimeReads" => "运行时查询次数",
        "variableReads" => "变量读取",
        "environmentReads" => "环境变量读取",
        "commandDefinitions" => "会话命令定义",
        "previousUpdates" => "前序赋值结果",
        "assignments" => "赋值",
        "candidateOrigin" => "可能来源",
        "dependsOn" => "依赖",
        "valueSource" => "值来源",
        "valueType" => "值类型",
        "valueLength" => "值长度",
        "known" | "valueKnown" => "值已知",
        "sensitive" => "敏感标记",
        "persistent" => "跨块继承",
        "prediction" => "静态推断",
        "observed" => "实测结果",
        "updated" => "值已变化",
        "predictionMatches" => "与推断一致",
        "parameters" => "参数",
        "name" => "名称",
        "invocationOperator" => "调用符",
        "line" => "行号",
        "literal" => "字面值",
        "id" => "编号",
        _ => key,
    }
}

fn render_debug(out: &mut impl Write, path: &str, v: &Value) -> io::Result<()> {
    match v {
        Value::Object(m) => {
            for (key, value) in m {
                let part = safe(label(key));
                let child = if path.is_empty() {
                    part
                } else {
                    format!("{path} / {part}")
                };
                render_debug(out, &child, value)?;
            }
        }
        Value::Array(items) => {
            for (index, item) in items.iter().enumerate() {
                render_debug(out, &format!("{path}[{}]", index + 1), item)?;
            }
        }
        _ => field(out, path, v)?,
    }
    Ok(())
}

fn list(v: &Value) -> String {
    v.as_array()
        .into_iter()
        .flatten()
        .filter_map(scalar)
        .collect::<Vec<_>>()
        .join("、")
}

fn render(out: &mut impl Write, v: &Value, debug: bool) -> io::Result<()> {
    if debug {
        return render_debug(out, "", v);
    }
    for key in [
        "timestamp",
        "decision",
        "severity",
        "message",
        "reason",
        "dropped",
    ] {
        if key == "decision" {
            let translated = match v[key].as_str() {
                Some("Block") => Some("已阻断"),
                Some("NotDetected") => Some("本规则未阻断"),
                other => other,
            };
            if let Some(s) = translated {
                writeln!(out, "判定: {}", safe(s))?;
            }
        } else if key == "severity" && v[key] == "Information" {
            continue;
        } else {
            let value = if key == "reason" {
                v["ast"]["policy"]["decision"]
                    .as_str()
                    .filter(|s| *s != "uncovered:command-shape")
                    .map(|_| &v["ast"]["policy"]["decision"])
                    .unwrap_or(&v[key])
            } else {
                &v[key]
            };
            field(out, label(key), value)?;
        }
    }
    field(out, "进程 PID", &v["process"]["pid"])?;
    field(out, "来源", &v["amsi"]["contentName"])?;
    field(out, "内容字节数", &v["amsi"]["contentSize"])?;
    field(out, "扫描序号", &v["amsi"]["scanSequence"])?;
    let ast = &v["ast"];
    if let Some(evidence) = ast["policy"]["evidence"].as_array() {
        for item in evidence {
            field(out, "发送目标", &item["endpoint"])?;
            if let Some(flow) = item["flow"].as_array() {
                for step in flow {
                    field(out, "规则 ID", &step["ruleId"])?;
                    field(out, "传播路径", &step["route"])?;
                }
            }
        }
    }
    if ast["status"] != "parsed" {
        field(out, "AST 状态", &ast["status"])?;
    }
    let commands = ast["commands"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|c| scalar(&c["name"]))
        .collect::<Vec<_>>()
        .join("、");
    if !commands.is_empty() {
        writeln!(out, "命令: {commands}")?;
    }
    for key in ["urls", "ipAddresses", "domains", "filePaths"] {
        let values = list(&ast[key]);
        if !values.is_empty() {
            writeln!(out, "{}: {values}", label(key))?;
        }
    }
    Ok(())
}

#[derive(Default)]
struct Journal {
    hasher: RandomState,
    seen: HashSet<u64>,
    recent: VecDeque<u64>,
}

impl Journal {
    fn new_events(&mut self, data: &[u8], limit: usize) -> (VecDeque<Value>, usize) {
        let mut events = VecDeque::new();
        let mut malformed = 0;
        // Only newline-terminated records are committed. Leave a partial last
        // line for the next snapshot rather than treating it as malformed.
        let end = data.iter().rposition(|&b| b == b'\n').map_or(0, |i| i + 1);
        for line in data[..end].split(|&b| b == b'\n') {
            let line = line.strip_suffix(b"\r").unwrap_or(line);
            if line.iter().all(|byte| byte.is_ascii_whitespace()) {
                continue;
            }
            // Retention rewrites the same file and preserves records byte for
            // byte. Remember those records independently of their byte offsets.
            let id = self.hasher.hash_one(line);
            if !self.seen.insert(id) {
                continue;
            }
            self.recent.push_back(id);
            if self.recent.len() > MAX_SEEN {
                if let Some(old) = self.recent.pop_front() {
                    self.seen.remove(&old);
                }
            }
            match serde_json::from_slice::<Value>(line) {
                Ok(event)
                    if event["schema"].as_u64() == Some(1) && event["process"].is_object() =>
                {
                    if events.len() == limit {
                        events.pop_front();
                    }
                    events.push_back(event);
                }
                _ => malformed += 1,
            }
        }
        (events, malformed)
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
struct Stamp {
    len: u64,
    modified: Option<SystemTime>,
    created: Option<SystemTime>,
}

impl From<Metadata> for Stamp {
    fn from(m: Metadata) -> Self {
        Self {
            len: m.len(),
            modified: m.modified().ok(),
            created: m.created().ok(),
        }
    }
}

fn run(a: Args) -> Result<(), String> {
    let read_error = |e| format!("读取 {} 失败：{e}", a.file.display());
    let mut last = None;
    let mut first = true;
    let mut journal = Journal::default();
    let mut printed = 0usize;
    let mut out = io::BufWriter::new(io::stdout().lock());
    if !a.once {
        eprintln!("正在跟踪 {}；按 Ctrl+C 退出。", a.file.display());
    }
    loop {
        let before = match fs::metadata(&a.file) {
            Ok(m) => Stamp::from(m),
            Err(e) if !a.once && e.kind() == io::ErrorKind::NotFound => {
                // Starting before the first event (or during a log recreation)
                // is normal. Keep the same deduplication state while waiting.
                first = false;
                last = None;
                thread::sleep(POLL_INTERVAL);
                continue;
            }
            Err(e) => return Err(read_error(e)),
        };
        if last != Some(before) || before.modified.is_none() {
            let file = match File::open(&a.file) {
                Ok(f) => f,
                Err(e) if !a.once && e.kind() == io::ErrorKind::NotFound => {
                    last = None;
                    thread::sleep(POLL_INTERVAL);
                    continue;
                }
                Err(e) => return Err(read_error(e)),
            };
            let mut data = Vec::new();
            file.take(MAX_READ + 1)
                .read_to_end(&mut data)
                .map_err(read_error)?;
            if data.len() as u64 > MAX_READ {
                return Err("日志超过读取上限 8 MiB".into());
            }
            let limit = if first { a.tail } else { usize::MAX };
            let (events, malformed) = journal.new_events(&data, limit);
            if a.debug && malformed != 0 {
                eprintln!("跳过 {malformed} 条不完整或未知格式的记录。");
            }
            if a.once && events.is_empty() {
                if malformed != 0 {
                    return Err("文件中没有可解析的 Guard 日志记录".into());
                }
                writeln!(out, "还没有扫描记录。").map_err(|e| e.to_string())?;
            }
            let mut write_batch = || -> io::Result<()> {
                for event in &events {
                    if printed != 0 {
                        writeln!(out)?;
                    }
                    printed += 1;
                    writeln!(out, "扫描记录 {printed}")?;
                    render(&mut out, event, a.debug)?;
                }
                out.flush()
            };
            if let Err(err) = write_batch() {
                return if err.kind() == io::ErrorKind::BrokenPipe {
                    Ok(())
                } else {
                    Err(err.to_string())
                };
            }
            // If a writer was active during this read, revisit the file on the
            // next poll even if it already contains some complete new records.
            let after = fs::metadata(&a.file).ok().map(Stamp::from);
            last = after.filter(|stamp| *stamp == before);
            first = false;
        }
        if a.once {
            return Ok(());
        }
        thread::sleep(POLL_INTERVAL);
    }
}

fn main() -> ExitCode {
    let result = match args() {
        Ok(Some(a)) => run(a),
        Ok(None) => {
            println!("guard-log [--tail 数量 | --all] [--debug] [--once] [--file 日志路径 | [--] 日志路径]\n默认先显示最近 20 条，然后持续输出新增记录；Ctrl+C 退出。\n--debug 展开详细字段；--once 只读取一次。");
            Ok(())
        }
        Err(e) => Err(e),
    };
    if let Err(e) = result {
        eprintln!("guard-log: {e}");
        ExitCode::FAILURE
    } else {
        ExitCode::SUCCESS
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn history_limit_does_not_replay_older_records_on_append() {
        let mut journal = Journal::default();
        let first = b"{\"schema\":1,\"process\":{},\"amsi\":{\"scanSequence\":1}}\n\
                      {\"schema\":1,\"process\":{},\"amsi\":{\"scanSequence\":2}}\n";
        let (initial, _) = journal.new_events(first, 1);
        assert_eq!(initial.len(), 1);
        assert_eq!(initial[0]["amsi"]["scanSequence"], 2);
        let mut next = first.to_vec();
        next.extend_from_slice(b"{\"schema\":1,\"process\":{},\"amsi\":{\"scanSequence\":3}}\n");
        let (appended, _) = journal.new_events(&next, usize::MAX);
        assert_eq!(appended.len(), 1);
        assert_eq!(appended[0]["amsi"]["scanSequence"], 3);
    }

    #[test]
    fn renders_without_empty_fields_or_inline_objects() {
        let event = serde_json::json!({
            "decision":"NotDetected","severity":"Warning","message":"Information missing",
            "process":{"pid":25,"elevated":false,"commandLine":""},
            "amsi":{"scanSequence":1,"content":"first\nsecond"},
            "ast":{"status":"parsed","commands":[{"name":"Invoke-RestMethod","parameters":[{"name":"Body","literal":null}]}],"urls":[]}
        });
        for debug in [false, true] {
            let mut out = Vec::new();
            render(&mut out, &event, debug).unwrap();
            let show = String::from_utf8(out).unwrap();
            assert!(show.contains("Information missing"));
            assert!(show.lines().all(|line| line.contains(": ")));
            assert!(!show.contains('{') && !show.contains("null"));
            assert!(!show.contains("启动命令行") && !show.contains("字面值"));
            assert_eq!(show.contains("first\\nsecond"), debug);
            if debug {
                assert!(show.contains("已提升: 否"));
            }
        }
    }
}
