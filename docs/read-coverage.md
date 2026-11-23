# 三类读取：命令与输出

以下是分析器有专门处理分支的常见形式，不是允许或阻断的命令名单。判断对象是某条管道实际选择的字段、记录或字节；未建模的形态报告信息缺失。本清单描述源码和构建产物，不声称已执行运行时回归测试。

## 1. 文件正文和字节

| 入口 | 分析的输出 |
|---|---|
| `Get-Content`，以及确实指向它的 `gc`、`cat`、`type`；`switch -File` | 常见逐行、整段、所选行、指定数据流和字节读取。逐个 Byte、分组和一份 byte[] 不等价；多文件的 `-Raw` 保持记录边界。 |
| `Select-String`、`Format-Hex` | 按参数区分命中行、上下文、安静模式或字节区间；路径、偏移和正文分别处理。 |
| `Import-Csv`、`Import-Clixml`、`Import-PowerShellDataFile`、`Import-LocalizedData`、`Select-Xml`、XML 文档的 `Load` | CSV 字段、可静态解读的数据对象、XML 节点。纯数据文件不作为脚本执行，也不解析外部 XML 实体。 |
| `File.ReadAllText/ReadAllLines/ReadLines/ReadAllBytes` 及已建模的异步读取，`FileInfo`、`FileStream`、`StreamReader`、`BinaryReader`、`MemoryStream` | 读取方法决定正文；句柄和位置不是正文。`ReadExactly` 和 `ReadAtLeast` 区分缓冲区、计数及短读。`RandomAccess.Read` 使用显式偏移；`ReadLinesAsync` 通过异步枚举器取当前行。 |
| `cmd /c type`、`more.com`、原生 `cat/head/tail/less`、`find/findstr/grep/rg`、`cut/sed/awk/jq` | 文本、选中的行或字段。只识别有界筛选语法，不启动解释器；仅输出名称或计数的形式不等同于输出命中正文。 |
| `strings/strings64/strings64a`、`xxd/hexdump/hd/od`、`nl/uniq/sort/wc` | 选中的可打印字符、转储文本、带编号的行、相邻重复行、排序成员或统计值。方言、区域排序和不可确定的布局保持未知。 |
| `ZipFile.OpenRead`、`ZipArchive.GetEntry`、`ZipArchiveEntry.Open`、`Expand-Archive`、`tar/bsdtar`、`7z/7za/7zz`、`unzip/zipinfo` | 列成员名、取成员字节、向目标文件解压分别建模。扫描器仅预测目标文件；不运行解压工具、不写解压目录。 |
| `gzip/gunzip/zcat`、`bzip2/bunzip2/bzcat`、`xz/unxz/xzcat` | 解压到 stdout 才产生正文输出。大小、时间、文件数、编解码器和校验类型均有边界；未知成员不能证明整份归档干净。 |

## 2. 本机系统和会话数据

| 来源 | 入口 |
|---|---|
| 环境与变量 | `$env:NAME`、`Get-Item/Get-ChildItem/Get-Content Env:` 的对应形式、`Environment.GetEnvironmentVariable(s)`、`Get-Variable`、`printenv`、`cmd /c set` 的只读形式。枚举名称和读取值不同。 |
| 注册表、日志、CIM | `Get-ItemProperty[Value]`、`Registry/RegistryKey.GetValue`、`reg query`、`Get-WinEvent`、`wevtutil qe`、本地 `Get-CimInstance`。来源可识别，不表示已取得或查询真实的值。 |
| 会话和系统报告 | `Get-Clipboard`、普通文本 `Read-Host`、`Get-History`、`Get-Process`、`Get-Service`、`Get-ComputerInfo`、`Get-NetIPConfiguration`，以及本地只读 `tasklist/systeminfo/hostname/whoami/ipconfig`。不在扫描时运行这些命令或弹出输入框。 |

来源选择器如 `env:NAME`、`clipboard`、`session:history#CommandLine` 或 `system:process#Path` 可标记所选来源。只选择输出字段，不把同一记录中其他字段的内容一并当成已输出。

## 3. 文件元数据、命名和管道投影

| 入口 | 分析的输出 |
|---|---|
| `Get-Item/Get-ChildItem`（含已确认的别名）、`Get-Location/Resolve-Path/Convert-Path/Test-Path`、`Directory.GetFiles/GetDirectories/GetFileSystemEntries` 及 `Enumerate*` | 分清 FileInfo、DirectoryInfo、路径字符串和布尔值。文件集合的 `.FullName` 保持顺序；未知项不删除，也不把后续独立项变成已知安全。目录对象可以作为下一次枚举的根。 |
| 文件对象的 `Extension/BaseName/DirectoryName/Directory/Parent/Root/Length/Attributes`、创建/修改/访问时间；`File.GetAttributes`、`File/Directory.GetLastWriteTime[Utc]` 等 | 按文件/目录的实际类型选择字段。常见时间分量（如 `Year`、`Ticks`）单独建模。只取元数据，不读正文；缓存可能过期、文件变化或路径不明确时标为缺失。 |
| `Get-Acl`、`Get-Item -Stream`、`Get-FileHash`、`certutil -hashfile` | 描述符、流名/长度、摘要元数据。扫描器不为补全摘要而计算文件哈希。 |
| `where.exe`、`cmd /c dir`、原生 `ls`、Windows `tree`、`stat` | 名称、路径、大小和时间，而非目录内文件的内容。`where /q` 没有 stdout 文件列表；`dir /b`、`ls -1` 与详细报表分别建模；`stat -c` 支持 `%n/%s/%X/%Y/%%`。排序、短文件名和平台布局不确定时不虚构整行。 |
| `ConvertFrom-Json/Csv/StringData`、`Select-Object`、`ForEach-Object -MemberName` | 解析或投影上游已经产生的数据，不是新的文件源；多行 JSON 区分一个跨行文档和多份完整文档。 |
| `Group-Object`（`group`）和 `Get-Member`（`gm`） | 分组的 `Name/Values` 取自分组键，`Group` 持有组员而 `Count` 是数量。`-NoElement` 不输出组员内容。`Get-Member` 区分 `Name/TypeName/MemberType/Definition`：普通属性名称不带属性值；自定义对象的 NoteProperty 定义可包含该标量值。动态扩展、未建模的重载签名及复杂分组键保留缺失原因。 |

## 流复制和压缩

**流之间的传播。** `FileStream.CopyTo/CopyToAsync` 按源的当前位置选择剩余数据；复制缓冲区大小不是要复制的长度。`MemoryStream.WriteTo` 和 `ToArray` 则取全部逻辑内容。空片段本身不携带源标签。对可识别的内存流、本地可写文件流和 HTTP 请求流，记录目标的状态变化；流句柄本身不是正文。

常见的 `GZipStream`、`DeflateStream` 和 `BrotliStream` 通过同一套底层流状态处理：构造时区分压缩/解压模式、压缩级别和 `leaveOpen`；支持多次写入、字节区间和复制到包装流。压缩输出可携带已知来源而没有精确的压缩字节或长度；不据此登记已经写入成功的永久副本。对可物化的压缩输入按预算解压；底层读前取数的位置不作精确推断。内存流关闭后仍可提取其逻辑数组。未等待的异步复制、冲突访问和超预算记录为信息缺失，保留独立的来源证据。

## 两个容易混淆的边界

- **未知程序与后续读取**：未知本地程序不自动作为网络命令。其 stdout 是 missing information，而非已证实干净；独立后续读取重新建立来源。已知发送器仍按实际发送参数检查，敏感的已知证据优先于信息缺失。
- **`Get-ChildItem -System`**：System 属性条件与是否枚举 Hidden 项是两个判断。`-Force`、`-Hidden`、明确涉及 Hidden 的属性表达式影响后者。对照了 [PowerShell FileSystemProvider 实现](https://github.com/PowerShell/PowerShell/blob/v7.5.4/src/System.Management.Automation/namespaces/FileSystemProvider.cs) 和本机 PowerShell 7.6.9 的 `FileSystemProvider.Dir` 编译分支；没有把单独 `-System` 或 `-Attributes System` 等同于 `-Force`，也没有把双属性情形列为运行时复现的漏拦。
