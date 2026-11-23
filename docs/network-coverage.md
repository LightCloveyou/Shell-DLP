# 网络传输：第一批

这里列的是静态分析器识别的常见形式，不是拦截名单。命令可能建立连接、发送请求元数据、上传本地内容、下载到本地，或只更改本地作业状态；这些行为分别处理。

| 入口 | 已建模的区别 |
|---|---|
| `curl` | 每个 URL 的上传槽位与共用字段分开；重复的用户代理、引用页和登录参数以最后一个值为准，追加的正文、头、表单不合并成“最后一个”。简单多文件表单检查每个成员；普通文件字段只检查发送的字段名、文件名和内容，不把本地目录名当成表单内容。 |
| GNU `wget` | 区分 URL 列表与请求正文文件。文件或标准输入中的多条 URL 各带自己的来源；单条未知记录不代替其他已知记录。互斥的 POST/body 参数不作为两份已发送正文。 |
| `Invoke-WebRequest`、`Invoke-RestMethod` | 分别处理 URI、请求头、正文、表单和输入文件；对相对 URI 按 Web Cmdlet 的规则补全 HTTP，再分析目标和查询字段。片段不算发往服务器的字段。 |
| `scp` | 上传检查本地源文件；下载检查远端请求字段，不读本地目标作为上传内容。多个本地源及递归检查受预算限制。远程源正文不在本机推测。 |
| OpenSSH `sftp` | 识别批处理文件、标准输入的命令记录和启动时的下载操作数。区分 `put/mput` 与 `get/mget/reget`；跟踪 `lcd`，遇到退出命令停止。支持常见的简单文件名通配符和递归；续传 `reput` 的起始偏移取决于远端，不把整份文件的文字匹配当成已发出的后缀。交互输入不可见、自定义传输、复杂展开和超过预算均可产生信息缺失。不执行批处理或连接主机。 |
| `Start-BitsTransfer` | 已知 Source/Destination 的常见绑定按 Download、Upload、UploadReply 判断方向；默认下载。源、目标无法配对或作业暂停时报告缺失，不推定立即发送。 |
| PowerShell 远程复制和共享写入 | `Copy-Item -ToSession` 检查本地源；远程会话的主机未知就保留未知。`-FromSession` 不将本地下载目标视为上传源。`Copy-Item/Move-Item/Set-Content/Add-Content/Out-File` 的显式 UNC 目标作为共享写入处理。 |
| `robocopy`、`xcopy` | 常见本地源到显式 UNC 目标的复制；只列举模式不扫描文件正文作为上传。远端已有文件、短文件名、复杂过滤和未建模选项不推测，也不访问共享来补全信息。 |

未知本地程序的输出仍是 **missing information**，不是“已证实干净”。后续独立读取照常建立来源。由策略决定已知敏感证据的处置，缺失本身不等于阻断。有发送意图或已匹配来源，也不等于网络传输已经成功。

语义参考：[curl 手册](https://curl.se/docs/manpage.html)、[GNU Wget 参数检查](https://github.com/mirror/wget/blob/master/src/main.c)、[PowerShell Web Cmdlet 实现](https://github.com/PowerShell/PowerShell/blob/master/src/Microsoft.PowerShell.Commands.Utility/commands/utility/WebCmdlet/Common/WebRequestPSCmdlet.Common.cs)、[OpenSSH sftp 手册](https://man.openbsd.org/sftp.1)、[BITS 传输方向](https://learn.microsoft.com/en-us/powershell/module/bitstransfer/start-bitstransfer)。
