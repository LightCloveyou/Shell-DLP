# Frida SCP Guard Demo

> 状态：正在从 Linux eBPF 迁移到 Frida。

独立的 SCP 上传拦截示例，结构与 `frida_git_guard` 类似。后台接入已有 PowerShell、pwsh、cmd、bash、sh，在父进程的 `CreateProcessW/A` 返回前检查 `scp` 上传源文件。

```powershell
python -m pip install -r .\demo\frida_scp_guard\requirements.txt
python .\demo\frida_scp_guard\backend.py
```

另开一个已被接入的终端进行现场验证：

```powershell
'hello' | Set-Content .\demo\frida_scp_guard\clean.txt
scp -P 22 .\demo\frida_scp_guard\clean.txt user@host:/tmp/clean.txt

'DEMO_SECRET_12345678' | Set-Content .\demo\frida_scp_guard\blocked.txt
scp .\demo\frida_scp_guard\blocked.txt user@host:/tmp/blocked.txt
```

第一条应记录 `ALLOWED` 并由真实 `scp.exe` 继续执行；第二条应在创建 `scp.exe` 前记录 `BLOCKED`/`NATIVE_BLOCK`。下载（远端为源）、本地复制和非 SCP 命令不属于本示例的上传门禁。按 Ctrl+C 后后台会立即输出 `STOP_REQUESTED`，随后输出 `STOPPING`、`STOPPED`。

自动化策略测试：`python -m unittest discover .\demo\frida_scp_guard\tests -v`。该测试只覆盖策略函数，不代表 Frida 接入、真实 SCP 传输和退出流程已经验证。测试记录、变更补丁和删除该新增目录的回滚脚本位于 `tests`。
