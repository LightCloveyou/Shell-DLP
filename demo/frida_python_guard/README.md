# Frida Python Guard Demo

> 状态：正在从 Linux eBPF 迁移到 Frida。

独立的 Python 启动拦截示例，结构与 `frida_git_guard` 类似。后台接入已有 PowerShell、pwsh、cmd、bash、sh，在父进程的 `CreateProcessW/A` 返回前检查 Python 脚本或 `python -c` 内容。

```powershell
python -m pip install -r .\demo\frida_python_guard\requirements.txt
python .\demo\frida_python_guard\backend.py
```

另开一个已被接入的终端进行现场验证：

```powershell
"print('clean python')" | Set-Content .\demo\frida_python_guard\clean.py
python .\demo\frida_python_guard\clean.py

"print('DEMO_SECRET_12345678')" | Set-Content .\demo\frida_python_guard\blocked.py
python .\demo\frida_python_guard\blocked.py
python -c "print('DEMO_SECRET_12345678')"
```

干净脚本应记录 `ALLOWED` 并真实执行；后两条应在创建 Python 进程前记录 `BLOCKED`/`NATIVE_BLOCK`。`-m`、标准输入、交互模式以及运行时动态文件和网络行为仍在迁移。按 Ctrl+C 后后台会立即输出 `STOP_REQUESTED`，随后输出 `STOPPING`、`STOPPED`。

自动化策略测试：`python -m unittest discover .\demo\frida_python_guard\tests -v`。该测试只覆盖策略函数，不代表 Frida 接入、真实 Python 启动和退出流程已经验证。测试记录、变更补丁和删除该新增目录的回滚脚本位于 `tests`。
