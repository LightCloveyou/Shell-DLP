# Frida Git Push 拦截

Windows + Git for Windows + Python 3.10+。

## 安装

```powershell
python -m pip install -r .\demo\frida_git_guard\requirements.txt
```

## 配置敏感目录

编辑 `.\demo\frida_git_guard\config.json`，例如：

```json
{
  "sensitive_directories": ["secrets", "private", "D:/Sensitive"],
  "sensitive_files": [".env", "*.pem", "demo/frida_git_guard/flag"],
  "scan_content": true
}
```

- 相对目录以仓库根目录为准；绝对目录必须存在，按内容指纹识别其中被复制或改名后提交的文件。
- `sensitive_files` 支持文件名通配符、仓库相对路径和绝对文件路径，已删除文件仍按提交历史检查。
- `scan_content` 开关私钥和凭证内容检测。修改配置后重启后台。

## 启动与推送

```powershell
python .\demo\frida_git_guard\backend.py
```

看到 `READY` 和对应终端的 `MONITOR` 后，在该终端照常运行：

```powershell
cd D:\your-project
git push origin main
```

沿用现有 HTTPS/SSH 登录和代理配置。推送时应出现 `GIT_PUSH`，随后 `DENY`（拦截）或 `ALLOW`（放行）；只有 `MONITOR` 不代表该次推送已检查。仅保护已接入的终端及子进程；扫描所有本地引用的历史，可能保守拦截未推送分支。

## 停止

按 `Ctrl+C` 或结束后台脚本即可解除拦截，不安装服务、不写 Git hook、不改 Git 配置。
