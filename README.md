# Shell DLP

本项目正在将原有的 Linux eBPF 实现迁移到 Frida，以便在不同平台上对命令执行和数据外传路径进行动态监控与策略拦截。

## 当前状态

项目正在从 Linux eBPF 迁移到 Frida。Git 已经验证，SCP、Python 及其他命令执行路径正在迁移和修复中。

## 进行中的工作

其余程序和命令路径仍在迁移、修复与兼容性调整中，部分场景可能存在性能、进程接入、退出清理或误拦问题。

迁移期间重点检查：

- 目标进程是否成功接入 Frida
- 普通命令是否正常放行
- 敏感操作是否按策略阻断
- 后台退出后相关命令是否恢复正常
- 不同终端、Shell 和子进程启动方式下的行为是否一致

当前版本仍是迁移中的测试版本。

## Demo 目录

当前 Frida Demo 位于：

```text
demo/frida_git_guard
demo/frida_scp_guard
demo/frida_python_guard
```

三个独立示例分别包含策略配置、Frida 后台、进程启动拦截脚本和验证说明，目前均在迁移中。
