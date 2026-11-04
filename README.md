# 华为分享（Windows 端）

用 Rust 实现的华为分享协议桌面端。与**鸿蒙手机 / 鸿蒙 7 平板**、**iPad / iPhone** 双向互通：
发现设备、发送文件、接收文件、发送剪贴板文本，全部在本机完成，不依赖华为电脑管家。

版本 **1.7.8** · 许可 **GPL-3.0-only** · 仅 Windows（x86_64）

---

## 目录结构

```text
华为分享/
├── README.md
├── bin/
│   ├── hwshare.exe          图形界面（1.88 MB）
│   └── hwshare-cli.exe      命令行（1.84 MB）
└── src/
    ├── Cargo.toml
    ├── Cargo.lock
    ├── build.rs             编入图标与版本资源
    ├── build.ps1            构建 / 测试脚本
    ├── assets/              图标、版本资源、托盘图标
    └── src/                 源码
```

两个 exe 共用同一份协议实现，功能完全一致，只是入口和子系统不同：

| 文件 | 子系统 | 用途 |
| --- | --- | --- |
| `hwshare.exe` | Windows GUI | 双击进托盘；不分配控制台，启动时没有黑框 |
| `hwshare-cli.exe` | Windows CUI | `discover` / `send` / `serve` / `listen` / `--help` |

静态链接，**不需要安装 Rust 或任何运行时**。

---

## 直接使用

双击 `bin\hwshare.exe`。窗口不会出现，程序常驻右下角托盘，同时开始监听，无需任何配置。

托盘右键菜单：

- 顶部是已发现的设备，点一下设为发送目标；选中项会置顶
- **重新扫描局域网** / **清除选择（不指定目标）**
- **发送文件到手机** / **发送剪贴板文本**
- **打开接收文件夹** / **选择接收文件夹…**
- **开机自启动**：勾选即开启，写当前用户注册表 `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`，
  不需要管理员权限；在「任务管理器 → 启动」里手动关掉后，这边菜单也会同步变成未勾选
- **关于** / **退出**

### 浮窗

发送或接收时右侧会出现一个浮窗，显示进度与结果：

- 可以拖动；拖到屏幕边缘会自动缩进贴边，只留一条 4px 的边
- 位置会被记住（存在 `window.json`），下次启动回到原处
- 上次退出时是贴边状态的话，启动后先完整显示 3 秒，再播一次缩进动画收成一条边
- 贴边状态下鼠标靠近会自动滑出，移开再缩回

### 接收方操作

手机 / 平板打开「华为分享」，保持亮屏，与本机连同一个 Wi-Fi。文件默认落到
`%USERPROFILE%\Downloads\HWShare`。

---

## 命令行

```text
hwshare-cli discover [--seconds N]                 扫描局域网设备（默认 12 秒）
hwshare-cli send --to <IP[:端口]> <文件...>          发给指定设备，端口可自动探测
hwshare-cli send --to-all <文件...>                 发给所有已发现设备
hwshare-cli serve [--dest 目录] [--name 名称] [--port 5684] [--no-discovery]
hwshare-cli listen [--dest 目录] [--port 0]         只接收一次
hwshare-cli --help
```

`serve` 是常驻接收（UDP 广播 + TCP 监听），`listen` 收一次就退出。
默认端口 5684，`--name` 缺省取计算机名 `COMPUTERNAME`。

---

## 从源码构建

需要：

- **Rust** stable 工具链（`x86_64-pc-windows-gnu` 或 `x86_64-pc-windows-msvc` 均可）
- **windres**（可选，来自 w64devkit 或任意 mingw-w64）。缺了也能构建，只是 exe 没有图标和版本号

```powershell
cd src
.\build.ps1            # release 构建，产物复制到 ..\bin\
.\build.ps1 -Test      # 单元测试
.\build.ps1 -Offline   # 只用本地 registry 缓存
```

脚本会自动寻找 `cargo` 和 `windres`，顺序是：环境变量覆盖（`HWSHARE_CARGO` / `HWSHARE_WINDRES`）
→ `PATH` → 常见安装目录。

也可以直接用 cargo：

```powershell
cargo build --release --bin hwshare --bin hwshare-cli
cargo test --lib
```

### 两个构建注意事项

1. **target 目录不要放在中文路径下。** mingw 的 `ld` 打不开非 ASCII 路径里的中间 `.o` 文件，
   会对每个目标报 `No such file or directory`。`build.ps1` 默认把 target 放到
   `%LOCALAPPDATA%\HWShareWin\build`，可用 `HWSHARE_TARGET_DIR` 覆盖。
2. **别给 `build.ps1` 加 `2>&1`。** 脚本里 `$ErrorActionPreference = 'Stop'`，cargo 往 stderr
   打一行 `Compiling ...` 就会被 PowerShell 当成 `NativeCommandError` 中止。

---

## 运行时数据

全部在 `%LOCALAPPDATA%\HWShareWin\`：

| 文件 | 内容 |
| --- | --- |
| `config.json` | 接收目录、分块大小 |
| `window.json` | 浮窗位置与贴边方向 |
| `hwshare.log` | 运行日志（超过 1 MB 轮转为 `.1`） |
| `transfers.log` | 收发记录 |
| `Huawei\identity.pem` | 本机身份密钥，首次运行自动生成 |
| `sessions\` | 协议采集，仅在设置 `HWSHARE_TRACE=1` 时产生 |

---

## 排障

| 现象 | 检查 |
| --- | --- |
| 菜单里没有设备 | 手机是否打开了「华为分享」、是否同一 Wi-Fi、防火墙是否放行 UDP 5684 |
| 发送失败 | 看 `hwshare.log` 末尾；设备列表里的 IP:端口 是否可达 |
| 接收目录不对 | 托盘菜单「选择接收文件夹…」，或直接改 `config.json` 的 `dest` |
| 开机自启动不生效 | 托盘菜单里该项应显示为已勾选；若显示「路径已变更」，说明 exe 被移动过，点一下修复 |

调试用的环境变量见 `src/src/bin/shared/app.rs` 的 `--help` 文本与 `trace.rs`，
常用的只有 `HWSHARE_DEBUG=1`（详细日志）和 `HWSHARE_TRACE=1`（协议采集）。

---

## 许可

GPL-3.0-only。协议实现参考了公开的逆向分析资料；本项目与华为、Apple 均无关联。
