# node-libsmb2

基于 [libsmb2](https://github.com/sahlberg/libsmb2) 的 Node.js N-API 原生插件，提供 SMB2/SMB3 客户端能力。

不依赖任何预编译二进制，`npm install` 时直接用系统 C 编译器把自带的 libsmb2 源码编译进来。

## 特点

- **纯源码构建**：libsmb2 上游源码完整放在 `c-libsmb2/`，随包编译，无需外部 `libsmb2` 安装
- **SMB2 / SMB3**：走 libsmb2 的协议实现
- **NTLM 认证**：支持用户名 / 密码 / 域
- **异步不阻塞**：所有网络操作提交到 libuv 线程池，不卡 Node 事件循环
- **支持 Range 读取**：`read(path, {offset, length})`，适合视频拖动、断点续传

## 安装

```bash
npm install node-libsmb2

```

安装过程：

1. `preinstall` 跑 `scripts/gen_config.js`，按当前平台生成 `c-libsmb2/build/config.h`
2. `install` 跑 `node-gyp rebuild --release`，把 libsmb2 与 N-API 绑定一起编译

构建环境要求（`node-gyp` 依赖系统自带的编译器和 Python，npm 装不了）：

| 平台    | 依赖                                                              |
| ------- | ----------------------------------------------------------------- |
| macOS   | Xcode Command Line Tools（`xcode-select --install`）+ Python 3    |
| Linux   | build-essential、python3                                          |
| Windows | Visual Studio Build Tools（含「使用 C++ 的桌面开发」工作负载）+ Python 3 |

环境不具备时会在这个阶段报错，常见提示：

| 提示 | 缺什么 |
| --- | --- |
| `gyp ERR! find VS` | Windows 缺 VS Build Tools |
| `xcrun: error: invalid active developer path` | macOS 缺 Xcode CLT |
| `gyp ERR! find Python` | 缺 Python 3 |

若你的环境不便编译，可用 `npm install --ignore-scripts` 只装 JS 部分（此时模块不可用）。

Windows 支持来自 libsmb2 自带的 `lib/compat.h` Winsock 兼容层（`poll`→`WSAPoll`、`readv`/`writev`→`WSARecv`/`WSASend`、errno→`WSA*` 映射）；安装时生成的 `config.h` 不打开任何 POSIX 头即可走该分支。

## 用法

```js
const {Smb2Client} = require('node-libsmb2');

const client = new Smb2Client();

await client.connect({
  server: '192.168.1.10',
  share: 'public',
  user: 'alice',
  password: 'secret',
});

const entries = await client.opendir('/');
console.log(entries);

await client.disconnect();

```

### 枚举共享

连接之前不知道共享名叫什么时，可以先列出来（走 IPC$ 的 NetrShareEnum）：

```js
const shares = await client.share_enum({
  server: '192.168.1.10',
  user: 'alice',
  password: 'secret',
});
// [{name: 'public', remark: '', is_ipc: false}, ...]

```

## API

见 `js/index.d.ts`。

## 测试

```bash
node test/basic.test.js   # 不需要真实 SMB 服务端

```

## 许可

MIT。内置的 libsmb2 遵循其自身许可（LGPL-2.1 / BSD-3-Clause），见 `c-libsmb2/`。
