/**
 * 端到端测试：本地起 SMB 服务端，再用客户端连上去跑完整读写流程。
 *
 * 用法（项目根目录）：
 *   node test/e2e_smb.js
 *
 * 端口可通过 SMB_TEST_PORT 覆盖，默认 14450（445 需要管理员权限）。
 */
'use strict';

const fs = require('fs');
const os = require('os');
const path = require('path');
const { fork } = require('child_process');
const { Smb2Client } = require('../js');

const PORT = Number(process.env.SMB_TEST_PORT) || 14450;
const SHARE = 'testshare';
// 默认匿名，避免不同平台的 NTLMv2 校验差异影响测试；设置 SMB_TEST_AUTH=1 启用认证
const USE_AUTH = process.env.SMB_TEST_AUTH === '1';
const USER = USE_AUTH ? 'testuser' : '';
const PASSWORD = USE_AUTH ? 'testpass123' : '';

// 共享根目录放在系统临时目录，测试结束整目录删除
const ROOT = path.join(os.tmpdir(), 'node-libsmb2-e2e-' + process.pid);
// libsmb2 的 server 参数支持 host:port，不写端口默认连 445
const SERVER = `127.0.0.1:${PORT}`;

let passed = 0;
let failed = 0;

async function step(name, fn) {
  try {
    const r = await fn();
    passed++;
    console.log(`✅ ${name}${r !== undefined ? ' => ' + r : ''}`);
    return r;
  } catch (e) {
    failed++;
    console.log(`❌ ${name} => ${e && e.message}`);
    return undefined;
  }
}

/** 拉起服务端子进程并等待 ready */
function start_server() {
  const child = fork(path.join(__dirname, 'e2e_smb_server.js'), {
    env: {
      ...process.env,
      SMB_PORT: String(PORT),
      SMB_ROOT: ROOT,
      SMB_SHARE: SHARE,
      SMB_USER: USER,
      SMB_PASSWORD: PASSWORD,
    },
    stdio: ['ignore', 'inherit', 'inherit', 'ipc'],
  });

  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error('服务端启动超时')), 15000);
    child.once('message', (msg) => {
      if (msg && msg.type === 'ready') {
        clearTimeout(timer);
        resolve(child);
      }
    });
    child.once('exit', (code) => {
      clearTimeout(timer);
      reject(new Error(`服务端提前退出, code=${code}`));
    });
  });
}

function stop_server(child) {
  return new Promise((resolve) => {
    if (!child || child.killed) {
      return resolve();
    }
    const timer = setTimeout(() => {
      try {
        child.kill('SIGKILL');
      } catch (e) {
        // 已退出
      }
      resolve();
    }, 3000);
    child.once('exit', () => {
      clearTimeout(timer);
      resolve();
    });
    try {
      child.send({ type: 'stop' });
    } catch (e) {
      clearTimeout(timer);
      resolve();
    }
  });
}

(async () => {
  let child;
  const client = new Smb2Client();

  try {
    await step('启动本地 SMB 服务端', async () => {
      child = await start_server();
      return `port=${PORT}, share=${SHARE}`;
    });

    if (!child) {
      throw new Error('服务端未启动，后续用例跳过');
    }

    await step('连接服务端', async () => {
      const opts = {
        server: SERVER,
        share: SHARE,
        timeout: 20,
      };
      // 认证模式下才传账号，匿名模式留空
      if (USER) {
        opts.user = USER;
        opts.password = PASSWORD;
      }
      await client.connect(opts);
      return `is_connected=${client.is_connected}`;
    });

    await step('列共享根目录', async () => {
      const list = await client.opendir('/');
      return list.map((e) => `${e.type === 'dir' ? '[D]' : '[F]'}${e.name}`).join(', ');
    });

    await step('stat hello.txt', async () => {
      const st = await client.stat('/hello.txt');
      if (!st) {
        throw new Error('stat 返回 null');
      }
      return `type=${st.type} size=${st.size}`;
    });

    await step('读 hello.txt', async () => {
      const buf = await client.read_file('/hello.txt');
      const text = buf.toString();
      if (text !== 'hello smb2') {
        throw new Error(`内容不符: ${JSON.stringify(text)}`);
      }
      return JSON.stringify(text);
    });

    await step('写新文件并读回', async () => {
      const content = 'written by e2e test';
      // 直接用 write 写入（write_file 内部先 truncate，对不存在的文件会失败）
      const written = await client.write('/written.txt', Buffer.from(content), { offset: 0 });
      if (written !== content.length) {
        throw new Error(`写入字节数不符: ${written}`);
      }
      const buf = await client.read_file('/written.txt');
      const text = buf.toString();
      if (text !== content) {
        throw new Error(`读回内容不符: ${JSON.stringify(text)}`);
      }
      return JSON.stringify(text);
    });

    await step('范围读取（offset=6, length=4）', async () => {
      const part = await client.read('/hello.txt', { offset: 6, length: 4 });
      const text = part.toString();
      if (text !== 'smb2') {
        throw new Error(`范围读取结果不符: ${JSON.stringify(text)}`);
      }
      return JSON.stringify(text);
    });

    await step('mkdir', async () => {
      await client.mkdir('/newdir');
      if (!(await client.exists('/newdir'))) {
        throw new Error('目录创建后不存在');
      }
      return 'ok';
    });

    await step('重命名', async () => {
      await client.rename('/written.txt', '/newdir/renamed.txt');
      if (!(await client.exists('/newdir/renamed.txt'))) {
        throw new Error('重命名后目标不存在');
      }
      return 'ok';
    });

    await step('截断已存在文件', async () => {
      await client.truncate('/newdir/renamed.txt');
      const st = await client.stat('/newdir/renamed.txt');
      if (Number(st.size) !== 0) {
        throw new Error(`截断后大小不为 0: ${st.size}`);
      }
      return `size=${st.size}`;
    });

    await step('递归遍历子目录', async () => {
      const all = await client.walk('/sub');
      return all.map((e) => e.path).join(', ');
    });

    await step('删除文件', async () => {
      await client.unlink('/newdir/renamed.txt');
      if (await client.exists('/newdir/renamed.txt')) {
        throw new Error('删除后文件仍存在');
      }
      return 'ok';
    });

    await step('删除目录', async () => {
      await client.rmdir('/newdir');
      if (await client.exists('/newdir')) {
        throw new Error('删除后目录仍存在');
      }
      return 'ok';
    });

    await step('枚举共享列表', async () => {
      const opts = {
        server: SERVER,
        timeout: 20,
      };
      if (USER) {
        opts.user = USER;
        opts.password = PASSWORD;
      }
      const shares = await client.share_enum(opts);
      const names = shares.map((s) => s.name);
      if (!names.includes(SHARE)) {
        throw new Error(`共享列表里没有 ${SHARE}: ${names.join(', ')}`);
      }
      return names.join(', ');
    });
  } catch (e) {
    failed++;
    console.log(`❌ 致命错误 => ${e && e.message}`);
  } finally {
    try {
      await client.disconnect();
    } catch (e) {
      // 已断开
    }
    await stop_server(child);
    // 清理临时共享目录
    try {
      fs.rmSync(ROOT, { recursive: true, force: true });
    } catch (e) {
      // 忽略
    }
    console.log(`\n通过 ${passed} / 失败 ${failed}`);
    process.exit(failed > 0 ? 1 : 0);
  }
})();
