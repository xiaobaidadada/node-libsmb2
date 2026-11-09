/**
 * 本地 SMB 服务端进程。
 *
 * 由 e2e_smb.js 通过 child_process 拉起，不直接手动运行。
 * 之所以要单独进程：libsmb2 用全局链表 active_contexts 管理所有 context，
 * 客户端与服务端在同一进程时，服务端的 select 循环会误处理客户端的 context，
 * 表现为断连或 "No io vectors left to read into"。
 *
 * 环境变量：
 *   SMB_PORT     监听端口
 *   SMB_ROOT     共享根目录（绝对路径）
 *   SMB_SHARE    共享名
 *   SMB_USER     用户名（留空表示匿名）
 *   SMB_PASSWORD 密码
 */
'use strict';

const fs = require('fs');
const path = require('path');
const { Smb2Server } = require('../js');

const port = Number(process.env.SMB_PORT);
const root = process.env.SMB_ROOT;
const share_name = process.env.SMB_SHARE || 'test';
const username = process.env.SMB_USER || '';
const password = process.env.SMB_PASSWORD || '';

if (!port || !root) {
  console.error('[smb-server] 缺少 SMB_PORT / SMB_ROOT');
  process.exit(1);
}

// 准备共享目录和几个固定文件，测试结束时由父进程清理
fs.mkdirSync(root, { recursive: true });
fs.writeFileSync(path.join(root, 'hello.txt'), 'hello smb2');
fs.mkdirSync(path.join(root, 'sub'), { recursive: true });
fs.writeFileSync(path.join(root, 'sub', 'nested.txt'), 'nested file');

const server = new Smb2Server();
server.start({
  port,
  name: 'filecat-test',
  shares: [{ name: share_name, path: root, remark: 'node-libsmb2 e2e' }],
  username,
  password,
});

// 通知父进程已就绪
if (process.send) {
  process.send({ type: 'ready', port, share: share_name });
}

process.on('message', (msg) => {
  if (msg && msg.type === 'stop') {
    try {
      server.stop();
    } catch (e) {
      // 已经停了
    }
    process.exit(0);
  }
});

process.on('uncaughtException', (e) => {
  console.error('[smb-server] 未捕获异常:', e && e.stack || e);
  process.exit(1);
});

process.on('disconnect', () => process.exit(0));
