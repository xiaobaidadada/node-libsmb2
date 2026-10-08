/**
 * 用 macOS 系统共享做端到端测试。
 *
 * 用法（在项目根目录）：
 *   node test/mac_e2e.js <用户名> <密码> [共享名]
 *
 * 注意：测试只在共享根的 __smb_test_tmp 目录内读写，结束时清理。
 */
const {Smb2Client} = require('../js');

const user = process.argv[2];
const password = process.argv[3];
const share = process.argv[4] || '111的公共文件夹';
const TMP = '__smb_test_tmp';

if (!user || !password) {
  console.error('用法: node test/mac_e2e.js <用户名> <密码> [共享名]');
  process.exit(1);
}

let passed = 0, failed = 0;
async function step(name, fn) {
  try {
    const r = await fn();
    passed++;
    console.log(`✅ ${name}${r !== undefined ? ' => ' + r : ''}`);
    return r;
  } catch (e) {
    failed++;
    console.log(`❌ ${name} => ${e.message}`);
  }
}

(async () => {
  const c = new Smb2Client();

  await step('连接共享', async () => {
    await c.connect({server: 'localhost', share, user, password, timeout: 20});
    return `is_connected=${c.is_connected}`;
  });

  await step('列根目录', async () => {
    const list = await c.opendir('/');
    return `${list.length} 项`;
  });

  await step(`列 ${TMP}`, async () => {
    const list = await c.opendir('/' + TMP);
    return list.map(e => `${e.type === 'dir' ? '[D]' : '[F]'}${e.name}`).join(', ');
  });

  await step('stat hello.txt', async () => {
    const st = await c.stat(`/${TMP}/hello.txt`);
    return st ? `type=${st.type} size=${st.size}` : 'null';
  });

  await step('读 hello.txt', async () => {
    const buf = await c.read_file(`/${TMP}/hello.txt`);
    return JSON.stringify(buf.toString());
  });

  await step('范围读取 data.bin offset=10 len=6', async () => {
    const part = await c.read(`/${TMP}/data.bin`, {offset: 10, length: 6});
    return JSON.stringify(part.toString());
  });

  await step('递归遍历', async () => {
    const all = await c.walk('/' + TMP);
    return all.map(e => e.path).join(', ');
  });

  await step('写入新文件', async () => {
    await c.write_file(`/${TMP}/written.txt`, Buffer.from('written by node-smb2'));
    return 'ok';
  });

  await step('读回写入内容', async () => {
    const buf = await c.read_file(`/${TMP}/written.txt`);
    return JSON.stringify(buf.toString());
  });

  await step('mkdir', async () => {
    await c.mkdir(`/${TMP}/newdir`);
    return 'ok';
  });

  await step('rename', async () => {
    await c.rename(`/${TMP}/written.txt`, `/${TMP}/newdir/renamed.txt`);
    return 'ok';
  });

  await step('确认重命名后存在', async () => {
    return String(await c.exists(`/${TMP}/newdir/renamed.txt`));
  });

  await step('删除文件', async () => {
    await c.unlink(`/${TMP}/newdir/renamed.txt`);
    return 'ok';
  });

  await step('删除目录', async () => {
    await c.rmdir(`/${TMP}/newdir`);
    return 'ok';
  });

  await c.disconnect();
  console.log(`\n通过 ${passed} / 失败 ${failed}`);
  process.exit(failed > 0 ? 1 : 0);
})();
