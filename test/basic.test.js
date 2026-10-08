/**
 * 基础测试 —— 不需要真实 SMB 服务端，验证模块加载与纯函数逻辑。
 *
 * 运行： node test/basic.test.js
 */
const assert = require('assert');
const {Smb2Client, normalize_path} = require('../js');

let passed = 0;
function ok(name, fn) {
  fn();
  passed++;
  console.log(`  ✓ ${name}`);
}

console.log('模块加载');
ok('导出 Smb2Client', () => assert.strictEqual(typeof Smb2Client, 'function'));
ok('导出 normalize_path', () => assert.strictEqual(typeof normalize_path, 'function'));

console.log('\nnormalize_path');
ok('空值 → 根目录', () => {
  assert.strictEqual(normalize_path(''), '/');
  assert.strictEqual(normalize_path(null), '/');
  assert.strictEqual(normalize_path(undefined), '/');
});
ok('补前导斜杠', () => assert.strictEqual(normalize_path('a/b'), '/a/b'));
ok('去末尾斜杠', () => assert.strictEqual(normalize_path('a/b/'), '/a/b'));
ok('合并重复斜杠', () => assert.strictEqual(normalize_path('/a//b///c'), '/a/b/c'));
ok('反斜杠转正斜杠', () => assert.strictEqual(normalize_path('\\a\\b'), '/a/b'));
ok('根目录保持', () => assert.strictEqual(normalize_path('/'), '/'));

console.log('\nSmb2Client 实例');
const client = new Smb2Client();
ok('初始未连接', () => assert.strictEqual(client.is_connected, false));
ok('断开未连接实例不报错', () => assert.strictEqual(typeof client.disconnect, 'function'));

const methods = [
  'connect', 'disconnect', 'opendir', 'stat', 'exists', 'read', 'write',
  'read_file', 'write_file', 'walk', 'unlink', 'mkdir', 'rmdir', 'rename', 'truncate',
  'share_enum',
];
ok(`暴露 ${methods.length} 个方法`, () => {
  for (const m of methods) {
    assert.strictEqual(typeof client[m], 'function', `缺少方法 ${m}`);
  }
});

console.log(`\n全部通过：${passed} 项`);
