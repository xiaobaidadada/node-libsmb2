'use strict';

const path = require('path');

/**
 * 底层 N-API 模块。
 * 构建产物在 build/Release/node_libsmb2.node（安装时由 node-gyp 现场编译）。
 */
function load_binding() {
  const candidates = [
    path.join(__dirname, '..', 'build', 'Release', 'node_libsmb2.node'),
    path.join(__dirname, '..', 'build', 'Debug', 'node_libsmb2.node'),
  ];
  let last_err;
  for (const file of candidates) {
    try {
      return require(file);
    } catch (e) {
      last_err = e;
    }
  }
  throw last_err;
}

const binding = load_binding();

/**
 * SMB2/3 客户端。
 *
 * 用法：
 *   const client = new Smb2Client();
 *   await client.connect({ server, share, user, password, domain });
 *   const list = await client.opendir('/');
 *   await client.disconnect();
 */
class Smb2Client {
  constructor() {
    this._impl = new binding.Smb2Client();
  }

  get is_connected() {
    return this._impl.isConnected();
  }

  /**
   * 连接共享目录。
   * @param {object} opts
   * @param {string} opts.server  主机名或 IP
   * @param {string} opts.share   共享名，如 "public"
   * @param {string} [opts.user]      用户名
   * @param {string} [opts.password]  密码
   * @param {string} [opts.domain]    域（工作组可留空）
   * @param {'ntlmssp'|'krb5'} [opts.security]  认证方式，默认 ntlmssp
   * @param {number} [opts.timeout]   超时秒数，默认 60
   */
  connect(opts) {
    return this._impl.connect(opts);
  }

  /**
   * 断开连接。重复调用安全。
   */
  disconnect() {
    return this._impl.disconnect();
  }

  /**
   * 枚举远程主机的共享列表，用于让用户挑选共享名。
   * 内部通过 IPC$ 走 NetrShareEnum，与当前连接无关，无需先 connect。
   * @param {object} opts
   * @param {string} opts.server  主机名或 IP
   * @param {string} [opts.user]
   * @param {string} [opts.password]
   * @param {string} [opts.domain]
   * @param {'ntlmssp'|'krb5'} [opts.security]
   * @param {number} [opts.timeout]
   * @returns {Promise<Array<{name, remark, is_ipc}>>}
   */
  share_enum(opts) {
    return this._impl.shareEnum(opts);
  }

  /**
   * 列出目录内容。
   * @param {string} dir_path 共享内的绝对路径，根目录传 '/' 或 ''
   * @returns {Promise<Array<{name,type,size,mtime,ctime,atime}>>}
   */
  opendir(dir_path) {
    return this._impl.opendir(normalize_path(dir_path));
  }

  /**
   * 读取文件元信息，不存在返回 null。
   */
  stat(file_path) {
    return this._impl.stat(normalize_path(file_path));
  }

  /**
   * 判断路径是否存在。
   */
  async exists(target_path) {
    const st = await this.stat(target_path);
    return st !== null;
  }

  /**
   * 读取文件片段。
   * @param {string} file_path
   * @param {object} [opts]
   * @param {number|bigint} [opts.offset] 起始偏移，默认 0
   * @param {number} [opts.length] 读取长度，默认 64KB
   * @returns {Promise<Buffer>} 实际读到的数据（到文件末尾会短于 length）
   */
  read(file_path, opts) {
    return this._impl.read(normalize_path(file_path), opts);
  }

  /**
   * 写入文件片段（不存在则创建）。
   * @returns {Promise<number>} 实际写入字节数
   */
  write(file_path, data, opts) {
    const buf = Buffer.isBuffer(data) ? data : Buffer.from(data);
    return this._impl.write(normalize_path(file_path), buf, opts);
  }

  /**
   * 完整读取整个文件。
   * @param {string} file_path
   * @param {number} [chunk_size] 每块大小，默认 1MB
   * @returns {Promise<Buffer>}
   */
  async read_file(file_path, chunk_size = 1024 * 1024) {
    const st = await this.stat(file_path);
    if (!st || st.type === 'dir') {
      throw new Error(`文件不存在或不是文件: ${file_path}`);
    }
    const total = Number(st.size);
    const out = Buffer.allocUnsafe(total);
    let offset = 0;
    while (offset < total) {
      const len = Math.min(chunk_size, total - offset);
      const chunk = await this.read(file_path, { offset, length: len });
      if (chunk.length === 0) {
        break;
      }
      chunk.copy(out, offset);
      offset += chunk.length;
    }
    return out.subarray(0, offset);
  }

  /**
   * 写入整个文件（覆盖已有内容）。
   */
  async write_file(file_path, data, chunk_size = 1024 * 1024) {
    const buf = Buffer.isBuffer(data) ? data : Buffer.from(data);
    await this.truncate(file_path);
    let offset = 0;
    while (offset < buf.length) {
      const chunk = buf.subarray(offset, Math.min(offset + chunk_size, buf.length));
      const written = await this.write(file_path, chunk, { offset });
      if (written <= 0) {
        throw new Error(`写入中断: ${file_path}`);
      }
      offset += written;
    }
    return offset;
  }

  /**
   * 递归读取目录树。
   * @param {string} dir_path
   * @param {(entry: object) => void} [on_entry] 每遇到一个条目回调一次
   * @returns {Promise<Array>} 所有条目（含完整 path 字段）
   */
  async walk(dir_path, on_entry) {
    const root = normalize_path(dir_path);
    const all = [];
    const stack = [root];
    while (stack.length) {
      const cur = stack.pop();
      const entries = await this.opendir(cur);
      for (const e of entries) {
        const full = join_path(cur, e.name);
        const item = { ...e, path: full };
        all.push(item);
        if (on_entry) {
          on_entry(item);
        }
        if (e.type === 'dir') {
          stack.push(full);
        }
      }
    }
    return all;
  }

  unlink(file_path) {
    return this._impl.unlink(normalize_path(file_path));
  }

  mkdir(dir_path) {
    return this._impl.mkdir(normalize_path(dir_path));
  }

  rmdir(dir_path) {
    return this._impl.rmdir(normalize_path(dir_path));
  }

  rename(old_path, new_path) {
    return this._impl.rename(normalize_path(old_path), normalize_path(new_path));
  }

  truncate(file_path) {
    return this._impl.truncate(normalize_path(file_path));
  }
}

/**
 * 统一路径为 SMB 风格：正斜杠分隔、以 / 开头、去掉末尾多余的 /。
 * 根目录表示为 '/'。
 */
function normalize_path(p) {
  if (!p) {
    return '/';
  }
  let s = String(p).replace(/\\/g, '/').trim();
  if (!s.startsWith('/')) {
    s = '/' + s;
  }
  s = s.replace(/\/+/g, '/');
  if (s.length > 1 && s.endsWith('/')) {
    s = s.slice(0, -1);
  }
  return s;
}

function join_path(base, name) {
  if (base === '/' || base === '') {
    return '/' + name;
  }
  return base + '/' + name;
}

module.exports = {
  Smb2Client,
  normalize_path,
};
