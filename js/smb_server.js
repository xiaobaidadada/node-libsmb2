'use strict';

const fs = require('fs');
const path = require('path');
const { encode_dir_entries, encode_file_all_info } = require('./smb_encoding');

/**
 * SMB2/3 服务端。
 *
 * 用法：
 *   const server = new Smb2Server();
 *   await server.start({ port: 4450, root: '/srv/share', readonly: true });
 *   ...
 *   server.stop();
 *
 * 注意：handler 由 C++ 在服务线程同步调用，这里必须是同步实现
 * （用 fs 的同步 API），因为返回值要立刻填进 SMB reply。
 * 这一点与项目其它模块「禁止同步 fs」的约定不同，属于协议层的硬性约束。
 */
class Smb2Server {
  constructor(binding) {
    this._binding = binding;
    this._impl = new binding.Smb2Server();
    this._root = '/';
    this._readonly = false;
    // 已列出过内容的目录句柄，避免客户端无限翻页
    this._listed_handles = new Set();
  }

  get is_running() {
    return this._impl.isRunning();
  }

  /**
   * 启动服务。
   * @param {object} opts
   * @param {number} opts.port     监听端口（SMB 默认 445，非 root 用高位端口）
   * @param {string} opts.root     共享根目录绝对路径
   * @param {boolean} [opts.readonly] 只读模式
   * @param {string} [opts.name]   服务端主机名
   */
  start(opts) {
    if (!opts || typeof opts !== 'object') {
      throw new Error('start 需要传入配置对象');
    }
    const root = path.resolve(opts.root || '');
    if (!fs.existsSync(root)) {
      throw new Error(`根目录不存在: ${root}`);
    }
    this._root = root;
    this._readonly = Boolean(opts.readonly);

    return this._impl.start({
      port: opts.port,
      root,
      readonly: this._readonly,
      name: opts.name || 'filecat',
      api: this,
    });
  }

  stop() {
    return this._impl.stop();
  }

  /* ---------------- 以下方法被 C++ 同步调用 ---------------- */

  /** 把 SMB 相对路径转成真实系统路径，并防止 ../ 逃逸出 root */
  _resolve(inner_path) {
    const rel = String(inner_path || '').replace(/\\/g, '/').replace(/^\/+/, '');
    const full = path.resolve(this._root, rel);
    if (full !== this._root && !full.startsWith(this._root + path.sep)) {
      throw new Error('path escape');
    }
    return full;
  }

  authorize() {
    return true;
  }

  create(payload) {
    let full;
    try {
      full = this._resolve(payload.name);
    } catch (e) {
      return { error: -13 /* EACCES */ };
    }

    const desired = payload.desired_access;
    const disposition = payload.create_disposition;

    // SMB2_FILE_OPEN = 1，其它值表示创建/覆盖
    const is_open = disposition === 1;
    let st = null;
    try {
      st = fs.statSync(full);
    } catch (e) {
      st = null;
    }

    if (!st) {
      if (is_open) {
        return { error: -2 /* ENOENT */ };
      }
      if (this._readonly) {
        return { error: -13 };
      }
      try {
        // 路径以 / 结尾或 CREATE_OPTIONS 带 DIRECTORY 视为建目录
        const want_dir = payload.create_options === 1 ||
          String(payload.name).endsWith('/');
        if (want_dir) {
          fs.mkdirSync(full, { recursive: true });
        } else {
          fs.mkdirSync(path.dirname(full), { recursive: true });
          fs.writeFileSync(full, Buffer.alloc(0));
        }
        st = fs.statSync(full);
      } catch (e) {
        return { error: -13 };
      }
    }

    const is_dir = st.isDirectory();

    // 客户端用目录方式打开（CREATE_OPTIONS 带 DIRECTORY_FILE）但实际是文件时，
    // 必须拒绝，否则会被当目录列出来。
    if (payload.create_options === 1 && !is_dir) {
      return { error: -2 /* ENOENT */ };
    }

    return {
      is_dir,
      path: full,
      size: st.size,
      create_action: is_open ? 1 : 2,
    };
  }

  close(payload) {
    return null;
  }

  read(payload) {
    const full = payload.path;
    try {
      const fd = fs.openSync(full, 'r');
      const len = payload.length;
      const buf = Buffer.alloc(len);
      const n = fs.readSync(fd, buf, 0, len, payload.offset);
      fs.closeSync(fd);
      return buf.subarray(0, n);
    } catch (e) {
      return null;
    }
  }

  write(payload) {
    if (this._readonly) {
      return { error: -13 };
    }
    const full = payload.path;
    try {
      const fd = fs.openSync(full, 'r+');
      fs.writeSync(fd, payload.data, 0, payload.data.length, payload.offset);
      fs.closeSync(fd);
      return null;
    } catch (e) {
      return { error: -13 };
    }
  }

  queryDirectory(payload) {
    // 路径由 C++ 侧按句柄查好后传进来，JS 侧不维护句柄表
    const full = payload.path;

    // SMB2 客户端每轮都带 file_index=0，没法靠它区分轮次。
    // 这里按句柄记录「已列过一次」：第一轮返回全部条目，之后返回 null，
    // 由服务端回 STATUS_NO_MORE_FILES 让客户端停止翻页。
    if (this._listed_handles.has(payload.handle_id)) {
      return null;
    }
    this._listed_handles.add(payload.handle_id);

    let names;
    try {
      names = fs.readdirSync(full, { withFileTypes: true });
    } catch (e) {
      return null;
    }

    // 按客户端给的 pattern 过滤，支持 * 和 ?
    const pattern = payload.pattern && payload.pattern !== '*' ? payload.pattern : null;
    const re = pattern ? glob_to_regex(pattern) : null;

    const entries = [];
    for (const d of names) {
      if (re && !re.test(d.name)) {
        continue;
      }
      const child = path.join(full, d.name);
      let st = null;
      try {
        st = fs.statSync(child);
      } catch (e) {
        continue;
      }
      entries.push({
        name: d.name,
        type: st.isDirectory() ? 'dir' : 'file',
        size: st.size,
        mtime: Math.floor(st.mtimeMs / 1000),
        ctime: Math.floor(st.ctimeMs / 1000),
        atime: Math.floor(st.atimeMs / 1000),
      });
    }

    if (entries.length === 0) {
      return null;
    }
    const result = encode_dir_entries(entries, payload.buffer_length || 65536);
    if (result.buffer.length === 0) {
      return null;
    }
    return result.buffer;
  }

  queryInfo(payload) {
    const full = payload.path;
    if (!full) {
      return null;
    }
    let st;
    try {
      st = fs.statSync(full);
    } catch (e) {
      return null;
    }
    return encode_file_all_info({
      type: st.isDirectory() ? 'dir' : 'file',
      size: st.size,
      mtime: Math.floor(st.mtimeMs / 1000),
      ctime: Math.floor(st.ctimeMs / 1000),
      atime: Math.floor(st.atimeMs / 1000),
    });
  }
}

function glob_to_regex(pattern) {
  let s = '^';
  for (const ch of pattern) {
    if (ch === '*') {
      s += '.*';
    } else if (ch === '?') {
      s += '.';
    } else {
      s += ch.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    }
  }
  return new RegExp(s + '$', 'i');
}

module.exports = {
  Smb2Server,
};
