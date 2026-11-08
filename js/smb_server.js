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
    // 共享名 → { path, readonly }
    this._shares = new Map();
    this._readonly = false;
    // 服务级账号：SMB 认证在 session 阶段，此时还没有共享上下文
    this._username = '';
    this._password = '';
    // 已返回过的 (句柄, pattern) → 已发出的条目名集合。
    // SMB2 客户端带 file_index=0 反复拉取，需要分批返回：
    // 每次只给还没发过的条目，全部发完后再回空，客户端才会收到 NO_MORE_FILES。
    this._qd_sent = new Map();
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
    if (!Array.isArray(opts.shares) || opts.shares.length === 0) {
      throw new Error('shares 不能为空');
    }

    this._shares.clear();
    const shares = [];
    for (const s of opts.shares) {
      const name = String(s.name || '');
      if (!name) {
        throw new Error('共享名不能为空');
      }
      if (this._shares.has(name)) {
        throw new Error(`共享名重复: ${name}`);
      }
      const share_path = path.resolve(s.path || '');
      if (!fs.existsSync(share_path)) {
        throw new Error(`共享目录不存在: ${name} -> ${share_path}`);
      }
      this._shares.set(name, {
        path: share_path,
        readonly: Boolean(s.readonly),
      });
      shares.push({ name, path: share_path, remark: s.remark || 'FileCat' });
    }

    this._readonly = Boolean(opts.readonly);
    this._username = opts.username ? String(opts.username) : '';
    this._password = opts.password ? String(opts.password) : '';

    return this._impl.start({
      port: opts.port,
      name: opts.name || 'filecat',
      // 共享列表：每条一行 "name\tpath\tremark"，供 NetrShareEnum 枚举与 tree_connect 定位
      shares: shares.map((x) => `${x.name}\t${x.path}\t${x.remark || ''}`).join('\n'),
      // 配了账号就需要认证
      allow_anonymous: !this._password,
      api: this,
    });
  }

  /** 按共享名取共享配置，不存在时抛错 */
  _share(name) {
    const s = this._shares.get(String(name || ''));
    if (!s) {
      const e = new Error('no such share');
      e.smb_status = 0xc00000cc; /* STATUS_BAD_NETWORK_NAME */
      throw e;
    }
    return s;
  }

  stop() {
    return this._impl.stop();
  }

  /* ---------------- 以下方法被 C++ 同步调用 ---------------- */

  /** 把 SMB 相对路径按指定共享转成真实系统路径，并防止 ../ 逃逸出共享根 */
  _resolve(share_name, inner_path) {
    const share = this._share(share_name);
    const root = share.path;
    const rel = String(inner_path || '').replace(/\\/g, '/').replace(/^\/+/, '');
    const full = path.resolve(root, rel);
    if (full !== root && !full.startsWith(root + path.sep)) {
      throw new Error('path escape');
    }
    return full;
  }

  /** 该共享是否只读（服务级或共享级任一为真） */
  _share_readonly(share_name) {
    return this._readonly || this._share(share_name).readonly;
  }

  authorize(payload) {
    // SMB 认证发生在 session setup 阶段，此时客户端还没说要访问哪个共享，
    // 因此账号是服务级的：一套用户名密码管所有共享。
    // 共享级的差异只体现在「只读」上，由 tree_connect 之后的各操作判断。
    const user = String(payload.user || '');
    if (this._username && user !== this._username) {
      throw new Error('user not found');
    }
    if (!this._password) {
      throw new Error('user not found');
    }
    // 返回密码明文，libsmb2 内部用它做 NTLMv2 校验
    return this._password;
  }

  create(payload) {
    let full;
    let readonly;
    try {
      full = this._resolve(payload.share, payload.name);
      readonly = this._share_readonly(payload.share);
    } catch (e) {
      return { error: -13 /* EACCES */ };
    }

    const desired = payload.desired_access;
    const disposition = payload.create_disposition;

    // SMB2 create_disposition 语义：
    //   0 FILE_SUPERSEDE     存在则覆盖为空，不存在则创建
    //   1 FILE_OPEN          必须存在
    //   2 FILE_CREATE        必须不存在
    //   3 FILE_OPEN_IF       存在则打开，不存在则创建
    //   4 FILE_OVERWRITE     必须存在，覆盖为空
    //   5 FILE_OVERWRITE_IF  存在则覆盖为空，不存在则创建
    const is_open = disposition === 1;
    let existed = false;
    let st = null;
    try {
      st = fs.statSync(full);
      existed = true;
    } catch (e) {
      st = null;
    }

    if (st && (disposition === 0 || disposition === 4 || disposition === 5)) {
      // 覆盖类：必须先截断为 0，否则客户端会以旧大小为准再发 SET_INFO 清空数据
      if (readonly) {
        return { error: -13 };
      }
      if (!st.isDirectory()) {
        try {
          fs.truncateSync(full, 0);
          st = fs.statSync(full);
        } catch (e) {
          return { error: -13 };
        }
      }
    }

    if (!st) {
      if (is_open || disposition === 4) {
        return { error: -2 /* ENOENT */ };
      }
      if (readonly) {
        return { error: -13 };
      }
      try {
        // 路径以 / 结尾或 CREATE_OPTIONS 带 FILE_DIRECTORY_FILE(0x1) 视为建目录
        const opts = Number(payload.create_options) || 0;
        const want_dir = (opts & 0x1) !== 0 ||
          String(payload.name).endsWith('/');
        if (want_dir) {
          fs.mkdirSync(full, { recursive: true });
        } else {          fs.mkdirSync(path.dirname(full), { recursive: true });
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

    // SMB2_FILE_DELETE_ON_CLOSE：客户端 unlink/rmdir 用这种方式删除
    const delete_on_close = (payload.create_options & 0x1000) !== 0;
    if (delete_on_close && readonly) {
      return { error: -13 };
    }

    // FILE_SUPERSEDED=0 / FILE_OPENED=1 / FILE_CREATED=2 / FILE_OVERWRITTEN=3
    const create_action = !existed ? 2
      : (disposition === 0 || disposition === 4 || disposition === 5) ? 3
      : 1;
    return {
      is_dir,
      path: full,
      size: st.size,
      create_action,
      delete_on_close,
    };
  }
  close(payload) {
    return null;
  }

  delete(payload) {
    if (this._share_readonly(payload.share)) {
      return { error: -13 };
    }
    try {
      const st = fs.lstatSync(payload.path);
      if (st.isDirectory()) {
        fs.rmdirSync(payload.path);
      } else {
        fs.unlinkSync(payload.path);
      }
      return null;
    } catch (e) {
      return { error: -13 };
    }
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
    if (this._share_readonly(payload.share)) {
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

  rename(payload) {
    if (this._share_readonly(payload.share)) {
      return { error: -13 };
    }
    try {
      const target = this._resolve(payload.share, payload.name);
      fs.renameSync(payload.path, target);
      // 回传新的绝对路径，交给 C++ 更新句柄
      return target;
    } catch (e) {
      console.error("[smb-server] rename 失败:", payload.path, "->", payload.name, e && e.message);
      return { error: -13 };
    }
  }

  truncate(payload) {
    if (this._share_readonly(payload.share)) {
      return { error: -13 };
    }
    try {
      const fd = fs.openSync(payload.path, "r+");
      fs.ftruncateSync(fd, payload.offset);
      fs.closeSync(fd);
      return null;
    } catch (e) {
      return { error: -13 };
    }
  }

  queryDirectory(payload) {
    // 路径由 C++ 侧按句柄查好后传进来，JS 侧不维护句柄表
    const full = payload.path;
    if (!full) {
      return null;
    }

    // 客户端每次带一个 pattern（可能是 "*" 也可能是指定文件名）。
    // 同一 (句柄, pattern) 分批返回：先记下所有匹配项，每次只给还没发过的，
    // 全部发完后再回空，客户端才会收到 NO_MORE_FILES 停止翻页。
    const key = payload.handle_id + '\u0000' + (payload.pattern || '');
    let sent = this._qd_sent.get(key);
    if (!sent) {
      sent = new Set();
      this._qd_sent.set(key, sent);
    }

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
      if (sent.has(d.name)) {
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
      if (entries.length >= 32) {
        break;
      }
    }

    if (entries.length === 0) {
      return null;
    }
    for (const e of entries) {
      sent.add(e.name);
    }
    // 返回条目数组，由 C++ 侧填 smb2_fileidbothdirectoryinformation 结构体：
    // libsmb2 会把 output_buffer 当成结构体数组再序列化，不能给已编码字节
    return entries;
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
    // 只回原始属性，序列化成 SMB 结构体由 C++ 侧负责：
    // libsmb2 会把 output_buffer 当成 C 结构体解析，不能回已编码的字节流
    return {
      path: full,
      size: st.size,
      mtime: Math.floor(st.mtimeMs / 1000),
      is_dir: st.isDirectory(),
    };
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
