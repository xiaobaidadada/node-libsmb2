/**
 * node-smb2 — 基于 libsmb2 的 SMB2/3 客户端
 * node-smb2 — SMB2/3 client built on libsmb2
 */

/** 目录项 / 文件信息 | Directory entry / file info */
export interface Smb2Stat {
  /** 类型 | Type */
  type: 'file' | 'dir';
  /** 文件大小（字节，BigInt 字符串形式） | File size in bytes (as bigint) */
  size: bigint;
  /** inode 号 | Inode number */
  ino: bigint;
  /** 硬链接数 | Hard link count */
  nlink: number;
  /** 访问时间（秒） | Access time (seconds) */
  atime: number;
  /** 修改时间（秒） | Modification time (seconds) */
  mtime: number;
  /** 创建时间（秒） | Creation time (seconds) */
  ctime: number;
  /** 创建时间（秒） | Birth time (seconds) */
  btime: number;
}

/** 目录项 | Directory entry */
export interface Smb2DirEntry {
  name: string;
  type: 'file' | 'dir';
  size: bigint;
  mtime: number;
  ctime: number;
  atime: number;
}

/** 目录项 + 完整路径（walk 返回） | Directory entry with full path (returned by walk) */
export interface Smb2WalkEntry extends Smb2DirEntry {
  path: string;
}

/** 共享列表项 | Share entry */
export interface Smb2ShareEntry {
  /** 共享名（用户在系统里看到的名字） | Share name (as shown on the remote host) */
  name: string;
  /** 备注 / 描述 | Remark / description */
  remark: string;
  /** 是否是 IPC$ 之类的系统共享，展示时应过滤 | Whether it is a system share like IPC$, should be filtered out when displaying */
  is_ipc: boolean;
}

export interface Smb2ConnectOptions {
  /** 主机名或 IP | Host name or IP */
  server: string;
  /** 共享名 | Share name */
  share: string;
  /** 用户名 | User name */
  user?: string;
  /** 密码 | Password */
  password?: string;
  /** 域（工作组可留空） | Domain (empty for workgroup) */
  domain?: string;
  /** 认证方式，默认 ntlmssp | Auth method, defaults to ntlmssp */
  security?: 'ntlmssp' | 'krb5';
  /** 超时秒数，默认 60 | Timeout in seconds, defaults to 60 */
  timeout?: number;
}

export interface Smb2ShareOptions {
  /** 主机名或 IP | Host name or IP */
  server: string;
  /** 用户名 | User name */
  user?: string;
  /** 密码 | Password */
  password?: string;
  /** 域 | Domain */
  domain?: string;
  /** 认证方式，默认 ntlmssp | Auth method, defaults to ntlmssp */
  security?: 'ntlmssp' | 'krb5';
  /** 超时秒数，默认 60 | Timeout in seconds, defaults to 60 */
  timeout?: number;
}

export interface Smb2ReadOptions {
  /** 起始偏移，默认 0 | Start offset, defaults to 0 */
  offset?: number | bigint;
  /** 读取长度，默认 64KB | Read length, defaults to 64KB */
  length?: number;
}

export interface Smb2WriteOptions {
  /** 写入偏移，默认 0（即覆盖开头） | Write offset, defaults to 0 (overwrite from the start) */
  offset?: number | bigint;
}

/**
 * 服务端配置 | Server options
 *
 * 注意：底层 handler 由 C++ 在服务线程同步调用，服务端文件操作使用 fs 同步 API，
 * 这是协议层的硬性约束（返回值要立刻填进 SMB reply），与普通的异步 API 用法不同。
 *
 * Note: handlers are invoked synchronously from the C++ service thread, so the
 * server uses fs sync APIs internally. This is a protocol-level constraint
 * (the return value must be written into the SMB reply immediately).
 */
export interface Smb2ServerOptions {
  /** 监听端口，1~65535。SMB 默认 445，非 root 环境请用高位端口 | Listen port, 1~65535. SMB uses 445 by default; use a high port when not running as root */
  port: number;
  /** 共享根目录的绝对路径，必须已存在 | Absolute path of the share root, must exist */
  root: string;
  /** 只读模式，开启后拒绝写入/创建/删除 | Read-only mode, rejects write/create/delete */
  readonly?: boolean;
  /** 服务端主机名，默认 "filecat" | Server hostname, defaults to "filecat" */
  name?: string;
  /** 登录用户名，配置后强制 NTLM 认证；留空则匿名访问 | Login user name; when set, NTLM auth is enforced. Empty means anonymous access */
  username?: string;
  /** 登录密码 | Login password */
  password?: string;
}

/**
 * SMB2/3 服务端 — 把本地目录通过 SMB 协议对外提供。
 *
 * SMB2/3 server — exposes a local directory over the SMB protocol.
 *
 * 与 Smb2Client 的关系：全库共用 libsmb2 的全局状态，同一进程内同时跑客户端和
 * 服务端会互相干扰，实际使用时建议把服务端放在独立子进程里。
 *
 * Relationship with Smb2Client: libsmb2 keeps global state, so running a client
 * and a server in the same process interferes with each other. In practice the
 * server should run in a separate child process.
 */
export class Smb2Server {
  constructor();

  /** 服务是否正在运行 | Whether the server is running */
  readonly is_running: boolean;

  /**
   * 启动服务。
   *
   * 根目录不存在或端口非法时会抛错。
   *
   * Start the server. Throws if the root directory is missing or the port is invalid.
   */
  start(opts: Smb2ServerOptions): Promise<boolean>;

  /** 停止服务（可重复调用） | Stop the server (safe to call multiple times) */
  stop(): Promise<boolean>;
}

export class Smb2Client {
  constructor();

  /** 是否已连接 | Whether the client is connected */
  readonly is_connected: boolean;

  /** 连接共享 | Connect to a share */
  connect(opts: Smb2ConnectOptions): Promise<boolean>;

  /** 断开连接（可重复调用） | Disconnect (safe to call multiple times) */
  disconnect(): Promise<boolean>;

  /**
   * 枚举远程主机的共享列表，用于让用户挑选共享名。
   * 内部通过 IPC$ 走 NetrShareEnum，与当前连接无关，无需先 connect。
   *
   * Enumerate the remote host's shares so the user can pick one.
   * Uses NetrShareEnum over IPC$ internally, independent of the current
   * connection; connect() is not required first.
   */
  share_enum(opts: Smb2ShareOptions): Promise<Smb2ShareEntry[]>;

  /** 列目录 | List a directory */
  opendir(dir_path: string): Promise<Smb2DirEntry[]>;

  /** 读取文件/目录信息，不存在返回 null | Stat a file/dir, returns null if not found */
  stat(file_path: string): Promise<Smb2Stat | null>;

  /** 路径是否存在 | Whether the path exists */
  exists(target_path: string): Promise<boolean>;

  /** 读取文件片段 | Read a chunk of a file */
  read(file_path: string, opts?: Smb2ReadOptions): Promise<Buffer>;

  /** 写入文件片段（不存在则创建） | Write a chunk to a file (creates it if missing) */
  write(file_path: string, data: Buffer, opts?: Smb2WriteOptions): Promise<number>;

  /** 完整读取整个文件 | Read the whole file */
  read_file(file_path: string, chunk_size?: number): Promise<Buffer>;

  /** 完整写入文件（先清空） | Write the whole file (truncates first) */
  write_file(file_path: string, data: Buffer, chunk_size?: number): Promise<number>;

  /** 递归遍历目录 | Recursively walk a directory */
  walk(
    dir_path: string,
    on_entry?: (entry: Smb2WalkEntry) => void
  ): Promise<Smb2WalkEntry[]>;

  /** 删除文件 | Delete a file */
  unlink(file_path: string): Promise<boolean>;

  /** 新建目录 | Create a directory */
  mkdir(dir_path: string): Promise<boolean>;

  /** 删除空目录 | Remove an empty directory */
  rmdir(dir_path: string): Promise<boolean>;

  /** 重命名 / 移动 | Rename / move */
  rename(old_path: string, new_path: string): Promise<boolean>;

  /** 清空文件内容 | Truncate a file */
  truncate(file_path: string): Promise<boolean>;
}

/** 把路径归一化为 SMB 风格（正斜杠、以 / 开头、去掉末尾 /） | Normalize a path to SMB style (forward slashes, leading /, no trailing /) */
export function normalize_path(p: string): string;
