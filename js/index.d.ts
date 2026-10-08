/**
 * node-smb2 — 基于 libsmb2 的 SMB2/3 客户端
 */

/** 目录项 / 文件信息 */
export interface Smb2Stat {
  /** 类型 */
  type: 'file' | 'dir';
  /** 文件大小（字节，BigInt 字符串形式） */
  size: bigint;
  /** inode 号 */
  ino: bigint;
  /** 硬链接数 */
  nlink: number;
  /** 访问时间（秒） */
  atime: number;
  /** 修改时间（秒） */
  mtime: number;
  /** 创建时间（秒） */
  ctime: number;
  /** 创建时间（秒） */
  btime: number;
}

/** 目录项 */
export interface Smb2DirEntry {
  name: string;
  type: 'file' | 'dir';
  size: bigint;
  mtime: number;
  ctime: number;
  atime: number;
}

/** 目录项 + 完整路径（walk 返回） */
export interface Smb2WalkEntry extends Smb2DirEntry {
  path: string;
}

/** 共享列表项 */
export interface Smb2ShareEntry {
  /** 共享名（用户在系统里看到的名字） */
  name: string;
  /** 备注 / 描述 */
  remark: string;
  /** 是否是 IPC$ 之类的系统共享，展示时应过滤 */
  is_ipc: boolean;
}

export interface Smb2ConnectOptions {
  /** 主机名或 IP */
  server: string;
  /** 共享名 */
  share: string;
  /** 用户名 */
  user?: string;
  /** 密码 */
  password?: string;
  /** 域（工作组可留空） */
  domain?: string;
  /** 认证方式，默认 ntlmssp */
  security?: 'ntlmssp' | 'krb5';
  /** 超时秒数，默认 60 */
  timeout?: number;
}

export interface Smb2ShareOptions {
  /** 主机名或 IP */
  server: string;
  /** 用户名 */
  user?: string;
  /** 密码 */
  password?: string;
  /** 域 */
  domain?: string;
  /** 认证方式，默认 ntlmssp */
  security?: 'ntlmssp' | 'krb5';
  /** 超时秒数，默认 60 */
  timeout?: number;
}

export interface Smb2ReadOptions {
  /** 起始偏移，默认 0 */
  offset?: number | bigint;
  /** 读取长度，默认 64KB */
  length?: number;
}

export interface Smb2WriteOptions {
  /** 写入偏移，默认 0（即覆盖开头） */
  offset?: number | bigint;
}

export class Smb2Client {
  constructor();

  /** 是否已连接 */
  readonly is_connected: boolean;

  /** 连接共享 */
  connect(opts: Smb2ConnectOptions): Promise<boolean>;

  /** 断开连接（可重复调用） */
  disconnect(): Promise<boolean>;

  /**
   * 枚举远程主机的共享列表，用于让用户挑选共享名。
   * 内部通过 IPC$ 走 NetrShareEnum，与当前连接无关，无需先 connect。
   */
  share_enum(opts: Smb2ShareOptions): Promise<Smb2ShareEntry[]>;

  /** 列目录 */
  opendir(dir_path: string): Promise<Smb2DirEntry[]>;

  /** 读取文件/目录信息，不存在返回 null */
  stat(file_path: string): Promise<Smb2Stat | null>;

  /** 路径是否存在 */
  exists(target_path: string): Promise<boolean>;

  /** 读取文件片段 */
  read(file_path: string, opts?: Smb2ReadOptions): Promise<Buffer>;

  /** 写入文件片段（不存在则创建） */
  write(file_path: string, data: Buffer, opts?: Smb2WriteOptions): Promise<number>;

  /** 完整读取整个文件 */
  read_file(file_path: string, chunk_size?: number): Promise<Buffer>;

  /** 完整写入文件（先清空） */
  write_file(file_path: string, data: Buffer, chunk_size?: number): Promise<number>;

  /** 递归遍历目录 */
  walk(
    dir_path: string,
    on_entry?: (entry: Smb2WalkEntry) => void
  ): Promise<Smb2WalkEntry[]>;

  /** 删除文件 */
  unlink(file_path: string): Promise<boolean>;

  /** 新建目录 */
  mkdir(dir_path: string): Promise<boolean>;

  /** 删除空目录 */
  rmdir(dir_path: string): Promise<boolean>;

  /** 重命名 / 移动 */
  rename(old_path: string, new_path: string): Promise<boolean>;

  /** 清空文件内容 */
  truncate(file_path: string): Promise<boolean>;
}

/** 把路径归一化为 SMB 风格（正斜杠、以 / 开头、去掉末尾 /） */
export function normalize_path(p: string): string;
