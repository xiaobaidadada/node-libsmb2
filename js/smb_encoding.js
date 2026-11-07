'use strict';

/**
 * SMB2 目录项与文件信息编码。
 *
 * 这两个结构体（FILE_ID_BOTH_DIR_INFORMATION / FILE_ALL_INFORMATION）在
 * libsmb2 里是 C 结构体，服务端要手工拼字节流回给客户端。字段布局必须
 * 与 Windows 的 wire format 严格一致，否则资源管理器会直接断开连接。
 *
 * 参考：c-libsmb2/examples/smb2-server-sync.c 的 fill_dir_info / fill_file_info
 */

// 目录项按 4 字节对齐（对应 libsmb2 的 PAD_TO_32BIT）
const PAD_TO_4 = (x) => (x + 3) & ~3;
const PAD_TO_64BIT = (x) => (x + 7) & ~7;  // 8 字节对齐（SMB2 目录项要求）

/** 秒级时间 → Windows FILETIME（100ns，1601-01-01 起） */
function unix_to_filetime(seconds) {
  if (!seconds || seconds <= 0) {
    return 0n;
  }
  return (BigInt(Math.floor(seconds)) + 11644473600n) * 10000000n;
}

/**
 * 编码 FILE_ID_BOTH_DIR_INFORMATION 链表。
 *
 * 客户端 opendir 默认用 FILE_ID_FULL_DIR_INFORMATION（0x25）。
 * 定长部分 80 字节（libsmb2 的 SMB2_FILEID_FULL_DIRECTORY_INFORMATION_SIZE）：
 *   NextEntryOffset(4) FileIndex(4)
 *   CreationTime(8) LastAccessTime(8) LastWriteTime(8) ChangeTime(8)
 *   EndOfFile(8) AllocationSize(8)
 *   FileAttributes(4) FileNameLength(4) EaSize(4) Reserved(4) FileId(8)
 *   FileName(variable, UTF16LE)
 *
 * @param {Array<{name,type,size,mtime,ctime,atime}>} entries
 * @param {number} buffer_length 客户端给的最大缓冲，超出要截断（分页）
 * @returns {{buffer: Buffer, next_index: number}}
 */
function encode_dir_entries(entries, buffer_length) {
  const chunks = [];
  let total = 0;

  for (const e of entries) {
    const name = Buffer.from(e.name, 'utf16le');
    // 固定头 80 字节：EaSize(4) 之后还有 Reserved(4) 和 FileId(8)
    const entry_len = PAD_TO_4(80 + name.length);

    // 加上这一条就超了客户端缓冲，停止
    if (total + entry_len > buffer_length) {
      break;
    }

    const buf = Buffer.alloc(entry_len);
    let off = 0;

    off += 4;  // NextEntryOffset 最后统一填
    buf.writeUInt32LE(chunks.length, off); // FileIndex
    off += 4;

    const ctime = unix_to_filetime(e.ctime || e.mtime);
    const atime = unix_to_filetime(e.atime || e.mtime);
    const mtime = unix_to_filetime(e.mtime);
    buf.writeBigUInt64LE(ctime, off); off += 8;   // CreationTime
    buf.writeBigUInt64LE(atime, off); off += 8;   // LastAccessTime
    buf.writeBigUInt64LE(mtime, off); off += 8;   // LastWriteTime
    buf.writeBigUInt64LE(mtime, off); off += 8;   // ChangeTime

    const size = BigInt(e.size || 0);
    buf.writeBigUInt64LE(size, off); off += 8;    // EndOfFile
    buf.writeBigUInt64LE(size, off); off += 8;    // AllocationSize

    const attrs = e.type === 'dir' ? 0x10 : 0x80; // DIRECTORY : NORMAL
    buf.writeUInt32LE(attrs, off); off += 4;      // FileAttributes

    buf.writeUInt32LE(name.length, off); off += 4; // FileNameLength
    buf.writeUInt32LE(0, off); off += 4;           // EaSize
    buf.writeUInt32LE(0, off); off += 4;           // Reserved
    buf.writeBigUInt64LE(0n, off);                 // FileId（客户端不校验，置 0）

    name.copy(buf, 80);

    chunks.push(buf);
    total += entry_len;
  }

  // 填 NextEntryOffset：最后一条为 0
  let next_index = entries.length;
  if (chunks.length) {
    let pos = 0;
    for (let i = 0; i < chunks.length; i++) {
      if (i < chunks.length - 1) {
        chunks[i].writeUInt32LE(chunks[i].length, 0);
      } else {
        chunks[i].writeUInt32LE(0, 0);
      }
      pos += chunks[i].length;
    }
    next_index = chunks.length;
  }

  return { buffer: Buffer.concat(chunks), next_index };
}

/**
 * 编码 SMB2_FILE_ALL_INFORMATION（query_info 的 FILE_ALL_INFORMATION class）。
 *
 * 布局与 libsmb2 的 smb2_encode_file_all_info 对齐：
 *   0   basic：CreationTime(8) AccessTime(8) WriteTime(8) ChangeTime(8)
 *              FileAttributes(4) Reserved(4)
 *   40  standard：AllocationSize(8) EndOfFile(8)
 *                 NumberOfLinks(4) DeletePending(1) Directory(1) Reserved(2)
 *   64  IndexNumber(8)
 *   72  EaSize(4)
 *   76  AccessFlags(4)
 *   80  CurrentByteOffset(8)
 *   88  Mode(4)
 *   92  AlignmentRequirement(4)
 *   96  FileNameLength(4)
 *   100 FileName
 */
function encode_file_all_info(stat) {
  const size = BigInt(stat.size || 0);
  const ctime = unix_to_filetime(stat.ctime || stat.mtime);
  const atime = unix_to_filetime(stat.atime || stat.mtime);
  const mtime = unix_to_filetime(stat.mtime);
  const is_dir = stat.type === 'dir';

  const buf = Buffer.alloc(100);

  // basic
  buf.writeBigUInt64LE(ctime, 0);   // CreationTime
  buf.writeBigUInt64LE(atime, 8);   // LastAccessTime
  buf.writeBigUInt64LE(mtime, 16);  // LastWriteTime
  buf.writeBigUInt64LE(mtime, 24);  // ChangeTime
  buf.writeUInt32LE(is_dir ? 0x10 : 0x80, 32);  // FileAttributes
  buf.writeUInt32LE(0, 36);                     // Reserved

  // standard
  buf.writeBigUInt64LE(size, 40);   // AllocationSize
  buf.writeBigUInt64LE(size, 48);   // EndOfFile
  buf.writeUInt32LE(1, 56);         // NumberOfLinks
  buf.writeUInt8(0, 60);            // DeletePending
  buf.writeUInt8(is_dir ? 1 : 0, 61); // Directory
  buf.writeUInt16LE(0, 62);         // Reserved

  buf.writeBigUInt64LE(0n, 64);     // IndexNumber
  buf.writeUInt32LE(0, 72);         // EaSize
  buf.writeUInt32LE(0, 76);         // AccessFlags
  buf.writeBigUInt64LE(0n, 80);     // CurrentByteOffset
  buf.writeUInt32LE(0, 88);         // Mode
  buf.writeUInt32LE(0, 92);         // AlignmentRequirement
  buf.writeUInt32LE(0, 96);         // FileNameLength（不带名字）

  return buf;
}

module.exports = {
  encode_dir_entries,
  PAD_TO_4,
  encode_file_all_info,
  unix_to_filetime,
  PAD_TO_64BIT,
};
