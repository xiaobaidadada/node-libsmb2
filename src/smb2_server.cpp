#include "smb2_server.h"
#include "dcerpc/dcerpc.h"
#include "dcerpc/server.h"
#include "dcerpc/srvsvc.h"

#include <cstring>
#include <chrono>
#include <vector>

/* ---------------------------------------------------------------- */
/* file_id <-> handle                                                */
/* ---------------------------------------------------------------- */

// smb2_file_id 是 uint8_t[16]，前 8 字节存 handle id
static void handle_to_file_id(uint64_t h, smb2_file_id fid) {
    memset(fid, 0, SMB2_FD_SIZE);
    memcpy(fid, &h, sizeof(h));
}

static uint64_t file_id_to_handle(const smb2_file_id fid) {
    uint64_t h = 0;
    memcpy(&h, fid, sizeof(h));
    return h;
}

/* ---------------------------------------------------------------- */
/* handler 实现                                                      */
/* ---------------------------------------------------------------- */

struct ServerHandlers {
    static Smb2Server *self_;

    // 统一入口：构造 Smb2Req → CallJs → 读结果
    static bool call(Smb2Server *self, Smb2Req &req) {
        return self->CallJs(req);
    }
    static int authorize(struct smb2_server *srvr, struct smb2_context *smb2,
                         const char *user, const char *domain,
                         const char *workstation) {
        Smb2Req r;
        r.op = "authorize";
        r.user = user ? user : "";
        r.domain = domain ? domain : "";
        r.workstation = workstation ? workstation : "";
        if (!call(self_, r)) {
            return -1;
        }
        if (r.err != 0) {
            // JS 侧抛错表示用户不存在，直接拒绝
            return -EACCES;
        }
        // 把密码交给 libsmb2，由它内部做 NTLMv2 校验
        if (!r.out_password.empty()) {
            // libsmb2 用 smb2->user 参与 NTLMv2 计算，必须先写入用户名
            if (user) {
                smb2_set_user(smb2, user);
            }
            smb2_set_password(smb2, r.out_password.c_str());
        }
        return 0;
    }

    static int create_cmd(struct smb2_server *srvr, struct smb2_context *smb2,
                          struct smb2_create_request *req,
                          struct smb2_create_reply *rep) {
        memset(rep, 0, sizeof(*rep));
        std::string req_name = req->name ? req->name : "";

        // FILE_OPEN_BY_FILE_ID：Windows 打开列表里的文件时 name 为空，
        // 真正的 file_id 放在 create context 的 FILE_OPEN_BY_FILE_ID(0x0A) 里。
        // 不处理这条会把“按 ID 打开”误当成“打开共享根目录”，
        // 造成双击文件、新建、删除等操作全部失败。
        if (req_name.empty() &&
            (req->create_options & SMB2_FILE_OPEN_BY_FILE_ID) != 0 &&
            req->create_context != NULL &&
            req->create_context_length >= 24) {
            const uint8_t *cc = req->create_context;
            size_t left = req->create_context_length;
            // [MS-SMB2] 2.2.13.2 CREATE context：
            // ChainNext(4) + NameOffset(2) + NameLength(2) + Reserved(4) + Name + Data
            // 头部固定 12 字节，NameOffset 相对 context 起点。
            while (left >= 12) {
                uint32_t chain = (uint32_t)(cc[0] | (cc[1] << 8) |
                                            (cc[2] << 16) | (cc[3] << 24));
                uint16_t noff = (uint16_t)(cc[4] | (cc[5] << 8));
                uint16_t nlen = (uint16_t)(cc[6] | (cc[7] << 8));
                // FILE_OPEN_BY_FILE_ID 的 tag 是 10 字节 "FileId:   "
                if (nlen >= 10 && (size_t)noff + nlen <= left &&
                    memcmp(cc + noff, "FileId:   ", 10) == 0) {
                    smb2_file_id fid;
                    memset(fid, 0, SMB2_FD_SIZE);
                    memcpy(fid, cc + 8, SMB2_FD_SIZE);
                    std::string by_id_path;
                    if (self_->get_handle(file_id_to_handle(fid), &by_id_path)) {
                        req_name = by_id_path;
                    }
                    break;
                }
                if (chain == 0 || chain > left) {
                    break;
                }
                cc += chain;
                left -= chain;
            }
        }

        std::string trimmed = req_name;
        while (!trimmed.empty() &&
               (trimmed[0] == '\\' || trimmed[0] == '/')) {
            trimmed.erase(0, 1);
        }

        // IPC$ 上的请求是命名管道（srvsvc/lsarpc/mdssvc 等）。
        // tree_id 取自请求头，能准确区分 IPC$ 与磁盘共享；
        // 再用已知管道名兜一层，避免 tree_id 尚未绑定时的误判。
        static const char *const known_pipes[] = {"srvsvc", "lsarpc", "samr",
                                                  "winreg", "netlogon", "spoolss",
                                                  "mdssvc", "msftewds"};
        bool name_is_pipe = false;
        std::string lower = trimmed;
        for (size_t i = 0; i < lower.size(); i++) {
            lower[i] = (char)tolower((unsigned char)lower[i]);
        }
        for (size_t i = 0; i < sizeof(known_pipes) / sizeof(known_pipes[0]); i++) {
            if (lower == known_pipes[i]) {
                name_is_pipe = true;
                break;
            }
        }

        if (self_->is_ipc_tree(smb2) || name_is_pipe) {
            // 只实现 srvsvc（共享枚举）；其它管道一律以 OBJECT_NAME_NOT_FOUND
            // 拒绝，客户端会退回只用磁盘共享，不会因此断开连接
            if (lower != "srvsvc") {
                return -ENOENT;
            }
            uint64_t ph = self_->add_pipe_handle("srvsvc");
            handle_to_file_id(ph, rep->file_id);
            self_->set_last_file_id(smb2, rep->file_id);
            rep->oplock_level = 0;
            rep->flags = 0;
            rep->file_attributes = SMB2_FILE_ATTRIBUTE_NORMAL;
            rep->create_action = 2;
            rep->end_of_file = 0;
            rep->allocation_size = 0;
            rep->create_context_length = 0;
            return 0;
        }

        Smb2Req r;
        r.op = "create";
        r.share = self_->disk_share(smb2);
        r.name = req->name ? req->name : "";
        r.desired_access = req->desired_access;
        r.create_disposition = req->create_disposition;
        r.create_options = req->create_options;

        if (!call(self_, r)) {
            // 返回 -1 会被 libsmb2 转成 STATUS_NOT_IMPLEMENTED 并可能让
            // 客户端判定共享不可用；用 ENOENT 表示“没有这个对象”更合适
            return -ENOENT;
        }
        if (r.err != 0) {
            return r.err;
        }

        // 登记句柄：后续 read/write/query_directory 都靠它反查路径。
        // 不能直接用 JS 返回的 handle 值，统一由 C++ 侧分配，避免和 JS 侧编号冲突。
        uint64_t handle = self_->add_handle(r.out_path);
        handle_to_file_id(handle, rep->file_id);
        self_->set_last_file_id(smb2, rep->file_id);
        if (r.out_delete_on_close) {
            self_->mark_pending_delete(handle, r.out_path);
        }
        rep->oplock_level = 0;  // SMB2_OPLOCK_LEVEL_NONE
        rep->flags = 0;
        rep->file_attributes =
            r.out_is_dir ? SMB2_FILE_ATTRIBUTE_DIRECTORY
                         : (SMB2_FILE_ATTRIBUTE_ARCHIVE | SMB2_FILE_ATTRIBUTE_NORMAL);
        rep->create_action = r.out_create_action;
        // 目录的 end_of_file 必须为 0，否则客户端会把目录当有内容的文件
        rep->end_of_file = r.out_is_dir ? 0 : r.out_size;
        rep->allocation_size = r.out_is_dir ? 0 : r.out_size;
        rep->create_context_length = 0;

        return 0;
    }

    // tree_connect 的 path 是 UTF-16LE，形如 \\\\server\\IPC$
    static bool is_ipc_path(const uint16_t *p, uint32_t byte_len) {
        if (p == NULL || byte_len < 8) {
            return false;
        }
        size_t chars = byte_len / 2;
        if (chars < 4) {
            return false;
        }
        // 尾部必须是 IPC$（$ 用字符码 0x24 表示，避免 shell 展开）
        const uint16_t tail[4] = {0x49, 0x50, 0x43, 0x24};
        for (int i = 0; i < 4; i++) {
            if (p[chars - 4 + i] != tail[i]) {
                return false;
            }
        }
        return true;
    }

    // compound 请求里 CREATE 之后的 PDU 带 RELATED_OPERATIONS 且 file_id 全 F，
    // 需要回退到当前链上一个 create 的 file_id。
    static uint64_t resolve_handle(Smb2Server *self, struct smb2_context *smb2,
                                   const smb2_file_id fid) {
        uint64_t handle = file_id_to_handle(fid);
        if (handle == 0xFFFFFFFFFFFFFFFFULL) {
            smb2_file_id last;
            if (self->get_last_file_id(smb2, last)) {
                handle = file_id_to_handle(last);
            }
        }
        return handle;
    }

    // UTF-16LE → UTF-8，遇到 0 结束
    static std::string utf16_to_utf8(const uint8_t *raw, size_t byte_len) {
        std::string out;
        size_t n = byte_len / 2;
        for (size_t i = 0; i < n; i++) {
            uint16_t lo = raw[i * 2];
            uint16_t hi = raw[i * 2 + 1];
            uint32_t cp = (uint32_t)lo | ((uint32_t)hi << 8);
            if (cp == 0) {
                break;
            }
            if (cp >= 0xD800 && cp <= 0xDBFF && i + 1 < n) {
                uint32_t low = (uint32_t)raw[(i + 1) * 2] | ((uint32_t)raw[(i + 1) * 2 + 1] << 8);
                if (low >= 0xDC00 && low <= 0xDFFF) {
                    cp = 0x10000 + ((cp - 0xD800) << 10) + (low - 0xDC00);
                    i++;
                }
            }
            if (cp < 0x80) {
                out += (char)cp;
            } else if (cp < 0x800) {
                out += (char)(0xC0 | (cp >> 6));
                out += (char)(0x80 | (cp & 0x3F));
            } else if (cp < 0x10000) {
                out += (char)(0xE0 | (cp >> 12));
                out += (char)(0x80 | ((cp >> 6) & 0x3F));
                out += (char)(0x80 | (cp & 0x3F));
            } else {
                out += (char)(0xF0 | (cp >> 18));
                out += (char)(0x80 | ((cp >> 12) & 0x3F));
                out += (char)(0x80 | ((cp >> 6) & 0x3F));
                out += (char)(0x80 | (cp & 0x3F));
            }
        }
        return out;
    }

    static int tree_connect_cmd(struct smb2_server *srvr, struct smb2_context *smb2,
                                struct smb2_tree_connect_request *req,
                                struct smb2_tree_connect_reply *rep) {
        memset(rep, 0, sizeof(*rep));
        // IPC$ 是命名管道共享，srvsvc 的 NetrShareEnum 从这里进；
        // 其它名字一律当磁盘共享，映射到共享根目录。
        if (is_ipc_path(req->path, req->path_length)) {
            self_->set_ipc_tree(smb2, true);
            rep->share_type = SMB2_SHARE_TYPE_PIPE;
            rep->share_flags = 0;
            rep->capabilities = 0;
            rep->maximal_access = 0x001f01ff;
            return 0;
        }
        // 磁盘共享：req->path 是 UTF-16LE，形如 \\server\share，
        // 取最后一段作为共享名（前面是主机名，服务端不需要）
        std::string share;
        if (req->path) {
            uint32_t chars = req->path_length / 2;
            // 从尾部往前找最后一个反斜杠
            uint32_t end = chars;
            uint32_t begin = 0;
            for (uint32_t i = chars; i > 0; i--) {
                if (req->path[i - 1] == 0x5c || req->path[i - 1] == 0x2f) {
                    begin = i;
                    break;
                }
            }
            // UTF-16LE → UTF-8（共享名一般都落在 BMP 内）
            for (uint32_t i = begin; i < end; i++) {
                uint16_t cp = req->path[i];
                if (cp < 0x80) {
                    share.push_back((char)cp);
                } else if (cp < 0x800) {
                    share.push_back((char)(0xc0 | (cp >> 6)));
                    share.push_back((char)(0x80 | (cp & 0x3f)));
                } else {
                    share.push_back((char)(0xe0 | (cp >> 12)));
                    share.push_back((char)(0x80 | ((cp >> 6) & 0x3f)));
                    share.push_back((char)(0x80 | (cp & 0x3f)));
                }
            }
        }
        if (share.empty() || !self_->has_share(share)) {
            // 返回负数由 libsmb2 统一转成错误应答，客户端会把这个共享显示为不可用
            return -1;
        }
        // 存配置里的规范名，后续按共享名查目录时才能命中
        std::string canonical = self_->canonical_share(share);
        self_->set_ipc_tree(smb2, false);
        self_->set_tree_share(smb2, canonical);
        rep->share_type = SMB2_SHARE_TYPE_DISK;
        rep->share_flags = 0;
        rep->capabilities = 0;
        rep->maximal_access = 0x001f01ff;  // 全权限
        return 0;
    }

    static int tree_disconnect_cmd(struct smb2_server *srvr, struct smb2_context *smb2,
                                   const uint32_t tree_id) {
        self_->clear_tree_share(smb2);
        return 0;
    }

    static int session_established_cmd(struct smb2_server *srvr, struct smb2_context *smb2) {
        // 返回 0 表示会话建立成功；不实现这个 handler 时服务端会回
        // STATUS_NOT_IMPLEMENTED，客户端收到后直接断开。
        return 0;
    }

    static int close_cmd(struct smb2_server *srvr, struct smb2_context *smb2,
                         struct smb2_close_request *req,
                         struct smb2_close_reply *rep) {
        memset(rep, 0, sizeof(*rep));
        uint64_t h = resolve_handle(self_, smb2, req->file_id);
        std::string pipe_name;
        if (self_->get_pipe_name(h, &pipe_name)) {
            self_->del_pipe_handle(h);
            self_->drop_last_file_id(smb2);
            return 0;
        }
        std::string del_path;
        if (self_->take_pending_delete(h, &del_path)) {
            Smb2Req del_req;
            del_req.op = "delete";
            del_req.share = self_->disk_share(smb2);
            del_req.path = del_path;
            call(self_, del_req);
        }
        self_->drop_last_file_id(smb2);
        self_->del_handle(h);
        rep->file_attributes = SMB2_FILE_ATTRIBUTE_NORMAL;
        return 0;
    }

    static int read_cmd(struct smb2_server *srvr, struct smb2_context *smb2,
                        struct smb2_read_request *req,
                        struct smb2_read_reply *rep) {
        memset(rep, 0, sizeof(*rep));
        // 读不依赖 passthrough，但前一个 handler 可能把它关掉，
        // 这里显式设为 1 保持全局状态可预期
        smb2_set_passthrough(smb2, 1);
        uint64_t h = file_id_to_handle(req->file_id);
        std::string path;
        if (!self_->get_handle(h, &path)) {
            return -ENOENT;
        }

        Smb2Req r;
        r.op = "read";
        r.share = self_->disk_share(smb2);
        r.path = path;
        r.handle_id = h;
        r.offset = req->offset;
        r.length = req->length;

        if (!call(self_, r)) {
            return -1;
        }

        rep->data_remaining = 0;
        if (r.out_bytes.empty()) {
            rep->data = nullptr;
            rep->data_length = 0;
            rep->data_offset = 0;
            return 0;
        }
        // libsmb2 回包后会 free(rep->data)，必须 malloc 拷贝
        size_t len = r.out_bytes.size();
        rep->data = (uint8_t *)malloc(len);
        if (!rep->data) {
            return -ENOMEM;
        }
        memcpy(rep->data, r.out_bytes.data(), len);
        rep->data_offset = 0;
        rep->data_length = (uint32_t)len;
        return 0;
    }

    static int write_cmd(struct smb2_server *srvr, struct smb2_context *smb2,
                         struct smb2_write_request *req,
                         struct smb2_write_reply *rep) {
        memset(rep, 0, sizeof(*rep));
        // 写请求的数据区依赖 passthrough 才会被填充到 req->buf，
        // queryDirectory 为避免结构体内存外泄会把它关掉，这里补回来
        smb2_set_passthrough(smb2, 1);
        uint64_t h = file_id_to_handle(req->file_id);
        std::string path;
        if (!self_->get_handle(h, &path)) {
            return -ENOENT;
        }
        if (self_->readonly()) {
            return -EACCES;
        }

        Smb2Req r;
        r.op = "write";
        r.share = self_->disk_share(smb2);
        r.path = path;
        r.handle_id = h;
        r.offset = req->offset;
        r.length = req->length;
        r.data.assign((const char *)req->buf, req->length);

        if (!call(self_, r)) {
            return -1;
        }
        if (r.err != 0) {
            return r.err;
        }
        rep->count = req->length;
        rep->remaining = 0;
        return 0;
    }

    // rename（FILE_RENAME_INFORMATION）与截断（END_OF_FILE）
    static int set_info_cmd(struct smb2_server *srvr, struct smb2_context *smb2,
                            struct smb2_set_info_request *req) {
        uint64_t h = resolve_handle(self_, smb2, req->file_id);
        std::string file_path;
        if (!self_->get_handle(h, &file_path)) {
            return -ENOENT;
        }
        if (self_->readonly()) {
            return -EACCES;
        }

        if (req->file_info_class == SMB2_FILE_RENAME_INFORMATION) {
            // 线格式：ReplaceIfExists(1) + 保留(7) + FileNameLength(4, 偏移16) +
            // FileName[]（UTF-16LE，偏移 20 起）
            const uint8_t *raw = (const uint8_t *)req->input_data;
            if (raw == NULL || req->buffer_length < 20) {
                return -EINVAL;
            }
            uint32_t name_len = (uint32_t)raw[16] | ((uint32_t)raw[17] << 8) |
                                ((uint32_t)raw[18] << 16) | ((uint32_t)raw[19] << 24);
            if (name_len == 0 || name_len > req->buffer_length - 20) {
                name_len = req->buffer_length - 20;
            }
            std::string target = utf16_to_utf8(raw + 20, name_len);
            if (target.empty()) {
                return -EINVAL;
            }

            Smb2Req r;
            r.op = "rename";
            r.share = self_->disk_share(smb2);
            r.path = file_path;
            r.name = target;
            if (!call(self_, r)) {
                return -1;
            }
            if (r.err != 0) {
                return r.err;
            }
            self_->rename_handle(h, r.out_path.empty() ? target : r.out_path);
            return 0;
        }

        if (req->file_info_class == SMB2_FILE_END_OF_FILE_INFORMATION) {
            auto *ei = (struct smb2_file_end_of_file_info *)req->input_data;
            if (ei == NULL) {
                return -EINVAL;
            }
            Smb2Req r;
            r.op = "truncate";
            r.share = self_->disk_share(smb2);
            r.path = file_path;
            r.offset = ei->end_of_file;
            if (!call(self_, r)) {
                return -1;
            }
            if (r.err != 0) {
                return r.err;
            }
            return 0;
        }

        if (req->file_info_class == SMB2_FILE_DISPOSITION_INFORMATION) {
            // 线格式：DeletePending(1) + 保留(1)
            const uint8_t *raw = (const uint8_t *)req->input_data;
            if (raw == NULL || req->buffer_length < 1) {
                return -EINVAL;
            }
            if (raw[0] == 0) {
                // 取消删除标记
                return 0;
            }
            Smb2Req r;
            r.op = "delete";
            r.share = self_->disk_share(smb2);
            r.path = file_path;
            if (!call(self_, r)) {
                return -ENOENT;
            }
            if (r.err != 0) {
                return r.err;
            }
            return 0;
        }

        return -EOPNOTSUPP;
    }

    // ── DCE/RPC 服务端（libdcerpc 官方 server runtime）──────────────
    // 只负责业务数据：编解码、bind、分片、call_id 全由 dcerpc_server_* 处理。

    static int srvsvc_NetrShareEnum_stub(struct dcerpc_context *dce,
                                         struct dcerpc_pdu *pdu,
                                         void *req_v, void *rep_v) {
        struct srvsvc_NetrShareEnum_req *req =
            (struct srvsvc_NetrShareEnum_req *)req_v;
        struct srvsvc_NetrShareEnum_rep *rep =
            (struct srvsvc_NetrShareEnum_rep *)rep_v;

        uint32_t level = req->InfoStruct.Level;
        const std::vector<std::pair<std::string, std::string>> &shares =
            self_->shares();
        uint32_t count = (uint32_t)shares.size();
        const std::string &remark = self_->share_remark();
        size_t alloc_count = count > 0 ? count : 1;

        rep->InfoStruct.Level = level;
        rep->TotalEntries = count;
        rep->ResumeHandle = 0;
        rep->status = 0;

        if (level == 0) {
            struct srvsvc_SHARE_INFO_0 *buf = (struct srvsvc_SHARE_INFO_0 *)
                dcerpc_alloc_data(pdu, sizeof(*buf) * alloc_count);
            if (buf == NULL) {
                return -1;
            }
            for (uint32_t i = 0; i < count; i++) {
                buf[i].NetName = (char *)shares[i].first.c_str();
            }
            rep->InfoStruct.ShareInfo.Level0.EntriesRead = count;
            rep->InfoStruct.ShareInfo.Level0.Buffer = buf;
        } else if (level == 1) {
            struct srvsvc_SHARE_INFO_1 *buf = (struct srvsvc_SHARE_INFO_1 *)
                dcerpc_alloc_data(pdu, sizeof(*buf) * alloc_count);
            if (buf == NULL) {
                return -1;
            }
            for (uint32_t i = 0; i < count; i++) {
                buf[i].NetName = (char *)shares[i].first.c_str();
                buf[i].Type = 0;  // STYPE_DISKTREE
                buf[i].Remark = (char *)remark.c_str();
            }
            rep->InfoStruct.ShareInfo.Level1.EntriesRead = count;
            rep->InfoStruct.ShareInfo.Level1.Buffer = buf;
        } else if (level == 2) {
            struct srvsvc_SHARE_INFO_2 *buf = (struct srvsvc_SHARE_INFO_2 *)
                dcerpc_alloc_data(pdu, sizeof(*buf) * alloc_count);
            if (buf == NULL) {
                return -1;
            }
            for (uint32_t i = 0; i < count; i++) {
                buf[i].NetName = (char *)shares[i].first.c_str();
                buf[i].Type = 0;
                buf[i].Remark = (char *)remark.c_str();
                buf[i].Permissions = 0;
                buf[i].MaxUses = 0xffffffff;
                buf[i].CurrentUses = 0;
                buf[i].Path = (char *)shares[i].second.c_str();
                buf[i].Passwd = (char *)"";
            }
            rep->InfoStruct.ShareInfo.Level2.EntriesRead = count;
            rep->InfoStruct.ShareInfo.Level2.Buffer = buf;
        } else {
            return DCERPC_FAULT_OP_RNG_ERROR;
        }
        return 0;
    }

    // 资源管理器还会调 NetrShareGetInfo（\\host\share 属性页）
    static int srvsvc_NetrShareGetInfo_stub(struct dcerpc_context *dce,
                                            struct dcerpc_pdu *pdu,
                                            void *req_v, void *rep_v) {
        struct srvsvc_NetrShareGetInfo_req *req =
            (struct srvsvc_NetrShareGetInfo_req *)req_v;
        struct srvsvc_NetrShareGetInfo_rep *rep =
            (struct srvsvc_NetrShareGetInfo_rep *)rep_v;

        const std::vector<std::pair<std::string, std::string>> &shares =
            self_->shares();
        const std::string &remark = self_->share_remark();
        std::string want = req->NetName != NULL ? req->NetName : "";
        // 客户端可能传 \\host\share，只取最后一段
        size_t pos = want.find_last_of('\\');
        std::string name = (pos == std::string::npos) ? want : want.substr(pos + 1);

        uint32_t level = req->Level;
        for (size_t i = 0; i < shares.size(); i++) {
            if (shares[i].first != name) {
                continue;
            }
            if (level == 0) {
                struct srvsvc_SHARE_INFO_0 *info = (struct srvsvc_SHARE_INFO_0 *)
                    dcerpc_alloc_data(pdu, sizeof(*info));
                if (info == NULL) {
                    return -1;
                }
                info->NetName = (char *)shares[i].first.c_str();
                rep->InfoStruct.ShareInfo0 = *info;
            } else if (level == 1) {
                struct srvsvc_SHARE_INFO_1 *info = (struct srvsvc_SHARE_INFO_1 *)
                    dcerpc_alloc_data(pdu, sizeof(*info));
                if (info == NULL) {
                    return -1;
                }
                info->NetName = (char *)shares[i].first.c_str();
                info->Type = 0;
                info->Remark = (char *)remark.c_str();
                rep->InfoStruct.ShareInfo1 = *info;
            } else if (level == 2) {
                struct srvsvc_SHARE_INFO_2 *info = (struct srvsvc_SHARE_INFO_2 *)
                    dcerpc_alloc_data(pdu, sizeof(*info));
                if (info == NULL) {
                    return -1;
                }
                info->NetName = (char *)shares[i].first.c_str();
                info->Type = 0;
                info->Remark = (char *)remark.c_str();
                info->Permissions = 0;
                info->MaxUses = 0xffffffff;
                info->CurrentUses = 0;
                info->Path = (char *)shares[i].second.c_str();
                info->Passwd = (char *)"";
                rep->InfoStruct.ShareInfo2 = *info;
            } else {
                return DCERPC_FAULT_OP_RNG_ERROR;
            }
            rep->status = 0;
            return 0;
        }
        rep->status = 0x00000906;  // NERR_NetNameNotFound
        return 0;
    }

    // 双击 \\host 时客户端先问服务器信息
    static int srvsvc_NetrServerGetInfo_stub(struct dcerpc_context *dce,
                                             struct dcerpc_pdu *pdu,
                                             void *req_v, void *rep_v) {
        struct srvsvc_NetrServerGetInfo_req *req =
            (struct srvsvc_NetrServerGetInfo_req *)req_v;
        struct srvsvc_NetrServerGetInfo_rep *rep =
            (struct srvsvc_NetrServerGetInfo_rep *)rep_v;

        if (req->Level != 101) {
            return DCERPC_FAULT_OP_RNG_ERROR;
        }
        struct srvsvc_SERVER_INFO_101 *info = (struct srvsvc_SERVER_INFO_101 *)
            dcerpc_alloc_data(pdu, sizeof(*info));
        if (info == NULL) {
            return -1;
        }
        info->PlatformId = 500;      // PLATFORM_ID_NT
        info->Name = (char *)"filecat";
        info->VersionMajor = 10;
        info->VersionMinor = 0;
        info->Type = 0x00001003;     // SV_TYPE_SERVER_NT | SV_TYPE_WORKSTATION
        info->Comment = (char *)self_->share_remark().c_str();
        rep->InfoStruct.ServerInfo101 = *info;
        rep->status = 0;
        return 0;
    }


    // DCE/RPC over FSCTL_PIPE_TRANSCEIVE
    static int ioctl_cmd(struct smb2_server *srvr, struct smb2_context *smb2,
                         struct smb2_ioctl_request *req,
                         struct smb2_ioctl_reply *rep) {
        memset(rep, 0, sizeof(*rep));
        rep->ctl_code = req->ctl_code;
        memcpy(rep->file_id, req->file_id, SMB2_FD_SIZE);
        rep->input_offset = 0;
        rep->input_count = 0;
        rep->output_offset = 0;
        rep->output_count = 0;
        rep->flags = req->flags;
        rep->output = NULL;

        smb2_set_passthrough(smb2, 1);

        uint64_t h = resolve_handle(self_, smb2, req->file_id);
        std::string pipe_name;
        if (!self_->get_pipe_name(h, &pipe_name)) {
            // 非命名管道上的 ioctl 返回错误会让客户端放弃整个连接
            return 0;
        }
        if (req->ctl_code != SMB2_FSCTL_PIPE_TRANSCEIVE) {
            return -EOPNOTSUPP;
        }
        if (pipe_name != "srvsvc") {
            return -EOPNOTSUPP;
        }

        std::lock_guard<std::mutex> guard(self_->rpc_mutex_);
        if (self_->rpc_ == NULL) {
            return -ENOMEM;
        }
        struct dcerpc_server_pipe *pipe = self_->rpc_pipes_[h];
        if (pipe == NULL) {
            pipe = dcerpc_server_pipe_create(self_->rpc_, NULL);
            if (pipe == NULL) {
                return -ENOMEM;
            }
            self_->rpc_pipes_[h] = pipe;
        }

        // 客户端写入的字节原样交给 runtime
        if (req->input != NULL && req->input_count > 0) {
            if (dcerpc_server_pipe_write(pipe, (const uint8_t *)req->input,
                                         req->input_count) != 0) {
                return -EINVAL;
            }
        }

        // 取走 runtime 已排队的输出
        std::vector<uint8_t> out;
        int more = 0;
        do {
            uint8_t tmp[65536];
            size_t got = dcerpc_server_pipe_read(pipe, tmp, sizeof(tmp), &more);
            if (got == 0) {
                break;
            }
            out.insert(out.end(), tmp, tmp + got);
        } while (more);

        if (out.empty()) {
            return 0;
        }
        rep->output = malloc(out.size());
        if (rep->output == NULL) {
            return -ENOMEM;
        }
        memcpy(rep->output, out.data(), out.size());
        rep->output_count = (uint32_t)out.size();
        return 0;
    }

    static int query_directory_cmd(struct smb2_server *srvr,
                                   struct smb2_context *smb2,
                                   struct smb2_query_directory_request *req,
                                   struct smb2_query_directory_reply *rep) {
        memset(rep, 0, sizeof(*rep));
        uint64_t h = file_id_to_handle(req->file_id);
        std::string path;
        if (!self_->get_handle(h, &path)) {
            smb2_file_id last;
            memset(last, 0, SMB2_FD_SIZE);
            if (!self_->get_last_file_id(smb2, last)) {
                return -ENOENT;
            }
            h = file_id_to_handle(last);
            if (!self_->get_handle(h, &path)) {
                return -ENOENT;
            }
        }

        Smb2Req r;
        r.op = "queryDirectory";
        r.share = self_->disk_share(smb2);
        r.path = path;
        r.handle_id = h;
        r.pattern = req->name ? req->name : "*";
        r.index = req->file_index;
        r.buffer_length = req->output_buffer_length;

        if (!call(self_, r)) {
            return -1;
        }
        if (r.err != 0) {
            return r.err;
        }
        if (r.out_entries.empty()) {
            // 没有更多条目：length=0 且返回 0，libsmb2 会回 STATUS_NO_MORE_FILES；
            // 返回负值会被它转成 STATUS_NOT_IMPLEMENTED，客户端会当作错误
            rep->output_buffer = nullptr;
            rep->output_buffer_offset = 0;
            rep->output_buffer_length = 0;
            return 0;
        }

        size_t n = r.out_entries.size();
        // libsmb2 的 smb2_encode_query_directory_reply 在非 passthrough 模式下
        // 把 output_buffer 当作「结构体数组」按 PAD_TO_64BIT(sizeof(struct))
        // 定长步进读取，name 走独立指针，线上布局由它自己拼装。
        // 因此这里只要按结构体大小分配数组，并填好 name 指针即可。
        size_t bytes = sizeof(struct smb2_fileidbothdirectoryinformation) * n;
        struct smb2_fileidbothdirectoryinformation *arr =
            (struct smb2_fileidbothdirectoryinformation *)calloc(1, bytes);
        if (arr == NULL) {
            return -ENOMEM;
        }
        for (size_t i = 0; i < n; i++) {
            const Smb2Req::DirEntry &e = r.out_entries[i];
            struct smb2_fileidbothdirectoryinformation *d = &arr[i];
            d->file_index = (uint32_t)(h + i);
            d->creation_time.tv_sec = (time_t)e.mtime;
            d->last_access_time.tv_sec = (time_t)e.mtime;
            d->last_write_time.tv_sec = (time_t)e.mtime;
            d->change_time.tv_sec = (time_t)e.mtime;
            d->end_of_file = e.is_dir ? 0 : e.size;
            d->allocation_size = e.is_dir ? 0 : e.size;
            d->file_attributes = e.is_dir ? SMB2_FILE_ATTRIBUTE_DIRECTORY
                                          : (SMB2_FILE_ATTRIBUTE_ARCHIVE |
                                             SMB2_FILE_ATTRIBUTE_NORMAL);
            d->file_name_length = (uint32_t)e.name.size() * 2;
            // Windows 会拿列表里的 file_id 直接发 FILE_OPEN_BY_FILE_ID 来打开文件，
            // 所以这里必须是「指向该条目真实路径」的句柄，不能用父句柄或编造值，
            // 否则后续打开/删除等操作全部失败。
            std::string child = path;
            if (!child.empty() && child.back() != '/' && child.back() != '\\') {
                child += '/';
            }
            child += e.name;
            d->file_id = self_->add_handle(child);
            d->name = strdup(e.name.c_str());
        }
        rep->output_buffer = (uint8_t *)arr;
        rep->output_buffer_length = (uint32_t)bytes;
        smb2_set_passthrough(smb2, 0);
        return 0;
    }

    static int query_info_cmd(struct smb2_server *srvr, struct smb2_context *smb2,
                              struct smb2_query_info_request *req,
                              struct smb2_query_info_reply *rep) {
        memset(rep, 0, sizeof(*rep));
        // 注意：libsmb2 的 smb2_encode_query_info_reply 会把 rep->output_buffer
        // 直接强转成对应的 C 结构体再序列化，所以这里必须填结构体，
        // 不能填“已编码好的线上字节”，否则会被当成结构体解析并崩溃。
        static const uint8_t fs_name[] = {'N', 0, 'T', 0, 'F', 0, 'S', 0};

        // 与 queryDirectory 同理：query_info 的 output_buffer 也是 C 结构体，
        // passthrough 模式下会被原样 memcpy 出去
        smb2_set_passthrough(smb2, 0);

        // FILE_SYSTEM：卷信息，与具体文件无关，直接由 C++ 侧产生
        if (req->info_type == SMB2_0_INFO_FILESYSTEM) {
            if (req->file_info_class == SMB2_FILE_FS_ATTRIBUTE_INFORMATION) {
                struct smb2_file_fs_attribute_info *ai =
                    (struct smb2_file_fs_attribute_info *)
                    calloc(1, sizeof(*ai));
                if (ai == NULL) {
                    return -ENOMEM;
                }
                ai->filesystem_attributes = 0x00000003;
                ai->maximum_component_name_length = 255;
                ai->filesystem_name_length = sizeof(fs_name);
                ai->filesystem_name = fs_name;
                rep->output_buffer = (uint8_t *)ai;
                rep->output_buffer_length = sizeof(*ai);
                return 0;
            }
            if (req->file_info_class == SMB2_FILE_FS_SIZE_INFORMATION) {
                struct smb2_file_fs_size_info *si =
                    (struct smb2_file_fs_size_info *)calloc(1, sizeof(*si));
                if (si == NULL) {
                    return -ENOMEM;
                }
                const uint64_t unit = 4096;
                si->total_allocation_units = (uint64_t)(1ULL << 40) / unit;
                si->available_allocation_units = si->total_allocation_units;
                si->sectors_per_allocation_unit = 1;
                si->bytes_per_sector = (uint32_t)unit;
                rep->output_buffer = (uint8_t *)si;
                rep->output_buffer_length = sizeof(*si);
                return 0;
            }
            return -EOPNOTSUPP;
        }

        uint64_t h = file_id_to_handle(req->file_id);
        std::string path;
        if (!self_->get_handle(h, &path)) {
            // 复合请求中后续 PDU 的 file_id 为全 F，表示沿用上一个 CREATE 的句柄
            smb2_file_id last;
            memset(last, 0, SMB2_FD_SIZE);
            if (!self_->get_last_file_id(smb2, last)) {
                return -ENOENT;
            }
            h = file_id_to_handle(last);
            if (!self_->get_handle(h, &path)) {
                return -ENOENT;
            }
        }

        // FILE_ALL_INFORMATION：文件/目录属性
        if (req->info_type == SMB2_0_INFO_FILE &&
            req->file_info_class == SMB2_FILE_ALL_INFORMATION) {
            Smb2Req r;
            r.op = "queryInfo";
            r.share = self_->disk_share(smb2);
            r.path = path;
            r.handle_id = h;
            if (!call(self_, r)) {
                return -1;
            }
            if (r.err != 0) {
                return r.err;
            }
            size_t plen = r.out_path.size();
            // libsmb2 的 smb2_encode_file_all_info 会把 name 按 UTF-16 写到结构体
            // 之后，调用方已按 output_buffer_length + 1024 预留了空间，
            // 这里只需按结构体大小分配并挂好 name 指针。
            struct smb2_file_all_info *fi =
                (struct smb2_file_all_info *)calloc(1, sizeof(*fi));
            if (fi == NULL) {
                return -ENOMEM;
            }
            // 时间字段是 struct smb2_timeval { tv_sec, tv_usec }，
            // 由 libsmb2 的 smb2_encode_file_all_info 转成 FILETIME
            fi->basic.creation_time.tv_sec = (time_t)r.out_mtime;
            fi->basic.last_access_time.tv_sec = (time_t)r.out_mtime;
            fi->basic.last_write_time.tv_sec = (time_t)r.out_mtime;
            fi->basic.change_time.tv_sec = (time_t)r.out_mtime;
            fi->basic.file_attributes =
                r.out_is_dir ? SMB2_FILE_ATTRIBUTE_DIRECTORY
                             : (SMB2_FILE_ATTRIBUTE_ARCHIVE | SMB2_FILE_ATTRIBUTE_NORMAL);
            fi->standard.allocation_size = r.out_is_dir ? 0 : r.out_size;
            fi->standard.end_of_file = r.out_is_dir ? 0 : r.out_size;
            fi->standard.number_of_links = 1;
            fi->standard.directory = r.out_is_dir ? 1 : 0;
            fi->index_number = h;
            fi->name = plen ? (const uint8_t *)strdup(r.out_path.c_str()) : NULL;
            rep->output_buffer = (uint8_t *)fi;
            rep->output_buffer_length = sizeof(*fi);
            return 0;
        }

        // FILE_NETWORK_OPEN_INFORMATION：Windows 打开文件前用它预取大小/时间，
        // 不支持会导致资源管理器与记事本判定文件不可用
        if (req->info_type == SMB2_0_INFO_FILE &&
            req->file_info_class == SMB2_FILE_NETWORK_OPEN_INFORMATION) {
            Smb2Req r;
            r.op = "queryInfo";
            r.share = self_->disk_share(smb2);
            r.path = path;
            r.handle_id = h;
            if (!call(self_, r)) {
                return -1;
            }
            if (r.err != 0) {
                return r.err;
            }
            struct smb2_file_network_open_info *ni =
                (struct smb2_file_network_open_info *)calloc(1, sizeof(*ni));
            if (ni == NULL) {
                return -ENOMEM;
            }
            ni->creation_time.tv_sec = (time_t)r.out_mtime;
            ni->last_access_time.tv_sec = (time_t)r.out_mtime;
            ni->last_write_time.tv_sec = (time_t)r.out_mtime;
            ni->change_time.tv_sec = (time_t)r.out_mtime;
            ni->allocation_size = r.out_is_dir ? 0 : r.out_size;
            ni->end_of_file = r.out_is_dir ? 0 : r.out_size;
            ni->file_attributes =
                r.out_is_dir ? SMB2_FILE_ATTRIBUTE_DIRECTORY
                             : (SMB2_FILE_ATTRIBUTE_ARCHIVE | SMB2_FILE_ATTRIBUTE_NORMAL);
            rep->output_buffer = (uint8_t *)ni;
            rep->output_buffer_length = sizeof(*ni);
            return 0;
        }

        // FILE_BASIC_INFORMATION：属性框的时间与属性列
        if (req->info_type == SMB2_0_INFO_FILE &&
            req->file_info_class == SMB2_FILE_BASIC_INFORMATION) {
            Smb2Req r;
            r.op = "queryInfo";
            r.share = self_->disk_share(smb2);
            r.path = path;
            r.handle_id = h;
            if (!call(self_, r)) {
                return -1;
            }
            if (r.err != 0) {
                return r.err;
            }
            struct smb2_file_basic_info *bi =
                (struct smb2_file_basic_info *)calloc(1, sizeof(*bi));
            if (bi == NULL) {
                return -ENOMEM;
            }
            bi->creation_time.tv_sec = (time_t)r.out_mtime;
            bi->last_access_time.tv_sec = (time_t)r.out_mtime;
            bi->last_write_time.tv_sec = (time_t)r.out_mtime;
            bi->change_time.tv_sec = (time_t)r.out_mtime;
            bi->file_attributes =
                r.out_is_dir ? SMB2_FILE_ATTRIBUTE_DIRECTORY
                             : (SMB2_FILE_ATTRIBUTE_ARCHIVE | SMB2_FILE_ATTRIBUTE_NORMAL);
            rep->output_buffer = (uint8_t *)bi;
            rep->output_buffer_length = sizeof(*bi);
            return 0;
        }

        return -EOPNOTSUPP;
    }
};

Smb2Server *ServerHandlers::self_ = nullptr;

// srvsvc 的 stub 表：opnum -> 业务函数。放在类外，Start() 与 ServerHandlers 都能用。
static const struct dcerpc_stub g_srvsvc_stubs[] = {
    {SRVSVC_NETRSHAREENUM,     (char *)"NetrShareEnum",     ServerHandlers::srvsvc_NetrShareEnum_stub},
    {SRVSVC_NETRSHAREGETINFO,  (char *)"NetrShareGetInfo",  ServerHandlers::srvsvc_NetrShareGetInfo_stub},
    {SRVSVC_NETRSERVERGETINFO, (char *)"NetrServerGetInfo", ServerHandlers::srvsvc_NetrServerGetInfo_stub},
    {0, NULL, NULL}
};

static struct smb2_server_request_handlers g_handlers = {
    nullptr,                              // destruction_event
    ServerHandlers::authorize,            // authorize_user
    ServerHandlers::session_established_cmd,  // session_established
    nullptr,                              // logoff_cmd
    ServerHandlers::tree_connect_cmd,     // tree_connect_cmd
    ServerHandlers::tree_disconnect_cmd,  // tree_disconnect_cmd
    ServerHandlers::create_cmd,           // create_cmd
    ServerHandlers::close_cmd,            // close_cmd
    nullptr,                              // flush_cmd
    ServerHandlers::read_cmd,             // read_cmd
    ServerHandlers::write_cmd,            // write_cmd
    nullptr,                              // oplock_break_cmd
    nullptr,                              // lease_break_cmd
    nullptr,                              // lock_cmd
    ServerHandlers::ioctl_cmd,            // ioctl_cmd
    nullptr,                              // cancel_cmd
    nullptr,                              // echo_cmd
    ServerHandlers::query_directory_cmd,  // query_directory_cmd
    nullptr,                              // change_notify_cmd
    ServerHandlers::query_info_cmd,       // query_info_cmd
    ServerHandlers::set_info_cmd,          // set_info_cmd
};

/* ---------------------------------------------------------------- */
/* Smb2Server                                                        */
/* ---------------------------------------------------------------- */

Napi::Object Smb2Server::Init(Napi::Env env, Napi::Object exports) {
    Napi::Function func = DefineClass(
        env, "Smb2Server",
        {
            InstanceMethod("start", &Smb2Server::Start),
            InstanceMethod("stop", &Smb2Server::Stop),
            InstanceMethod("isRunning", &Smb2Server::IsRunning),
        });
    exports.Set("Smb2Server", func);
    return exports;
}

Smb2Server::Smb2Server(const Napi::CallbackInfo &info)
    : Napi::ObjectWrap<Smb2Server>(info) {}

Smb2Server::~Smb2Server() {
    if (running_) {
        server_.stop_requested = 1;
        if (thread_.joinable()) {
            thread_.join();
        }
    }
    if (tsfn_) {
        tsfn_.Release();
        tsfn_ = nullptr;
    }
}

Napi::Value Smb2Server::IsRunning(const Napi::CallbackInfo &info) {
    return Napi::Boolean::New(info.Env(), running_.load());
}

Napi::Value Smb2Server::Start(const Napi::CallbackInfo &info) {
    Napi::Env env = info.Env();

    if (info.Length() < 1 || !info[0].IsObject()) {
        throw Napi::TypeError::New(env, "start 需要传入配置对象");
    }
    if (running_) {
        throw Napi::Error::New(env, "服务已经在运行");
    }

    auto opts = info[0].As<Napi::Object>();

    int port = 0;
    if (opts.Has("port") && opts.Get("port").IsNumber()) {
        port = opts.Get("port").As<Napi::Number>().Int32Value();
    }
    if (port <= 0 || port > 65535) {
        throw Napi::TypeError::New(env, "port 必须是 1~65535 的整数");
    }

    // 共享列表：每条一行 "name\tpath\tremark"，避免在 C++ 里解析 JSON
    shares_.clear();
    if (opts.Has("shares") && opts.Get("shares").IsString()) {
        std::string raw = opts.Get("shares").As<Napi::String>().Utf8Value();
        size_t pos = 0;
        while (pos <= raw.size()) {
            size_t nl = raw.find('\n', pos);
            std::string line = raw.substr(pos, nl == std::string::npos ? std::string::npos : nl - pos);
            pos = (nl == std::string::npos) ? raw.size() + 1 : nl + 1;
            if (line.empty()) {
                continue;
            }
            size_t t1 = line.find('\t');
            if (t1 == std::string::npos) {
                continue;
            }
            size_t t2 = line.find('\t', t1 + 1);
            std::string nm = line.substr(0, t1);
            std::string pth = t2 == std::string::npos
                                  ? line.substr(t1 + 1)
                                  : line.substr(t1 + 1, t2 - t1 - 1);
            if (!nm.empty() && !pth.empty()) {
                shares_.emplace_back(nm, pth);
            }
        }
    }
    if (shares_.empty()) {
        throw Napi::TypeError::New(env, "shares 不能为空");
    }

    readonly_ = opts.Has("readonly") && opts.Get("readonly").IsBoolean()
                    ? opts.Get("readonly").As<Napi::Boolean>().Value()
                    : false;

    if (opts.Has("remark") && opts.Get("remark").IsString()) {
        share_remark_ = opts.Get("remark").As<Napi::String>().Utf8Value();
    }

    std::string server_name = "filecat";
    if (opts.Has("name") && opts.Get("name").IsString()) {
        server_name = opts.Get("name").As<Napi::String>().Utf8Value();
    }

    if (!opts.Has("api") || !opts.Get("api").IsObject()) {
        throw Napi::TypeError::New(env, "api 必须是实现了各 handler 的对象");
    }
    api_ = Napi::Persistent(opts.Get("api").As<Napi::Object>());

    tsfn_ = Napi::ThreadSafeFunction::New(
        env, Napi::Function::New(env, [](const Napi::CallbackInfo &) {}),
        "smb2_server", 0, 1);

    bool allow_anonymous = opts.Has("allow_anonymous") && opts.Get("allow_anonymous").IsBoolean()
                              ? opts.Get("allow_anonymous").As<Napi::Boolean>().Value()
                              : true;

    memset(&server_, 0, sizeof(server_));
    server_.handlers = &g_handlers;
    server_.port = port;
    // 签名关闭：开启后服务端在 NTLM 会话密钥就绪前就会给部分 reply 签名，
    // 客户端校验失败并断开。匿名/无签名模式足以本地文件服务使用。
    server_.signing_enabled = 1;
    // 配了账号就关闭匿名，强制走 NTLM 校验
    server_.allow_anonymous = allow_anonymous ? 1 : 0;
    server_.max_read_size = 0x100000;
    server_.max_write_size = 0x100000;
    server_.max_transact_size = 0x100000;
    snprintf(server_.hostname, sizeof(server_.hostname), "%s", server_name.c_str());
    snprintf(server_.domain, sizeof(server_.domain), "%s", "WORKGROUP");

    ServerHandlers::self_ = this;

    // srvsvc 共享枚举：绑定 libdcerpc 官方服务端 runtime
    if (rpc_ == NULL) {
        rpc_ = dcerpc_server_create("srvsvc");
        if (rpc_ == NULL) {
            throw Napi::Error::New(env, "创建 DCE/RPC 服务端失败");
        }
        if (dcerpc_server_add_interface(rpc_, &srvsvc_interface, srvsvc_procs,
                                        g_srvsvc_stubs, DCERPC_SERVER_ALL_NDR) != 0) {
            dcerpc_server_destroy(rpc_);
            rpc_ = NULL;
            throw Napi::Error::New(env, "注册 srvsvc 接口失败");
        }
    }
    running_ = true;

    thread_ = std::thread([this]() { ServeLoop(); });

    // 等主循环把 fd 绑定好
    for (int i = 0; i < 100 && server_.fd == 0; i++) {
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }

    return env.Undefined();
}

void Smb2Server::ServeLoop() {
    struct smb2_context *ctx = nullptr;
    int rc = smb2_serve_port(
        &server_, 4,
        [](struct smb2_context *smb2, void *cb_data) {
            smb2_set_version(smb2, SMB2_VERSION_ANY);
            // 开启 passthrough：目录项/文件信息按 wire format 原样收发。
            // 否则 libsmb2 会把我们自己编码的 blob 当成 C 结构体重新解析，
            // 读 fs->name 指针时错乱导致服务端崩溃。
            smb2_set_passthrough(smb2, 1);
            auto *p = (struct smb2_context **)cb_data;
            *p = smb2;
        },
        &ctx);
    running_ = false;
}

Napi::Value Smb2Server::Stop(const Napi::CallbackInfo &info) {
    server_.stop_requested = 1;
    if (thread_.joinable()) {
        thread_.join();
    }
    running_ = false;
    if (rpc_ != NULL) {
        for (auto &it : rpc_pipes_) {
            dcerpc_server_pipe_destroy(it.second);
        }
        rpc_pipes_.clear();
        dcerpc_server_destroy(rpc_);
        rpc_ = NULL;
    }
    if (tsfn_) {
        tsfn_.Release();
        tsfn_ = nullptr;
    }
    return info.Env().Undefined();
}

/**
 * 跨线程调用 JS。
 *
 * 服务线程没有 HandleScope，所以这里只传 Smb2Req（纯 C++ 结构体）。
 * 主线程在 ThreadSafeFunction 回调里把 Smb2Req 转成 JS 对象、调用 api[op]，
 * 再把返回值写回同一个 Smb2Req，最后唤醒服务线程。
 */
bool Smb2Server::CallJs(Smb2Req &req) {
    if (!tsfn_) {
        return false;
    }

    struct Share {
        std::mutex mtx;
        std::condition_variable cv;
        bool done = false;
        Smb2Req *req;
    };
    Share share;
    share.req = &req;

    napi_status st = tsfn_.BlockingCall(
        &share, [](Napi::Env env, Napi::Function /*unused*/, Share *s) {
            Napi::HandleScope scope(env);
            Smb2Req &r = *s->req;

            Napi::Object api_obj = ServerHandlers::self_->api_.Value();
            if (!api_obj.Has(r.op)) {
                r.ok = false;
                std::lock_guard<std::mutex> lock(s->mtx);
                s->done = true;
                s->cv.notify_all();
                return;
            }

            // Smb2Req → JS 参数对象
            Napi::Object p = Napi::Object::New(env);
            p.Set("op", Napi::String::New(env, r.op));
            // 空串也必须下发：create 打开共享根目录时 name 为空，
            // 省略会让 JS 侧拿到 undefined 而拼出错误路径
            p.Set("share", Napi::String::New(env, r.share));
            if (r.op == "authorize") {
                p.Set("user", Napi::String::New(env, r.user));
                p.Set("domain", Napi::String::New(env, r.domain));
                p.Set("workstation", Napi::String::New(env, r.workstation));
            }
            if (r.op == "create") {
                p.Set("name", Napi::String::New(env, r.name));
                p.Set("desired_access", Napi::Number::New(env, r.desired_access));
                p.Set("create_disposition", Napi::Number::New(env, r.create_disposition));
                p.Set("create_options", Napi::Number::New(env, r.create_options));
            } else if (!r.name.empty()) {
                p.Set("name", Napi::String::New(env, r.name));
            }
            if (!r.path.empty()) {
                p.Set("path", Napi::String::New(env, r.path));
                p.Set("handle_id", Napi::Number::New(env, (double)r.handle_id));
            }
            if (r.op == "read") {
                p.Set("offset", Napi::Number::New(env, (double)r.offset));
                p.Set("length", Napi::Number::New(env, r.length));
            }
            if (r.op == "truncate") {
                p.Set("offset", Napi::Number::New(env, (double)r.offset));
            }
            if (r.op == "write") {
                p.Set("offset", Napi::Number::New(env, (double)r.offset));
                p.Set("data", Napi::Buffer<char>::Copy(env, r.data.data(), r.data.size()));
            }
            if (r.op == "queryDirectory") {
                p.Set("pattern", Napi::String::New(env, r.pattern));
                p.Set("index", Napi::Number::New(env, r.index));
                p.Set("buffer_length", Napi::Number::New(env, r.buffer_length));
            }
            if (r.op == "queryInfo") {
                p.Set("info_type", Napi::Number::New(env, r.info_type));
                p.Set("file_info_class", Napi::Number::New(env, r.file_info_class));
                p.Set("buffer_length", Napi::Number::New(env, r.buffer_length));
            }

            Napi::Function fn = api_obj.Get(r.op).As<Napi::Function>();

            Napi::Value ret = env.Null();
            bool threw = false;
            try {
                ret = fn.Call(api_obj, {p});
            } catch (const Napi::Error &e) {
                // JS 侧抛异常时不能让它逃出去：一旦跳过下面的 notify_all，
                // 服务线程会永久阻塞在条件变量上。
                threw = true;
            } catch (...) {
                threw = true;
            }

            // JS 返回值 → Smb2Req
            r.err = 0;
            r.out_bytes.clear();
            r.ok = true;

            if (threw) {
                r.ok = false;
                r.err = -1;
            } else if (ret.IsArray() && r.op == "queryDirectory") {
                Napi::Array arr = ret.As<Napi::Array>();
                r.out_entries.clear();
                for (uint32_t i = 0; i < arr.Length(); i++) {
                    Napi::Value v = arr.Get(i);
                    if (!v.IsObject()) {
                        continue;
                    }
                    Napi::Object o = v.As<Napi::Object>();
                    Smb2Req::DirEntry e;
                    if (o.Has("name")) {
                        e.name = o.Get("name").As<Napi::String>().Utf8Value();
                    }
                    if (o.Has("size")) {
                        e.size = (uint64_t)o.Get("size").As<Napi::Number>().Int64Value();
                    }
                    if (o.Has("mtime")) {
                        e.mtime = (uint64_t)o.Get("mtime").As<Napi::Number>().Int64Value();
                    }
                    if (o.Has("type")) {
                        e.is_dir =
                            o.Get("type").As<Napi::String>().Utf8Value() == "dir";
                    }
                    r.out_entries.push_back(e);
                }
            } else if (ret.IsNull() || ret.IsUndefined()) {
                // create 之类的成功返回 null 不代表有数据
            } else if (ret.IsNumber() && r.op == "create") {
                r.out_handle = ret.As<Napi::Number>().Int64Value();
            } else if (ret.IsString() && r.op == "authorize") {
                r.out_password = ret.As<Napi::String>().Utf8Value();
            } else if (ret.IsString() && r.op == "rename") {
                r.out_path = ret.As<Napi::String>().Utf8Value();
            } else if (ret.IsBuffer()) {
                auto buf = ret.As<Napi::Buffer<char>>();
                r.out_bytes.assign(buf.Data(), buf.Length());
            } else if (ret.IsObject()) {
                Napi::Object o = ret.As<Napi::Object>();
                if (o.Has("error")) {
                    r.err = o.Get("error").As<Napi::Number>().Int32Value();
                    r.ok = false;
                } else if (r.op == "queryInfo") {
                    if (o.Has("path")) {
                        r.out_path = o.Get("path").As<Napi::String>().Utf8Value();
                    }
                    if (o.Has("size")) {
                        r.out_size = (uint64_t)o.Get("size").As<Napi::Number>().Int64Value();
                    }
                    if (o.Has("mtime")) {
                        r.out_mtime = (uint64_t)o.Get("mtime").As<Napi::Number>().Int64Value();
                    }
                    if (o.Has("is_dir")) {
                        r.out_is_dir = o.Get("is_dir").As<Napi::Boolean>().Value();
                    }
                } else if (r.op == "create") {
                    if (o.Has("path")) {
                        r.out_path = o.Get("path").As<Napi::String>().Utf8Value();
                    }
                    r.out_is_dir = o.Get("is_dir").As<Napi::Boolean>().Value();
                    if (o.Has("size")) {
                        r.out_size = (uint64_t)o.Get("size").As<Napi::Number>().Int64Value();
                    }
                    if (o.Has("delete_on_close")) {
                        r.out_delete_on_close =
                            o.Get("delete_on_close").As<Napi::Boolean>().Value();
                    }
                    if (o.Has("create_action")) {
                        r.out_create_action =
                            o.Get("create_action").As<Napi::Number>().Uint32Value();
                    }
                }
            } else if (ret.IsBoolean() && !ret.As<Napi::Boolean>().Value()) {
                r.err = -1;
                r.ok = false;
            }

            std::lock_guard<std::mutex> lock(s->mtx);
            s->done = true;
            s->cv.notify_all();
        });

    if (st != napi_ok) {
        return false;
    }

    {
        std::unique_lock<std::mutex> lock(share.mtx);
        share.cv.wait(lock, [&]() { return share.done; });
    }
    return req.ok;
}
