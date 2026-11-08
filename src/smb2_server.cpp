#include "smb2_server.h"
#include <cstring>
#include <chrono>

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
            smb2_set_password(smb2, r.out_password.c_str());
        }
        return 0;
    }

    static int create_cmd(struct smb2_server *srvr, struct smb2_context *smb2,
                          struct smb2_create_request *req,
                          struct smb2_create_reply *rep) {
        // IPC$ 上打开的是命名管道（如 srvsvc），不落到文件系统
        if (self_->is_ipc_tree(smb2)) {
            std::string pipe_name = req->name ? req->name : "";
            while (!pipe_name.empty() &&
                   (pipe_name[0] == '\\' || pipe_name[0] == '/')) {
                pipe_name.erase(0, 1);
            }
            uint64_t ph = self_->add_pipe_handle(pipe_name);
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
        r.share = self_->tree_share(smb2);
        r.name = req->name ? req->name : "";
        r.desired_access = req->desired_access;
        r.create_disposition = req->create_disposition;
        r.create_options = req->create_options;

        if (!call(self_, r)) {
            return -1;
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
            r.out_is_dir ? SMB2_FILE_ATTRIBUTE_DIRECTORY : SMB2_FILE_ATTRIBUTE_NORMAL;
        rep->create_action = r.out_create_action;
        rep->end_of_file = r.out_size;
        rep->allocation_size = r.out_size;
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
            fprintf(stderr, "[smb2-server] tree_connect 拒绝共享: '%s' 已配置=%zu\n",
                    share.c_str(), self_->shares().size());
            for (const auto &it : self_->shares()) {
                fprintf(stderr, "[smb2-server]   可用共享: '%s'\n", it.first.c_str());
            }
            return -1;
        }
        self_->set_ipc_tree(smb2, false);
        self_->set_tree_share(smb2, share);
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
            del_req.share = self_->tree_share(smb2);
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
        uint64_t h = file_id_to_handle(req->file_id);
        std::string path;
        if (!self_->get_handle(h, &path)) {
            return -ENOENT;
        }

        Smb2Req r;
        r.op = "read";
        r.share = self_->tree_share(smb2);
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
        r.share = self_->tree_share(smb2);
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
            r.share = self_->tree_share(smb2);
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
            r.share = self_->tree_share(smb2);
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

        return -EOPNOTSUPP;
    }

    // NetrShareEnum 的 NDR 响应（SHARE_INFO_1，返回全部共享）
    static std::vector<uint8_t> build_share_enum_response(
        uint16_t call_id,
        const std::vector<std::pair<std::string, std::string>> &shares,
        const std::string &remark) {
        std::vector<uint8_t> b;
        auto put_u32 = [&b](uint32_t v) {
            b.push_back((uint8_t)(v & 0xff));
            b.push_back((uint8_t)((v >> 8) & 0xff));
            b.push_back((uint8_t)((v >> 16) & 0xff));
            b.push_back((uint8_t)((v >> 24) & 0xff));
        };

        b.resize(24, 0);
        b[0] = 5;
        b[1] = 0;
        b[2] = 0x02;  // PTYPE_RESPONSE
        b[3] = 0x03;
        b[4] = 0x10;
        b[12] = (uint8_t)(call_id & 0xff);
        b[13] = (uint8_t)((call_id >> 8) & 0xff);

        const uint32_t count = (uint32_t)shares.size();
        const uint32_t level = 1;  // SHARE_INFO_1
        put_u32(level);       // Level
        put_u32(level);       // Switch
        put_u32(0x00020004);  // SHARE_ENUM_STRUCT 指针
        put_u32(count);       // EntriesRead
        put_u32(0x00020004);  // Buffer 指针
        put_u32(count);       // max_count，必须等于 EntriesRead

        // SHARE_INFO_1 固定部分：netname 引用、type、remark 引用
        // 每条共享的结构引用地址依次递增，NDR 只要求是唯一非零引用
        for (uint32_t i = 0; i < count; i++) {
            put_u32(0x00020020 + i * 4);  // netname 引用
            put_u32(0);                   // STYPE_DISKTREE
            put_u32(0x00020024 + i * 4);  // remark 引用
        }

        auto put_ndr_string = [&b, &put_u32](const std::string &utf8) {
            // UTF-8 → UTF-16LE，NDR 字符串按宽字符计数
            std::vector<uint16_t> w;
            for (size_t i = 0; i < utf8.size();) {
                uint32_t cp = (uint8_t)utf8[i];
                size_t extra = 0;
                if (cp < 0x80) {
                    extra = 0;
                } else if ((cp & 0xE0) == 0xC0) {
                    cp &= 0x1F;
                    extra = 1;
                } else if ((cp & 0xF0) == 0xE0) {
                    cp &= 0x0F;
                    extra = 2;
                } else if ((cp & 0xF8) == 0xF0) {
                    cp &= 0x07;
                    extra = 3;
                }
                for (size_t k = 1; k <= extra && i + k < utf8.size(); k++) {
                    cp = (cp << 6) | ((uint8_t)utf8[i + k] & 0x3F);
                }
                i += extra + 1;
                if (cp >= 0x10000) {
                    cp -= 0x10000;
                    w.push_back((uint16_t)(0xD800 | (cp >> 10)));
                    w.push_back((uint16_t)(0xDC00 | (cp & 0x3FF)));
                } else {
                    w.push_back((uint16_t)cp);
                }
            }
            uint32_t chars = (uint32_t)w.size();
            put_u32(chars + 1);
            put_u32(0);
            put_u32(chars + 1);
            for (size_t i = 0; i < w.size(); i++) {
                b.push_back((uint8_t)(w[i] & 0xff));
                b.push_back((uint8_t)(w[i] >> 8));
            }
            b.push_back(0);
            b.push_back(0);
            // NDR 要求字符串结束后 4 字节对齐
            while (b.size() % 4 != 0) {
                b.push_back(0);
            }
        };
        for (const auto &it : shares) {
            put_ndr_string(it.first);
            put_ndr_string(remark);
        }

        put_u32(count);  // TotalEntries
        put_u32(0);  // ResumeHandle 引用（NULL）
        put_u32(0);  // WERROR

        uint32_t total = (uint32_t)b.size();
        b[8] = (uint8_t)(total & 0xff);
        b[9] = (uint8_t)((total >> 8) & 0xff);
        b[16] = (uint8_t)((total - 24) & 0xff);
        b[17] = (uint8_t)(((total - 24) >> 8) & 0xff);
        return b;
    }

    static std::vector<uint8_t> build_bind_ack(uint16_t call_id) {
        static const uint8_t ndr32[20] = {
            0x04, 0x5d, 0x88, 0x8a, 0xeb, 0x1c, 0xc9, 0x11,
            0x9f, 0xe8, 0x08, 0x00, 0x2b, 0x10, 0x48, 0x60,
            0x02, 0x00, 0x00, 0x00
        };
        // 布局：24 字节头 + sec_addr_len(2) + 填充到 28 + n_results(1) + 保留(3)
        //      + context 结果 24 字节（含 transfer syntax）
        std::vector<uint8_t> out(28 + 24, 0);
        out[0] = 5;     // version major
        out[1] = 0;     // version minor
        out[2] = 0x0c;  // PTYPE_BIND_ACK
        out[3] = 0x03;  // first | last frag
        out[4] = 0x10;  // little-endian
        uint32_t total = (uint32_t)out.size();
        out[8] = (uint8_t)(total & 0xff);
        out[9] = (uint8_t)((total >> 8) & 0xff);
        out[12] = (uint8_t)(call_id & 0xff);
        out[13] = (uint8_t)((call_id >> 8) & 0xff);
        out[20] = 0x01;  // assoc_group_id 非 0
        // p[24..25] = secondary address length = 0
        // p[26..27] = 保留
        out[28] = 0x01;  // n_results = 1
        // p[29..31] = 保留
        // context 结果从 32 开始：result(2)=0 接受, reason(2)=0
        memcpy(&out[36], ndr32, 20);
        return out;
    }

    // DCE/RPC over FSCTL_PIPE_TRANSCEIVE，为 srvsvc 服务
    static int ioctl_cmd(struct smb2_server *srvr, struct smb2_context *smb2,
                         struct smb2_ioctl_request *req,
                         struct smb2_ioctl_reply *rep) {
        rep->ctl_code = req->ctl_code;
        memcpy(rep->file_id, req->file_id, SMB2_FD_SIZE);
        rep->input_offset = 0;
        rep->input_count = 0;
        rep->output_offset = 0;
        rep->output_count = 0;
        rep->flags = req->flags;
        rep->output = NULL;

        uint64_t h = resolve_handle(self_, smb2, req->file_id);
        std::string pipe_name;
        if (!self_->get_pipe_name(h, &pipe_name)) {
            return -ENOENT;
        }
        if (req->ctl_code != SMB2_FSCTL_PIPE_TRANSCEIVE) {
            return -EOPNOTSUPP;
        }

        const uint8_t *in = (const uint8_t *)req->input;
        uint32_t in_len = req->input_count;
        if (in == NULL || in_len < 16) {
            return -EINVAL;
        }

        uint8_t ptype = in[2];
        uint16_t call_id = (uint16_t)(in[12] | (in[13] << 8));
        std::vector<uint8_t> out;

        if (ptype == 0x0b) {
            out = build_bind_ack(call_id);
        } else if (ptype == 0x00) {
            if (in_len < 24) {
                return -EINVAL;
            }
            uint16_t opnum = (uint16_t)(in[22] | (in[23] << 8));
            if (opnum != 15) {
                return -EOPNOTSUPP;
            }
            out = build_share_enum_response(call_id, self_->shares(),
                                            self_->share_remark());
        } else {
            return -EOPNOTSUPP;
        }

        if (out.empty()) {
            return -ENOMEM;
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
        uint64_t h = file_id_to_handle(req->file_id);
        std::string path;
        if (!self_->get_handle(h, &path)) {
            return -ENOENT;
        }

        Smb2Req r;
        r.op = "queryDirectory";
        r.share = self_->tree_share(smb2);
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
        if (r.out_bytes.empty()) {
            // 空 buffer 表示没有更多条目，客户端停止翻页
            rep->output_buffer = nullptr;
            rep->output_buffer_offset = 0;
            rep->output_buffer_length = 0;
            return 0;
        }

        size_t len = r.out_bytes.size();
        rep->output_buffer = (uint8_t *)malloc(len);
        if (!rep->output_buffer) {
            return -ENOMEM;
        }
        memcpy(rep->output_buffer, r.out_bytes.data(), len);
        rep->output_buffer_offset = 0;
        rep->output_buffer_length = (uint32_t)len;
        return 0;
    }

    static int query_info_cmd(struct smb2_server *srvr, struct smb2_context *smb2,
                              struct smb2_query_info_request *req,
                              struct smb2_query_info_reply *rep) {
        uint64_t h = file_id_to_handle(req->file_id);
        std::string path;
        if (!self_->get_handle(h, &path)) {
            return -ENOENT;
        }

        Smb2Req r;
        r.op = "queryInfo";
        r.share = self_->tree_share(smb2);
        r.path = path;
        r.handle_id = h;
        r.info_type = req->info_type;
        r.file_info_class = req->file_info_class;
        r.buffer_length = req->output_buffer_length;

        if (!call(self_, r)) {
            return -1;
        }
        if (r.err != 0) {
            return r.err;
        }
        if (r.out_bytes.empty()) {
            return -EINVAL;
        }

        size_t len = r.out_bytes.size();
        rep->output_buffer = (uint8_t *)malloc(len);
        if (!rep->output_buffer) {
            return -ENOMEM;
        }
        memcpy(rep->output_buffer, r.out_bytes.data(), len);
        rep->output_buffer_offset = 0;
        rep->output_buffer_length = (uint32_t)len;
        return 0;
    }
};

Smb2Server *ServerHandlers::self_ = nullptr;

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
    running_ = true;

    thread_ = std::thread([this]() { ServeLoop(); });

    // 等主循环把 fd 绑定好
    for (int i = 0; i < 100 && server_.fd == 0; i++) {
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    fprintf(stderr, "[smb2-server] bind 后 fd=%d listener_ready=%d\n",
            (int)server_.fd, (int)server_.listener_ready);

    return env.Undefined();
}

void Smb2Server::ServeLoop() {
    struct smb2_context *ctx = nullptr;
    fprintf(stderr, "[smb2-server] 进入主循环, port=%d handlers=%p\n",
            server_.port, (void *)server_.handlers);
    int rc = smb2_serve_port(
        &server_, 4,
        [](struct smb2_context *smb2, void *cb_data) {
            fprintf(stderr, "[smb2-server] 新连接 fd=%d\n", smb2_get_fd(smb2));
            smb2_set_version(smb2, SMB2_VERSION_ANY);
            // 开启 passthrough：目录项/文件信息按 wire format 原样收发。
            // 否则 libsmb2 会把我们自己编码的 blob 当成 C 结构体重新解析，
            // 读 fs->name 指针时错乱导致服务端崩溃。
            smb2_set_passthrough(smb2, 1);
            smb2_set_security_mode(smb2, 0);
            smb2_register_error_callback(
                smb2, [](struct smb2_context *, const char *msg) {
                    if (msg && msg[0]) {
                        fprintf(stderr, "[smb2-server] 错误: %s\n", msg);
                    }
                });
            auto *p = (struct smb2_context **)cb_data;
            *p = smb2;
        },
        &ctx);
    fprintf(stderr, "[smb2-server] 主循环退出 rc=%d fd=%d\n", rc, server_.fd);
    running_ = false;
}

Napi::Value Smb2Server::Stop(const Napi::CallbackInfo &info) {
    server_.stop_requested = 1;
    if (thread_.joinable()) {
        thread_.join();
    }
    running_ = false;
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
            if (!r.share.empty()) {
                p.Set("share", Napi::String::New(env, r.share));
            }
            if (r.op == "authorize") {
                p.Set("user", Napi::String::New(env, r.user));
                p.Set("domain", Napi::String::New(env, r.domain));
                p.Set("workstation", Napi::String::New(env, r.workstation));
            }
            if (!r.name.empty()) {
                p.Set("name", Napi::String::New(env, r.name));
                p.Set("desired_access", Napi::Number::New(env, r.desired_access));
                p.Set("create_disposition", Napi::Number::New(env, r.create_disposition));
                p.Set("create_options", Napi::Number::New(env, r.create_options));
            }
            if (!r.path.empty()) {
                p.Set("path", Napi::String::New(env, r.path));
                p.Set("handle_id", Napi::Number::New(env, (double)r.handle_id));
            }
            if (r.op == "read") {
                p.Set("offset", Napi::Number::New(env, (double)r.offset));
                p.Set("length", Napi::Number::New(env, r.length));
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
                fprintf(stderr, "[smb2-server] handler %s 抛异常: %s\n",
                        r.op.c_str(), e.Message().c_str());
                threw = true;
            } catch (...) {
                fprintf(stderr, "[smb2-server] handler %s 抛未知异常\n", r.op.c_str());
                threw = true;
            }

            // JS 返回值 → Smb2Req
            r.err = 0;
            r.out_bytes.clear();
            r.ok = true;

            if (threw) {
                r.ok = false;
                r.err = -1;
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
