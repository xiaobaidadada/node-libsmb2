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
/* ---------------------------------------------------------------- */
/* srvsvc 共享枚举服务端（IPC$ / srvsvc）                             */
/* ---------------------------------------------------------------- */
/*
 * iOS / macOS 的文件 App 在用户不指定共享名时会先做共享枚举：
 *   连接 IPC$ -> 打开 srvsvc 命名管道 -> DCE/RPC BIND -> NetrShareEnum
 *
 * libdcerpc 自带完整的服务端运行时（BIND、REQUEST 分发、NDR 编解码），
 * 这里只需要挂一个 NetrShareEnum 的 stub，把共享名按 SHARE_INFO_1 返回。
 */

// NetrShareEnum 在 srvsvc 接口里的 opnum（[MS-SRVS] 3.1.4.8）
#define SRVSVC_OPNUM_NETRSHAREENUM 15
// srvsvc 方法返回的 WERROR，0 表示成功
#define SRVSVC_STATUS_SUCCESS 0
// 共享类型：磁盘共享（[MS-SRVS] 2.2.2.4）
#define SRVSVC_STYPE_DISKTREE 0

class Smb2Server;

// 当前正在服务的实例，供 srvsvc stub 取共享名列表
static Smb2Server *g_srvsvc_owner = nullptr;


struct ServerHandlers {
    static Smb2Server *self_;

    // DCE/RPC PDU 类型（[C706] 12.6.1）
    enum {
        DCE_PDU_REQUEST = 0,
        DCE_PDU_BIND = 11,
        DCE_PDU_BIND_ACK = 12,
        DCE_PDU_RESPONSE = 2,
    };
    // PDU 头标志位：首片 + 末片
    static const uint8_t DCE_PFC_FIRST_LAST = 0x03;
    // 数据表示：小端
    static const uint8_t DCE_DR_LE = 0x10;
    // bind_ack 的 ack_result：0 为接受
    static const uint16_t DCE_ACK_ACCEPT = 0;
    // srvsvc 接口的 opnum：NetrShareEnum（[MS-SRVS] 3.1.4.8）
    static const uint16_t SRVSVC_OPNUM_SHARE_ENUM = 15;

    static void put_le16(std::vector<uint8_t> &v, uint16_t x) {
        v.push_back((uint8_t)(x & 0xff));
        v.push_back((uint8_t)(x >> 8));
    }
    static void put_le32(std::vector<uint8_t> &v, uint32_t x) {
        v.push_back((uint8_t)(x & 0xff));
        v.push_back((uint8_t)((x >> 8) & 0xff));
        v.push_back((uint8_t)((x >> 16) & 0xff));
        v.push_back((uint8_t)((x >> 24) & 0xff));
    }
    static uint16_t get_le16(const uint8_t *p) {
        return (uint16_t)(p[0] | (p[1] << 8));
    }
    static uint32_t get_le32(const uint8_t *p) {
        return (uint32_t)(p[0] | (p[1] << 8) | (p[2] << 16) |
                          ((uint32_t)p[3] << 24));
    }
    // 在 DCE 头部补齐 4 字节
    static void pad4(std::vector<uint8_t> &v) {
        while (v.size() & 3) {
            v.push_back(0);
        }
    }

    /**
     * 回应 BIND：把客户端请求的接口/传输语法按 NDR32 接受。
     *
     * 只需要一个 ACK 结果，指向 NDR32（8a885d04-1ceb-11c9-9fe8-08002b104860），
     * 客户端随后用同样的 context_id 发 REQUEST。
     */
    static void build_bind_ack(const uint8_t *in, uint32_t in_len,
                               std::vector<uint8_t> &out) {
        // NDR32 传输语法 UUID（线格式按小端序列化）
        static const uint8_t ndr32_uuid[16] = {
            0x04, 0x5d, 0x88, 0x8a, 0xeb, 0x1c, 0xc9, 0x11,
            0x9f, 0xe8, 0x08, 0x00, 0x2b, 0x10, 0x48, 0x60};
        // 客户端会用这个地址在管道上继续访问。
        // NDR 里的 secondary_address 是长度前缀的字符串，不含结尾 '\0'。
        static const char sec_addr[] = "\\PIPE\\srvsvc";
        const uint16_t sec_len = (uint16_t)(sizeof(sec_addr) - 1);

        const uint32_t call_id = in_len >= 16 ? get_le32(in + 12) : 0;

        out.clear();
        // ---- 16 字节公共头 ----
        out.push_back(5);  // rpc_vers
        out.push_back(0);  // rpc_vers_minor
        out.push_back(DCE_PDU_BIND_ACK);
        out.push_back(DCE_PFC_FIRST_LAST);
        out.push_back(DCE_DR_LE);
        out.push_back(0);  // flags
        pad4(out);         // 实际上 out 已经是 8 字节
        out.resize(8, 0);
        // frag_length 占位，最后回填
        const size_t frag_len_pos = out.size();
        put_le16(out, 0);
        // auth_length = 0
        put_le16(out, 0);
        put_le32(out, call_id);

        // ---- BIND_ACK 体 ----
        put_le16(out, 4280);  // max_xmit_frag
        put_le16(out, 4280);  // max_recv_frag
        put_le32(out, 0);     // assoc_group_id
        put_le16(out, sec_len);
        out.insert(out.end(), sec_addr, sec_addr + sec_len);
        pad4(out);
        out.push_back(1);  // num_results
        out.push_back(0);  // 对齐
        out.push_back(0);
        out.push_back(0);
        put_le16(out, DCE_ACK_ACCEPT);  // ack_result
        put_le16(out, 0);               // ack_reason
        out.insert(out.end(), ndr32_uuid, ndr32_uuid + 16);
        put_le32(out, 2);  // transfer syntax 版本

        // 回填 frag_length
        const uint16_t fl = (uint16_t)out.size();
        out[frag_len_pos] = (uint8_t)(fl & 0xff);
        out[frag_len_pos + 1] = (uint8_t)(fl >> 8);
    }

    /**
     * 回应 NetrShareEnum REQUEST：手工编码整个响应体。
     *
     * 头部原样回填 call_id 和 context_id，PDU 类型置为 RESPONSE。
     */
    static void build_share_enum_response(
        const uint8_t *in, uint32_t in_len,
        const std::vector<std::pair<std::string, std::string>> &shares,
        std::vector<uint8_t> &out) {
        const uint32_t call_id = get_le32(in + 12);
        const uint16_t context_id = get_le16(in + 20);

        // 先编码 stub，再套 DCE 头，方便最后回填长度
        std::vector<uint8_t> stub;
        encode_share_enum_reply(shares, stub);

        out.clear();
        out.push_back(5);
        out.push_back(0);
        out.push_back(DCE_PDU_RESPONSE);
        out.push_back(DCE_PFC_FIRST_LAST);
        out.push_back(DCE_DR_LE);
        out.push_back(0);
        out.resize(8, 0);
        const size_t frag_len_pos = out.size();
        put_le16(out, 0);              // frag_length 占位
        put_le16(out, 0);              // auth_length
        put_le32(out, call_id);
        put_le32(out, (uint32_t)stub.size());  // alloc_hint
        put_le16(out, context_id);
        out.push_back(0);  // cancel_count
        out.push_back(0);  // 保留
        out.insert(out.end(), stub.begin(), stub.end());

        const uint16_t fl = (uint16_t)out.size();
        out[frag_len_pos] = (uint8_t)(fl & 0xff);
        out[frag_len_pos + 1] = (uint8_t)(fl >> 8);
    }

    /**
     * srvsvc 管道上的一个 DCE/RPC PDU 入口。
     *
     * 只处理 BIND 和 NetrShareEnum，其它一律返回 false，由调用方决定如何回应。
     */
    static bool srvsvc_process(const uint8_t *in, uint32_t in_len,
                               std::vector<uint8_t> &out) {
        if (in == NULL || in_len < 16) {
            return false;
        }
        // 只认 DCE/RPC 5.0
        if (in[0] != 5) {
            return false;
        }
        switch (in[2]) {
            case DCE_PDU_BIND:
                build_bind_ack(in, in_len, out);
                return true;
            case DCE_PDU_REQUEST:
                // REQUEST 的 opnum 在偏移 22
                if (in_len < 24 ||
                    get_le16(in + 22) != SRVSVC_OPNUM_SHARE_ENUM) {
                    return false;
                }
                build_share_enum_response(in, in_len,
                                          self_ ? self_->shares()
                                                : std::vector<std::pair<
                                                      std::string, std::string>>(),
                                          out);
                return true;
            default:
                return false;
        }
    }


    /**
     * NetrShareEnum 的响应体手工编码（NDR32）。
     *
     * 为什么不用 libdcerpc 的 srvsvc coder：
     * dcerpc_ptr_coder 对 PTR_UNIQUE / PTR_REF 一律写入 UPTR / RPTR 占位
     * 标记（见 libdcerpc/dcerpc.c "stand out in a hexdump" 的注释），
     * 只有在 pdu->top_level 时才回填，嵌套指针永远不会回填真实 referent id。
     * 自家客户端与编码端共用同一实现所以互通，但真实 SMB 客户端
     * （iOS 文件类 App、Windows）按标准 NDR 解析会拿到 0x55707472 这种
     * 非法 referent id，随后直接断开。
     * 这里按 [MS-SRVS] 3.1.4.8 / [C706] 14.3 的线格式手工编码。
     */
    static void encode_share_enum_reply(
        const std::vector<std::pair<std::string, std::string>> &shares,
        std::vector<uint8_t> &out) {
        const uint32_t count = (uint32_t)shares.size();

        // referent id 从 1 开始递增，NDR 要求非 0 且唯一，且按出现顺序编排：
        //   1: SHARE_ENUM_UNION 的 Level1（SHARE_INFO_1_CONTAINER）
        //   2: Level1.Buffer（SHARE_INFO_1 数组）
        //   3..: 每个条目的 name / comment
        uint32_t next_ref = 1;
        const uint32_t ref_array = next_ref++;
        const uint32_t ref_elements = next_ref++;
        std::vector<uint32_t> ref_names(count), ref_remarks(count);
        for (uint32_t i = 0; i < count; i++) {
            ref_names[i] = next_ref++;
            ref_remarks[i] = next_ref++;
        }

        // 逐字段写入的小工具：统一做 4 字节对齐
        auto put32 = [&out](uint32_t v) {
            out.push_back((uint8_t)(v & 0xff));
            out.push_back((uint8_t)((v >> 8) & 0xff));
            out.push_back((uint8_t)((v >> 16) & 0xff));
            out.push_back((uint8_t)((v >> 24) & 0xff));
        };
        auto align4 = [&out]() {
            while (out.size() & 3) {
                out.push_back(0);
            }
        };
        // [string] 在 NDR 里是 unique pointer 指向的 conformant varying
        // 数组：MaximumCount + Offset + ActualCount + UTF-16LE 字符 + 结束符
        auto put_utf16_string = [&](const std::string &s) {
            align4();
            // 字符串先转成 UTF-16LE；这里共享名与备注都是 ASCII/UTF-8，
            // 逐字节提升为 UTF-16 即可覆盖文件名场景
            std::vector<uint16_t> w;
            for (unsigned char ch : s) {
                w.push_back((uint16_t)ch);
            }
            const uint32_t n = (uint32_t)w.size();
            put32(n + 1);  // MaximumCount
            put32(0);      // Offset
            put32(n + 1);  // ActualCount
            for (uint16_t ch : w) {
                out.push_back((uint8_t)(ch & 0xff));
                out.push_back((uint8_t)(ch >> 8));
            }
            out.push_back(0);  // 结束符
            out.push_back(0);
        };

        // ---- srvsvc_NetShareInfoCtr ----
        // 布局以 libsmb2 自带的解析器（lib/smb2-share-enum.c 的
        // se_decode_stub）为准，它按如下顺序读取：
        //   level, sw, ctr_ref, count, buf_ref, max_count, entries...
        put32(1);  // level = 1

        // sw：switch 值，解析器要求它等于 level
        put32(1);

        // ctr_ref：指向 SHARE_INFO_1_CONTAINER 的指针
        put32(count ? ref_array : 0);
        if (count) {
            // ---- SHARE_INFO_1_CONTAINER ----
            put32(count);  // count（EntriesRead）
            // buf_ref：指向 SHARE_INFO_1 数组的指针
            put32(ref_elements);
            // conformant 数组只有 MaximumCount
            align4();
            put32(count);  // MaximumCount
            // 数组元素：[MS-SRVS] 2.2.4.1 srvsvc_NetShareInfo1 的字段顺序是
            //   [string] name, ShareType type, [string] comment
            // type 夹在两个字符串指针中间，顺序错了客户端直接解析失败。
            for (uint32_t i = 0; i < count; i++) {
                align4();
                put32(ref_names[i]);
                put32(SRVSVC_STYPE_DISKTREE);
                put32(ref_remarks[i]);
            }
            // 元素数据按出现顺序紧接其后
            for (uint32_t i = 0; i < count; i++) {
                put_utf16_string(shares[i].first);
                put_utf16_string(shares[i].second);
            }
        }

        // ---- TotalEntries ----
        // 客户端按直接取值解析（smb2-share-enum.c 的 ndr_u32(&total)），
        // 不先读指针，所以这里直接写数值。
        align4();
        put32(count);

        // ---- ResumeHandle：[in,out,unique]，0 表示 NULL，没有后续 ----
        put32(0);

        // ---- Status ----
        put32(SRVSVC_STATUS_SUCCESS);
    }

    /**
     * srvsvc 的 NetrShareEnum stub。
     *
     * 返回已编码的响应体给 ioctl_cmd，由它写进 FSCTL_PIPE_TRANSCEIVE 的
     * 输出缓冲区；不再经过 libdcerpc 的 srvsvc coder。
     */
    static int srvsvc_netr_share_enum_stub(struct dcerpc_context *dce,
                                           struct dcerpc_pdu *pdu,
                                           void *req, void *rep) {
        auto *r = (struct srvsvc_NetrShareEnum_req *)req;
        (void)rep;
        if (r == NULL || self_ == nullptr) {
            return -1;
        }
        // 只实现 Level 1
        if (r->InfoStruct.Level != 1) {
            return -1;
        }

        // 编码结果暂存在实例上，由 ioctl_cmd 取走后清空
        const std::vector<std::pair<std::string, std::string>> shares =
            self_->shares();
        encode_share_enum_reply(shares, self_->srvsvc_reply_);

        // 让 runtime 认为 stub 成功，但没有 rep 数据要编码
        self_->srvsvc_reply_ready_ = true;
        return 0;
    }


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
                // FILE_OPEN_BY_FILE_ID 的 context Name 为空，Data 是紧跟
                // 12 字节头之后的 16 字节 FileId。之前读 cc+8 会落在
                // Reserved 字段里，取到的是错误句柄。
                if (nlen == 0 && left >= 12 + SMB2_FD_SIZE) {
                    smb2_file_id fid;
                    memset(fid, 0, SMB2_FD_SIZE);
                    memcpy(fid, cc + 12, SMB2_FD_SIZE);
                    std::string by_id_path;
                    const uint64_t want = file_id_to_handle(fid);
                    // 先查 create/close 生命周期的 handle，再查目录项 id
                    if (self_->get_handle(want, &by_id_path) ||
                        self_->get_dir_entry_path(want, &by_id_path)) {
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
            // IPC$ 上的命名管道：只要是已知管道名就允许打开，返回一个管道句柄。
            // 之前对非 srvsvc 的管道直接返回 ENOENT，会让客户端（iOS 文件类
            // App 等）判定整个 IPC$ 共享不可用而放弃共享枚举。
            // 真正的功能限制放在 ioctl 阶段：只有 srvsvc 支持 PIPE_TRANSCEIVE，
            // 其它管道在 transceive 时返回 NOT_SUPPORTED 即可。
            if (!name_is_pipe) {
                return -ENOENT;
            }
            uint64_t ph = self_->add_pipe_handle(lower);
            handle_to_file_id(ph, rep->file_id);
            self_->set_last_file_id(smb2, rep->file_id);
            rep->oplock_level = 0;
            rep->flags = 0;
            rep->file_attributes = SMB2_FILE_ATTRIBUTE_NORMAL;
            // 命名管道是“打开已有对象”，对应 FILE_OPEN；
            // 之前给 2(FILE_CREATE) 会让客户端认为要求新建管道而判定不存在。
            rep->create_action = SMB2_FILE_OPEN;
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
            // 与 libsmb2 官方示例 examples/smb2-server-sync.c 保持一致：
            // IPC$ 的 maximal_access 是 0x1f00a9，不是磁盘共享的 0x101f01ff。
            rep->maximal_access = 0x1f00a9;
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
        //
        // 会话建立后立即开启 passthrough：ioctl 的 input、set_info 的
        // 变长缓冲区（rename/disposition）都依赖它才会被填进 req->input，
        // 否则这些字段全是 NULL，管道 transceive（srvsvc 共享枚举）无法工作。
        smb2_set_passthrough(smb2, 1);
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
        std::string pipe_name;
        if (self_->get_pipe_name(h, &pipe_name)) {
            // IPC$ 上的命名管道（srvsvc 等）：服务端尚未实现 DCE/RPC，
            // 这里返回 0 字节而不是 ENOENT，避免客户端一直等待响应而超时。
            rep->data_remaining = 0;
            rep->data = nullptr;
            rep->data_length = 0;
            rep->data_offset = 0;
            return 0;
        }
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
        std::string pipe_name;
        if (self_->get_pipe_name(h, &pipe_name)) {
            // 命名管道的写请求由 ioctl 的 PIPE_TRANSCEIVE 处理，这里直接吞掉
            rep->count = req->length;
            return 0;
        }
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

    static int flush_cmd(struct smb2_server *srvr, struct smb2_context *smb2,
                         struct smb2_flush_request *req) {
        // flush 只是让服务端把缓存写盘，本地文件系统写入即落地，直接成功
        return 0;
    }

    /// @brief 连接保活探测，原样回显即可 | keep-alive probe, just echo back
    static int echo_cmd(struct smb2_server *srvr, struct smb2_context *smb2) {
        return 0;
    }

    /// @brief 会话登出，客户端主动断开前的收尾 | session logoff
    static int logoff_cmd(struct smb2_server *srvr, struct smb2_context *smb2) {
        return 0;
    }

    /// @brief 文件区间锁，本地共享场景直接视为成功 | byte-range lock
    static int lock_cmd(struct smb2_server *srvr, struct smb2_context *smb2,
                        struct smb2_lock_request *req) {
        return 0;
    }

    /// @brief 取消先前请求，直接回复空应答避免客户端一直等待 | cancel
    static int cancel_cmd(struct smb2_server *srvr, struct smb2_context *smb2) {
        return 0;
    }

    /// @brief 目录变更通知：本地共享不做推送，回 STATUS_NOT_SUPPORTED
    ///        让客户端退回到轮询，而不是一直挂着等待 | change notify
    static int change_notify_cmd(struct smb2_server *srvr,
                                 struct smb2_context *smb2,
                                 struct smb2_change_notify_request *req,
                                 struct smb2_change_notify_reply *rep) {
        return -EOPNOTSUPP;
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
            return 0;
        }
        if (req->ctl_code != SMB2_FSCTL_PIPE_TRANSCEIVE) {
            return -EOPNOTSUPP;
        }
        if (pipe_name != "srvsvc") {
            return -EOPNOTSUPP;
        }

        std::lock_guard<std::mutex> guard(self_->rpc_mutex_);
        if (req->input == NULL || req->input_count < 16) {
            return -EINVAL;
        }

        // srvsvc 的 DCE/RPC 由这里直接处理：
        // BIND 回 BIND_ACK，REQUEST 调 NetrShareEnum 并手工编码响应。
        // 不经过 libdcerpc runtime，因为它对嵌套指针只写 UPTR/RPTR 占位，
        // 真实 SMB 客户端解析不了（详见 encode_share_enum_reply 的说明）。
        const uint8_t *in = (const uint8_t *)req->input;
        const uint32_t in_len = req->input_count;
        self_->srvsvc_reply_.clear();
        self_->srvsvc_reply_ready_ = false;

        std::vector<uint8_t> out;
        if (!srvsvc_process(in, in_len, out)) {
            return -EINVAL;
        }
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
        // libsmb2 的 smb2_encode_query_directory_reply 不管客户端请求哪个 info_class，
        // 都固定把 output_buffer 强转成 struct smb2_fileidbothdirectoryinformation
        // 并按 PAD_TO_64BIT(sizeof(该结构体)) 步进读取；info_class 只影响
        // 它计算线上条目大小用的 fixed 值。因此这里必须统一按 fileidboth 结构体
        // 排布数组，slot 也用它的 sizeof，否则会错位或越界。
        const size_t slot = PAD_TO_64BIT(sizeof(struct smb2_fileidbothdirectoryinformation));
        size_t bytes = slot * n;
        auto *arr = (struct smb2_fileidbothdirectoryinformation *)calloc(1, bytes);
        if (arr == NULL) {
            return -ENOMEM;
        }
        for (size_t i = 0; i < n; i++) {
            const Smb2Req::DirEntry &e = r.out_entries[i];
            struct smb2_fileidbothdirectoryinformation *d =
                (struct smb2_fileidbothdirectoryinformation *)(void *)((uint8_t *)arr + i * slot);
            d->file_index = (uint32_t)(h + i);
            d->creation_time.tv_sec = (time_t)e.mtime;
            d->last_access_time.tv_sec = (time_t)e.mtime;
            d->last_write_time.tv_sec = (time_t)e.mtime;
            d->change_time.tv_sec = (time_t)e.mtime;
            d->end_of_file = e.is_dir ? 0 : e.size;
            d->allocation_size = e.is_dir ? 0 : e.size;
            d->file_attributes = e.is_dir
                ? SMB2_FILE_ATTRIBUTE_DIRECTORY
                : (SMB2_FILE_ATTRIBUTE_ARCHIVE | SMB2_FILE_ATTRIBUTE_NORMAL);
            d->file_name_length = (uint32_t)e.name.size() * 2;
            // file_id 必须指向该条目的真实路径：Windows/iOS 拿到列表后
            // 会用这个 id 直接发 FILE_OPEN_BY_FILE_ID 打开文件。
            std::string child = path;
            if (!child.empty() && child.back() != '/' && child.back() != '\\') {
                child += '/';
            }
            child += e.name;
            // 用稳定的目录项 id，而不是每次新建 handle：
            // 目录项不经过 create/close，用 add_handle 会持续泄漏。
            d->file_id = self_->dir_entry_file_id(child);
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
        // 卷标用 UTF-16LE 编码，内容为 "filecat"
        static const uint8_t volume_label[] = {
            'f', 0, 'i', 0, 'l', 0, 'e', 0, 'c', 0, 'a', 0, 't', 0};

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
            // 卷标：部分客户端（iOS 文件类 App）连接时会查询，缺失会导致 NOT_IMPLEMENTED
            if (req->file_info_class == SMB2_FILE_FS_VOLUME_INFORMATION) {
                struct smb2_file_fs_volume_info *vi =
                    (struct smb2_file_fs_volume_info *)calloc(1, sizeof(*vi));
                if (vi == NULL) {
                    return -ENOMEM;
                }
                vi->volume_serial_number = 0x12345678;
                vi->supports_objects = 0;
                vi->volume_label_length = sizeof(volume_label);
                vi->volume_label = volume_label;
                rep->output_buffer = (uint8_t *)vi;
                rep->output_buffer_length = sizeof(*vi);
                return 0;
            }
            // 设备类型：标识为磁盘设备，部分客户端用来区分共享类型
            if (req->file_info_class == SMB2_FILE_FS_DEVICE_INFORMATION) {
                struct smb2_file_fs_device_info *di =
                    (struct smb2_file_fs_device_info *)calloc(1, sizeof(*di));
                if (di == NULL) {
                    return -ENOMEM;
                }
                di->device_type = FILE_DEVICE_DISK;
                di->characteristics = 0;
                rep->output_buffer = (uint8_t *)di;
                rep->output_buffer_length = sizeof(*di);
                return 0;
            }
            // 完整容量信息：结构与 SIZE_INFORMATION 相同，额外带 sector 大小
            if (req->file_info_class == SMB2_FILE_FS_FULL_SIZE_INFORMATION) {
                struct smb2_file_fs_full_size_info *fi =
                    (struct smb2_file_fs_full_size_info *)calloc(1, sizeof(*fi));
                if (fi == NULL) {
                    return -ENOMEM;
                }
                const uint64_t unit = 4096;
                fi->total_allocation_units = (uint64_t)(1ULL << 40) / unit;
                fi->caller_available_allocation_units = fi->total_allocation_units;
                fi->actual_available_allocation_units = fi->total_allocation_units;
                fi->sectors_per_allocation_unit = 1;
                fi->bytes_per_sector = (uint32_t)unit;
                rep->output_buffer = (uint8_t *)fi;
                rep->output_buffer_length = sizeof(*fi);
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

        // FILE_ATTRIBUTE_TAG_INFORMATION：iOS / macOS 客户端在 create 之后
        // 用它判断目标是否为重解析点（符号链接/快捷方式），缺失会让客户端
        // 整个操作以 STATUS_NOT_IMPLEMENTED 失败。
        if (req->info_type == SMB2_0_INFO_FILE &&
            req->file_info_class == SMB2_FILE_ATTRIBUTE_TAG_INFORMATION) {
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
            struct smb2_file_attribute_tag_info *ati =
                (struct smb2_file_attribute_tag_info *)calloc(1, sizeof(*ati));
            if (ati == NULL) {
                return -ENOMEM;
            }
            ati->file_attributes =
                r.out_is_dir ? SMB2_FILE_ATTRIBUTE_DIRECTORY
                             : (SMB2_FILE_ATTRIBUTE_ARCHIVE | SMB2_FILE_ATTRIBUTE_NORMAL);
            // 不是重解析点，reparse_tag 固定为 0
            ati->reparse_tag = 0;
            rep->output_buffer = (uint8_t *)ati;
            rep->output_buffer_length = sizeof(*ati);
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
    {SRVSVC_NETRSHAREENUM, (char *)"NetrShareEnum",
     ServerHandlers::srvsvc_netr_share_enum_stub},
    {0, NULL, NULL}};

static struct smb2_server_request_handlers g_handlers = {
    nullptr,                              // destruction_event
    ServerHandlers::authorize,            // authorize_user
    ServerHandlers::session_established_cmd,  // session_established
    ServerHandlers::logoff_cmd,               // logoff_cmd
    ServerHandlers::tree_connect_cmd,     // tree_connect_cmd
    ServerHandlers::tree_disconnect_cmd,  // tree_disconnect_cmd
    ServerHandlers::create_cmd,           // create_cmd
    ServerHandlers::close_cmd,            // close_cmd
    ServerHandlers::flush_cmd,             // flush_cmd
    ServerHandlers::read_cmd,             // read_cmd
    ServerHandlers::write_cmd,            // write_cmd
    nullptr,                              // oplock_break_cmd
    nullptr,                              // lease_break_cmd
    ServerHandlers::lock_cmd,             // lock_cmd
    ServerHandlers::ioctl_cmd,            // ioctl_cmd
    ServerHandlers::cancel_cmd,           // cancel_cmd
    ServerHandlers::echo_cmd,             // echo_cmd
    ServerHandlers::query_directory_cmd,  // query_directory_cmd
    ServerHandlers::change_notify_cmd,    // change_notify_cmd
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

    // srvsvc 共享枚举：绑定 libdcerpc 官方服务端 runtime。
    // 只在服务线程里创建（见 ServeLoop），避免 Start 与 ServeLoop 各建一份
    // 造成指针被覆盖、旧的 dcerpc_server 泄漏。
    running_ = true;

    thread_ = std::thread([this]() { ServeLoop(); });

    // 等主循环把 fd 绑定好
    for (int i = 0; i < 100 && server_.fd == 0; i++) {
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }

    return env.Undefined();
}

void Smb2Server::ServeLoop() {
    // 建立 srvsvc 的 DCE/RPC 服务端端点：客户端在 IPC$ 上打开 srvsvc 管道后，
    // BIND 与 NetrShareEnum 都由 libdcerpc 的服务端运行时处理。
    // 没有这个端点时，不填共享名的客户端（iOS 文件类 App）枚举共享会超时。
    rpc_ = dcerpc_server_create("srvsvc");
    if (rpc_ != NULL) {
        if (dcerpc_server_add_interface(rpc_, &srvsvc_interface, srvsvc_procs,
                                        g_srvsvc_stubs,
                                        DCERPC_SERVER_ALL_NDR) != 0) {
//             fprintf(stderr, "[SMB][rpc] srvsvc 接口注册失败\n");
        }
    } else {
//         fprintf(stderr, "[SMB][rpc] srvsvc 端点创建失败，共享枚举不可用\n");
    }

    struct smb2_context *ctx = nullptr;
    int rc = smb2_serve_port(
        &server_, 4,
        [](struct smb2_context *smb2, void *cb_data) {
            // 只协商 SMB 2.0.2：libsmb2 服务端在 2.1 / 3.1.1 下会强制开启签名
            // （见 libsmb2.c 中 dialect == 0210 / >= 0311 时 will_sign = 1），
            // 而签名密钥要等 NTLM 认证完成才能派生，导致 session setup 阶段的
            // 响应签名无效。iOS / macOS 等严格校验签名的客户端会直接断开。
            // 2.0.2 不在强制签名列表内，可避开该问题。
            smb2_set_version(smb2, SMB2_VERSION_0202);
            // 开启 passthrough：目录项/文件信息按 wire format 原样收发。
            // 否则 libsmb2 会把我们自己编码的 blob 当成 C 结构体重新解析，
            // 读 fs->name 指针时错乱导致服务端崩溃。
            smb2_set_passthrough(smb2, 1);
            // 注册错误回调，把 libsmb2 内部的失败原因输出到 stderr，
            // 否则客户端中途断开时服务端看不到任何线索。
            smb2_register_error_callback(smb2, [](struct smb2_context *s, const char *err) {
//                 if (err) {
//                     fprintf(stderr, "[SMB][error] %s\n", err);
//                 }
            });
            auto *p = (struct smb2_context **)cb_data;
            *p = smb2;
        },
        &ctx);
    running_ = false;

    // 服务循环退出后回收 DCE/RPC 端点
    {
        std::lock_guard<std::mutex> guard(rpc_mutex_);
        for (auto &it : rpc_pipes_) {
            if (it.second != NULL) {
                dcerpc_server_pipe_destroy(it.second);
            }
        }
        rpc_pipes_.clear();
        if (rpc_ != NULL) {
            dcerpc_server_destroy(rpc_);
            rpc_ = NULL;
        }
    }
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
