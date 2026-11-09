#pragma once

#include <napi.h>
#include <string>
#include <vector>
#include <mutex>
#include <thread>
#include <map>
#include <array>
#include <atomic>
#include <cctype>
#include <condition_variable>

extern "C" {
#include "smb2.h"
#include "libsmb2.h"
#include "libsmb2-private.h"
}

/**
 * 服务端请求参数。
 *
 * 关键约束：服务线程没有 HandleScope，绝不能碰 Napi::Value / Napi::Object。
 * 所以跨线程传递的数据必须先是纯粹的 C++ 类型，到主线程再转成 JS 对象。
 */
struct Smb2Req {
    std::string op;

    // authorize
    std::string user;
    std::string domain;
    std::string workstation;

    // 当前 tree 连接到的共享名；authorize 阶段为空
    std::string share;

    // create
    std::string name;
    uint32_t desired_access = 0;
    uint32_t create_disposition = 0;
    uint32_t create_options = 0;

    // 通用
    std::string path;
    uint64_t handle_id = 0;
    uint64_t offset = 0;
    uint32_t length = 0;
    std::string data;          // write 的数据

    // queryDirectory
    std::string pattern;
    uint32_t index = 0;
    uint32_t buffer_length = 0;

    // queryDirectory 的目录项结果：C++ 侧要据此填 smb2_fileidbothdirectoryinformation
    struct DirEntry {
        std::string name;
        uint64_t size = 0;
        uint64_t mtime = 0;
        bool is_dir = false;
    };
    std::vector<DirEntry> out_entries;

    // queryInfo
    uint32_t info_type = 0;
    uint32_t file_info_class = 0;

    // ---- 结果 ----
    bool ok = false;
    int err = 0;               // 错误 errno
    uint64_t out_handle = 0;
    bool out_is_dir = false;
    bool out_delete_on_close = false;
    std::string out_password;   // authorize 返回的密码，空表示匿名
    std::string out_path;
    uint64_t out_size = 0;
    uint64_t out_mtime = 0;    // queryInfo 返回的修改时间（unix 秒）
    uint32_t out_create_action = 0;

    std::string out_bytes;     // read/queryDirectory/queryInfo 的返回字节
};

/**
 * SMB2/3 服务端。
 *
 * smb2_serve_port() 是带 select() 的阻塞主循环（见 c-libsmb2/lib/libsmb2.c），
 * 独占一个 std::thread 运行；所有 handler 都在该线程同步回调。
 *
 * handler 要拿 JS 侧的数据，通过 napi_threadsafe_function 投递到主线程，
 * 服务线程在条件变量上等待，拿到结果后填 reply。
 */
class Smb2Server : public Napi::ObjectWrap<Smb2Server> {
public:
    static Napi::Object Init(Napi::Env env, Napi::Object exports);

    explicit Smb2Server(const Napi::CallbackInfo &info);
    ~Smb2Server() override;

    Napi::Value Start(const Napi::CallbackInfo &info);
    Napi::Value Stop(const Napi::CallbackInfo &info);
    Napi::Value IsRunning(const Napi::CallbackInfo &info);

    // 服务线程调用：阻塞直到主线程执行完 JS 并把结果写回 req
    bool CallJs(Smb2Req &req);

    friend struct ServerHandlers;

private:
    void ServeLoop();

    struct smb2_server server_{};
    std::thread thread_;
    std::atomic<bool> running_{false};

    Napi::ThreadSafeFunction tsfn_;
    Napi::ObjectReference api_;

    std::mutex ipc_mtx_;
    std::map<uint64_t, std::string> pipe_handles_;
    uint64_t next_pipe_handle_ = 0x8000000000000000ULL;
    std::mutex last_fid_mtx_;
    std::map<struct smb2_context *, std::array<uint8_t, SMB2_FD_SIZE>> last_fids_;
    std::mutex pending_mtx_;
    std::map<uint64_t, std::string> pending_delete_;

    std::mutex handles_mtx_;
    std::map<uint64_t, std::string> handles_;   // handle -> 绝对路径
    uint64_t next_handle_ = 1;

    // 目录枚举的稳定 file id（不参与 create/close 生命周期，不释放）
    std::mutex dir_ids_mtx_;
    std::map<std::string, uint64_t> dir_path_to_id_;   // 绝对路径 -> id
    std::map<uint64_t, std::string> id_to_dir_path_;   // id -> 绝对路径
    uint64_t next_dir_id_ = 0x4000000000000000ULL;     // 与 handle 区间分开，避免混淆

    bool readonly_ = false;
    // 共享名 -> 目录；有序，枚举时保持配置顺序
    std::vector<std::pair<std::string, std::string>> shares_;
    std::string share_remark_ = "FileCat";

    // srvsvc 共享枚举：libdcerpc 的服务端运行时。
    // 只在服务线程内访问，rpc_mutex_ 防止 Stop 与服务线程竞争。
    struct dcerpc_server *rpc_ = NULL;
    std::map<uint64_t, struct dcerpc_server_pipe *> rpc_pipes_;
    std::mutex rpc_mutex_;

    // srvsvc 响应体：stub 手工编码后放这里，ioctl_cmd 取走写回客户端。
    // 不用 libdcerpc 的 coder 是因为它对嵌套指针只写 UPTR/RPTR 占位，
    // 真实 SMB 客户端解析不了。
    std::vector<uint8_t> srvsvc_reply_;
    bool srvsvc_reply_ready_ = false;
    // 每个连接当前 tree 对应的共享名
    std::mutex tree_mtx_;
    std::map<struct smb2_context *, std::string> cur_share_;   // IPC$ 标记
    std::map<struct smb2_context *, std::string> disk_share_;  // 磁盘共享名

public:
    bool readonly() const { return readonly_; }

    void set_share_remark(const std::string &n) { share_remark_ = n; }
    const std::string &share_remark() const { return share_remark_; }

    /** 共享名是否存在于配置中（SMB 共享名大小写不敏感） */
    bool has_share(const std::string &n) const {
        return !canonical_share(n).empty();
    }

    /** 按大小写不敏感规则返回配置里的规范共享名，未命中返回空串 */
    std::string canonical_share(const std::string &n) const {
        for (const auto &it : shares_) {
            if (it.first.size() != n.size()) {
                continue;
            }
            bool same = true;
            for (size_t i = 0; i < n.size(); i++) {
                if (std::tolower((unsigned char)it.first[i]) != std::tolower((unsigned char)n[i])) {
                    same = false;
                    break;
                }
            }
            if (same) {
                return it.first;
            }
        }
        return std::string();
    }

    const std::vector<std::pair<std::string, std::string>> &shares() const {
        return shares_;
    }

    /**
     * tree_connect 时记录共享名。
     *
     * libsmb2 服务端不会把请求的 tree_id 填进 smb2_context
     * （hdr.sync.tree_id 和 smb2_tree_id() 都拿不到真实值），
     * 因此改为：记录「本连接最近一次 tree_connect 的共享名」。
     * 客户端在同一连接上切换 tree 时会再发一次 tree_connect，
     * 这里跟着更新即可，create 时直接用当前值。
     */
    void set_tree_share(struct smb2_context *ctx, const std::string &name) {
        std::lock_guard<std::mutex> lock(tree_mtx_);
        std::string lower = name;
        for (size_t i = 0; i < lower.size(); i++) {
            lower[i] = (char)tolower((unsigned char)lower[i]);
        }
        // IPC$ 与磁盘共享在同一连接上并存，分开记，create 时按名字特征选
        if (lower == "ipc$") {
            cur_share_[ctx] = "IPC$";
        }
        else {
            disk_share_[ctx] = name;
        }
    }

    /** 取本连接当前 tree 对应的共享名 */
    std::string tree_share(struct smb2_context *ctx) {
        std::lock_guard<std::mutex> lock(tree_mtx_);
        auto it = cur_share_.find(ctx);
        return it == cur_share_.end() ? std::string() : it->second;
    }

    /** 取本连接的磁盘共享名（非 IPC$） */
    std::string disk_share(struct smb2_context *ctx) {
        std::lock_guard<std::mutex> lock(tree_mtx_);
        auto it = disk_share_.find(ctx);
        return it == disk_share_.end() ? std::string() : it->second;
    }

    void clear_tree_share(struct smb2_context *ctx) {
        // 同一连接上可能有多个 tree（SHARE1 与 IPC$），某个 tree 断开
        // 不应把整条连接的记录清掉，否则后续 create 拿不到共享名。
        // 这里保留最近一次 tree_connect 的名字，连接销毁时随 map 一起回收。
        (void)ctx;
    }

    void set_ipc_tree(struct smb2_context *ctx, bool on) {
        (void)ctx;
        (void)on;
    }

    /** 本连接当前 tree 是否为 IPC$ */
    bool is_ipc_tree(struct smb2_context *ctx) {
        std::string s = tree_share(ctx);
        for (size_t i = 0; i < s.size(); i++) {
            s[i] = (char)tolower((unsigned char)s[i]);
        }
        return s == "ipc$";
    }

    uint64_t add_pipe_handle(const std::string &nm) {
        std::lock_guard<std::mutex> lock(ipc_mtx_);
        uint64_t ph = next_pipe_handle_++;
        pipe_handles_[ph] = nm;
        return ph;
    }

    bool get_pipe_name(uint64_t ph, std::string *nm) {
        std::lock_guard<std::mutex> lock(ipc_mtx_);
        auto it = pipe_handles_.find(ph);
        if (it == pipe_handles_.end()) {
            return false;
        }
        *nm = it->second;
        return true;
    }

    void del_pipe_handle(uint64_t ph) {
        std::lock_guard<std::mutex> lock(ipc_mtx_);
        pipe_handles_.erase(ph);
    }

    void set_last_file_id(struct smb2_context *ctx, const smb2_file_id fid) {
        std::lock_guard<std::mutex> lock(last_fid_mtx_);
        auto it = last_fids_.find(ctx);
        if (it == last_fids_.end()) {
            last_fids_[ctx] = {};
            it = last_fids_.find(ctx);
        }
        memcpy(it->second.data(), fid, SMB2_FD_SIZE);
    }

    bool get_last_file_id(struct smb2_context *ctx, smb2_file_id out) {
        std::lock_guard<std::mutex> lock(last_fid_mtx_);
        auto it = last_fids_.find(ctx);
        if (it == last_fids_.end()) {
            return false;
        }
        memcpy(out, it->second.data(), SMB2_FD_SIZE);
        return true;
    }

    void drop_last_file_id(struct smb2_context *ctx) {
        std::lock_guard<std::mutex> lock(last_fid_mtx_);
        last_fids_.erase(ctx);
    }

    void rename_handle(uint64_t handle, const std::string &new_path) {
        std::lock_guard<std::mutex> lock(handles_mtx_);
        auto it = handles_.find(handle);
        if (it != handles_.end()) {
            it->second = new_path;
        }
    }

    void mark_pending_delete(uint64_t handle, const std::string &p) {
        std::lock_guard<std::mutex> lock(pending_mtx_);
        pending_delete_[handle] = p;
    }

    bool take_pending_delete(uint64_t handle, std::string *p) {
        std::lock_guard<std::mutex> lock(pending_mtx_);
        auto it = pending_delete_.find(handle);
        if (it == pending_delete_.end()) {
            return false;
        }
        *p = it->second;
        pending_delete_.erase(it);
        return true;
    }

    uint64_t add_handle(const std::string &path) {
        std::lock_guard<std::mutex> lock(handles_mtx_);
        uint64_t h = next_handle_++;
        handles_[h] = path;
        return h;
    }

    /*
     * 目录枚举专用的稳定 file id。
     * 目录项不经过 create/close 生命周期，如果直接用 add_handle 会在每次
     * 列目录时给每个条目新建一条 handle 记录且永不释放，memory 会持续增长。
     * 这里按路径复用同一个 id，既保证 FILE_OPEN_BY_FILE_ID 能反查到路径，
     * 又不会随列目录次数增加内存。
     */
    uint64_t dir_entry_file_id(const std::string &path) {
        std::lock_guard<std::mutex> lock(dir_ids_mtx_);
        auto it = dir_path_to_id_.find(path);
        if (it != dir_path_to_id_.end()) {
            return it->second;
        }
        uint64_t id = next_dir_id_++;
        dir_path_to_id_[path] = id;
        id_to_dir_path_[id] = path;
        return id;
    }

    /* 目录枚举分配的 id 也能被 FILE_OPEN_BY_FILE_ID 反查到路径 */
    bool get_dir_entry_path(uint64_t id, std::string *out_path) {
        std::lock_guard<std::mutex> lock(dir_ids_mtx_);
        auto it = id_to_dir_path_.find(id);
        if (it == id_to_dir_path_.end()) {
            return false;
        }
        *out_path = it->second;
        return true;
    }

    bool get_handle(uint64_t h, std::string *out_path) {
        std::lock_guard<std::mutex> lock(handles_mtx_);
        auto it = handles_.find(h);
        if (it == handles_.end()) {
            return false;
        }
        *out_path = it->second;
        return true;
    }

    void del_handle(uint64_t h) {
        std::lock_guard<std::mutex> lock(handles_mtx_);
        handles_.erase(h);
    }
};
