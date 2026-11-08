#pragma once

#include <napi.h>
#include <string>
#include <vector>
#include <mutex>
#include <thread>
#include <map>
#include <array>
#include <atomic>
#include <condition_variable>

extern "C" {
#include "smb2.h"
#include "libsmb2.h"
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
    std::map<struct smb2_context *, bool> ipc_trees_;
    std::map<uint64_t, std::string> pipe_handles_;
    uint64_t next_pipe_handle_ = 0x8000000000000000ULL;
    std::mutex last_fid_mtx_;
    std::map<struct smb2_context *, std::array<uint8_t, SMB2_FD_SIZE>> last_fids_;
    std::mutex pending_mtx_;
    std::map<uint64_t, std::string> pending_delete_;

    std::mutex handles_mtx_;
    std::map<uint64_t, std::string> handles_;   // handle -> 绝对路径
    uint64_t next_handle_ = 1;

    bool readonly_ = false;
    // 共享名 -> 目录；有序，枚举时保持配置顺序
    std::vector<std::pair<std::string, std::string>> shares_;
    std::string share_remark_ = "FileCat";
    // 每连接的 tree 连接到的共享名
    std::mutex tree_mtx_;
    std::map<struct smb2_context *, std::string> tree_shares_;

public:
    bool readonly() const { return readonly_; }

    void set_share_remark(const std::string &n) { share_remark_ = n; }
    const std::string &share_remark() const { return share_remark_; }

    /** 共享名是否存在于配置中 */
    bool has_share(const std::string &n) const {
        for (const auto &it : shares_) {
            if (it.first == n) {
                return true;
            }
        }
        return false;
    }

    const std::vector<std::pair<std::string, std::string>> &shares() const {
        return shares_;
    }

    /** tree_connect 时记录该连接连到了哪个共享 */
    void set_tree_share(struct smb2_context *ctx, const std::string &n) {
        std::lock_guard<std::mutex> lock(tree_mtx_);
        tree_shares_[ctx] = n;
    }

    /** 取该连接当前树连接的共享名，未连接时返回空串 */
    std::string tree_share(struct smb2_context *ctx) {
        std::lock_guard<std::mutex> lock(tree_mtx_);
        auto it = tree_shares_.find(ctx);
        return it == tree_shares_.end() ? std::string() : it->second;
    }

    void clear_tree_share(struct smb2_context *ctx) {
        std::lock_guard<std::mutex> lock(tree_mtx_);
        tree_shares_.erase(ctx);
    }

    void set_ipc_tree(struct smb2_context *ctx, bool on) {
        std::lock_guard<std::mutex> lock(ipc_mtx_);
        ipc_trees_[ctx] = on;
    }

    bool is_ipc_tree(struct smb2_context *ctx) {
        std::lock_guard<std::mutex> lock(ipc_mtx_);
        auto it = ipc_trees_.find(ctx);
        return it != ipc_trees_.end() && it->second;
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
