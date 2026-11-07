#pragma once

#include <napi.h>
#include <string>
#include <vector>
#include <mutex>
#include <thread>
#include <map>
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

    std::mutex handles_mtx_;
    std::map<uint64_t, std::string> handles_;   // handle -> 绝对路径
    uint64_t next_handle_ = 1;

    std::string root_path_;
    bool readonly_ = false;

public:
    bool readonly() const { return readonly_; }

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
