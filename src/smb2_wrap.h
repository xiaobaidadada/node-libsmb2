#pragma once

#include <napi.h>
#include <string>
#include <vector>
#include <mutex>
#include <memory>

extern "C" {
#include "smb2.h"
#include "libsmb2.h"
#include "libsmb2-share-enum.h"

// smb2_free_data 在 libsmb2.syms 中已导出，但头文件没声明，这里补上
void smb2_free_data(struct smb2_context *smb2, void *ptr);
}

/**
 * 封装 libsmb2 的一个连接上下文。
 *
 * libsmb2 的同步 API 内部通过 poll() 阻塞等待应答（见 lib/sync.c 的
 * wait_for_reply），因此绝不能在 Node 主线程调用，所有操作都提交到
 * libuv 线程池执行。
 *
 * 同时 libsmb2 的 smb2_context 不是线程安全的，所以本类用一把互斥锁
 * 把所有操作串行化，保证同一时刻只有一个线程碰 context。
 */
class Smb2Client : public Napi::ObjectWrap<Smb2Client> {
public:
    static Napi::Object Init(Napi::Env env, Napi::Object exports);

    explicit Smb2Client(const Napi::CallbackInfo &info);
    ~Smb2Client() override;

    // workers 需要直接访问连接状态与锁，故公开
    struct smb2_context *ctx_ = nullptr;
    std::mutex mtx_;            // 串行化对 ctx_ 的访问
    bool connected_ = false;
    std::string server_;
    std::string share_;

private:
    // 连接 / 断开
    Napi::Value Connect(const Napi::CallbackInfo &info);
    Napi::Value Disconnect(const Napi::CallbackInfo &info);
    Napi::Value IsConnected(const Napi::CallbackInfo &info);

    // 目录
    Napi::Value Opendir(const Napi::CallbackInfo &info);

    // 元信息
    Napi::Value Stat(const Napi::CallbackInfo &info);
    Napi::Value Statvfs(const Napi::CallbackInfo &info);

    // 读
    Napi::Value Read(const Napi::CallbackInfo &info);

    // 写
    Napi::Value Write(const Napi::CallbackInfo &info);

    // 目录与文件操作
    Napi::Value Unlink(const Napi::CallbackInfo &info);
    Napi::Value Mkdir(const Napi::CallbackInfo &info);
    Napi::Value Rmdir(const Napi::CallbackInfo &info);
    Napi::Value Rename(const Napi::CallbackInfo &info);
    Napi::Value Truncate(const Napi::CallbackInfo &info);
    Napi::Value Readlink(const Napi::CallbackInfo &info);

    // 工具
    Napi::Value GetError(const Napi::CallbackInfo &info);

    // 枚举远程主机的共享列表
    Napi::Value ShareEnum(const Napi::CallbackInfo &info);

    // 内部：把 libsmb2 错误码 + smb2_get_error 组装成 JS Error 抛出去
    void ThrowSmb2(Napi::Env env, const std::string &what, int rc);
};
