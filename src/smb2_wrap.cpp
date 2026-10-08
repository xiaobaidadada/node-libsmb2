#include "smb2_wrap.h"
#include "workers.h"
#include <fcntl.h>
#include <cstring>

/* ---------------------------------------------------------------- */
/* 工具                                                              */
/* ---------------------------------------------------------------- */

static std::string GetStringArg(const Napi::CallbackInfo &info, size_t idx,
                                const char *name) {
    if (info.Length() <= idx || !info[idx].IsString()) {
        throw Napi::TypeError::New(info.Env(),
                                   std::string("参数 ") + name + " 必须是字符串");
    }
    return info[idx].As<Napi::String>().Utf8Value();
}

static uint64_t GetBigUintArg(const Napi::CallbackInfo &info, size_t idx,
                              const char *name, uint64_t def) {
    if (info.Length() <= idx || info[idx].IsUndefined() || info[idx].IsNull()) {
        return def;
    }
    if (info[idx].IsBigInt()) {
        bool lossless = false;
        return info[idx].As<Napi::BigInt>().Uint64Value(&lossless);
    }
    if (info[idx].IsNumber()) {
        return (uint64_t)info[idx].As<Napi::Number>().Int64Value();
    }
    throw Napi::TypeError::New(info.Env(),
                               std::string("参数 ") + name + " 必须是整数");
}

/* ---------------------------------------------------------------- */
/* Smb2Client                                                        */
/* ---------------------------------------------------------------- */

Smb2Client::Smb2Client(const Napi::CallbackInfo &info)
    : Napi::ObjectWrap<Smb2Client>(info) {}

Smb2Client::~Smb2Client() {
    std::lock_guard<std::mutex> lock(mtx_);
    if (ctx_) {
        smb2_disconnect_share(ctx_);
        smb2_destroy_context(ctx_);
        ctx_ = nullptr;
    }
}

Napi::Value Smb2Client::IsConnected(const Napi::CallbackInfo &info) {
    return Napi::Boolean::New(info.Env(), connected_);
}

Napi::Value Smb2Client::Connect(const Napi::CallbackInfo &info) {
    Napi::Env env = info.Env();

    // connect({ server, share, user, domain, password, security, timeout })
    if (info.Length() < 1 || !info[0].IsObject()) {
        throw Napi::TypeError::New(env, "connect 需要传入配置对象");
    }
    auto opts = info[0].As<Napi::Object>();

    auto opt_str = [&](const char *key) -> std::string {
        if (!opts.Has(key) || opts.Get(key).IsUndefined() ||
            opts.Get(key).IsNull()) {
            return "";
        }
        return opts.Get(key).As<Napi::String>().Utf8Value();
    };

    std::string server = opt_str("server");
    std::string share = opt_str("share");
    if (server.empty() || share.empty()) {
        throw Napi::TypeError::New(env, "server 与 share 不能为空");
    }

    std::string user = opt_str("user");
    std::string domain = opt_str("domain");
    std::string password = opt_str("password");

    uint16_t security = SMB2_SEC_NTLMSSP;
    if (opts.Has("security") && opts.Get("security").IsString()) {
        std::string s = opts.Get("security").As<Napi::String>().Utf8Value();
        if (s == "krb5") {
            security = SMB2_SEC_KRB5;
        }
    }

    int timeout = 60;
    if (opts.Has("timeout") && opts.Get("timeout").IsNumber()) {
        timeout = opts.Get("timeout").As<Napi::Number>().Int32Value();
    }

    auto *worker = new ConnectWorker(env, this, server, share, user, domain,
                                     password, security, timeout);
    auto promise = worker->Promise();
    worker->Queue();
    return promise;
}

Napi::Value Smb2Client::ShareEnum(const Napi::CallbackInfo &info) {
    Napi::Env env = info.Env();

    // shareEnum({ server, user, domain, password, security, timeout })
    if (info.Length() < 1 || !info[0].IsObject()) {
        throw Napi::TypeError::New(env, "shareEnum 需要传入配置对象");
    }
    auto opts = info[0].As<Napi::Object>();

    auto opt_str = [&](const char *key) -> std::string {
        if (!opts.Has(key) || opts.Get(key).IsUndefined() ||
            opts.Get(key).IsNull()) {
            return "";
        }
        return opts.Get(key).As<Napi::String>().Utf8Value();
    };

    std::string server = opt_str("server");
    if (server.empty()) {
        throw Napi::TypeError::New(env, "server 不能为空");
    }

    uint16_t security = SMB2_SEC_NTLMSSP;
    if (opts.Has("security") && opts.Get("security").IsString()) {
        std::string s = opts.Get("security").As<Napi::String>().Utf8Value();
        if (s == "krb5") {
            security = SMB2_SEC_KRB5;
        }
    }

    int timeout = 60;
    if (opts.Has("timeout") && opts.Get("timeout").IsNumber()) {
        timeout = opts.Get("timeout").As<Napi::Number>().Int32Value();
    }

    auto *worker = new ShareEnumWorker(env, this, server, opt_str("user"),
                                       opt_str("domain"), opt_str("password"),
                                       security, timeout);
    auto promise = worker->Promise();
    worker->Queue();
    return promise;
}

Napi::Value Smb2Client::Disconnect(const Napi::CallbackInfo &info) {
    std::lock_guard<std::mutex> lock(mtx_);
    if (ctx_) {
        smb2_disconnect_share(ctx_);
        smb2_destroy_context(ctx_);
        ctx_ = nullptr;
    }
    connected_ = false;
    return Napi::Boolean::New(info.Env(), true);
}

Napi::Value Smb2Client::Opendir(const Napi::CallbackInfo &info) {
    Napi::Env env = info.Env();
    std::string path = GetStringArg(info, 0, "path");
    auto *worker = new OpendirWorker(env, this, path);
    auto promise = worker->Promise();
    worker->Queue();
    return promise;
}

Napi::Value Smb2Client::Stat(const Napi::CallbackInfo &info) {
    Napi::Env env = info.Env();
    std::string path = GetStringArg(info, 0, "path");
    auto *worker = new StatWorker(env, this, path);
    auto promise = worker->Promise();
    worker->Queue();
    return promise;
}

Napi::Value Smb2Client::Read(const Napi::CallbackInfo &info) {
    Napi::Env env = info.Env();
    std::string path = GetStringArg(info, 0, "path");
    uint64_t offset = 0;
    uint32_t length = 64 * 1024;

    // read(path, { offset, length })
    if (info.Length() >= 2 && info[1].IsObject()) {
        auto opts = info[1].As<Napi::Object>();
        if (opts.Has("offset")) {
            if (opts.Get("offset").IsBigInt()) {
                bool lossless = false;
                offset =
                    opts.Get("offset").As<Napi::BigInt>().Uint64Value(&lossless);
            } else {
                offset = (uint64_t)opts.Get("offset").As<Napi::Number>().Int64Value();
            }
        }
        if (opts.Has("length")) {
            length = (uint32_t)opts.Get("length").As<Napi::Number>().Uint32Value();
        }
    } else if (info.Length() >= 3) {
        offset = GetBigUintArg(info, 1, "offset", 0);
        length = (uint32_t)GetBigUintArg(info, 2, "length", 64 * 1024);
    }

    auto *worker = new ReadWorker(env, this, path, offset, length);
    auto promise = worker->Promise();
    worker->Queue();
    return promise;
}

Napi::Value Smb2Client::Write(const Napi::CallbackInfo &info) {
    Napi::Env env = info.Env();
    std::string path = GetStringArg(info, 0, "path");

    if (info.Length() < 2 || !info[1].IsBuffer()) {
        throw Napi::TypeError::New(env, "write 的第二个参数必须是 Buffer");
    }
    auto buf = info[1].As<Napi::Buffer<uint8_t>>();
    std::vector<uint8_t> data(buf.Data(), buf.Data() + buf.Length());

    uint64_t offset = 0;
    if (info.Length() >= 3 && info[2].IsObject()) {
        auto opts = info[2].As<Napi::Object>();
        if (opts.Has("offset")) {
            if (opts.Get("offset").IsBigInt()) {
                bool lossless = false;
                offset =
                    opts.Get("offset").As<Napi::BigInt>().Uint64Value(&lossless);
            } else {
                offset =
                    (uint64_t)opts.Get("offset").As<Napi::Number>().Int64Value();
            }
        }
    } else if (info.Length() >= 3) {
        offset = GetBigUintArg(info, 2, "offset", 0);
    }

    auto *worker = new WriteWorker(env, this, path, std::move(data), offset);
    auto promise = worker->Promise();
    worker->Queue();
    return promise;
}

static Napi::Value QueueSimple(Napi::Env env, Smb2Client *client,
                               SimpleWorker::Op op, const std::string &path,
                               const std::string &path2 = "") {
    auto *worker = new SimpleWorker(env, client, op, path, path2);
    auto promise = worker->Promise();
    worker->Queue();
    return promise;
}

Napi::Value Smb2Client::Unlink(const Napi::CallbackInfo &info) {
    return QueueSimple(info.Env(), this, SimpleWorker::UNLINK,
                       GetStringArg(info, 0, "path"));
}

Napi::Value Smb2Client::Mkdir(const Napi::CallbackInfo &info) {
    return QueueSimple(info.Env(), this, SimpleWorker::MKDIR,
                       GetStringArg(info, 0, "path"));
}

Napi::Value Smb2Client::Rmdir(const Napi::CallbackInfo &info) {
    return QueueSimple(info.Env(), this, SimpleWorker::RMDIR,
                       GetStringArg(info, 0, "path"));
}

Napi::Value Smb2Client::Rename(const Napi::CallbackInfo &info) {
    return QueueSimple(info.Env(), this, SimpleWorker::RENAME,
                       GetStringArg(info, 0, "old_path"),
                       GetStringArg(info, 1, "new_path"));
}

Napi::Value Smb2Client::Truncate(const Napi::CallbackInfo &info) {
    return QueueSimple(info.Env(), this, SimpleWorker::TRUNCATE,
                       GetStringArg(info, 0, "path"));
}

Napi::Value Smb2Client::Readlink(const Napi::CallbackInfo &info) {
    throw Napi::Error::New(info.Env(), "readlink 暂未支持");
}

/* ---------------------------------------------------------------- */
/* 模块入口                                                          */
/* ---------------------------------------------------------------- */

Napi::Object Smb2Client::Init(Napi::Env env, Napi::Object exports) {
    Napi::Function func = DefineClass(
        env, "Smb2Client",
        {
            InstanceMethod("connect", &Smb2Client::Connect),
            InstanceMethod("disconnect", &Smb2Client::Disconnect),
            InstanceMethod("isConnected", &Smb2Client::IsConnected),
            InstanceMethod("opendir", &Smb2Client::Opendir),
            InstanceMethod("stat", &Smb2Client::Stat),
            InstanceMethod("read", &Smb2Client::Read),
            InstanceMethod("write", &Smb2Client::Write),
            InstanceMethod("unlink", &Smb2Client::Unlink),
            InstanceMethod("mkdir", &Smb2Client::Mkdir),
            InstanceMethod("rmdir", &Smb2Client::Rmdir),
            InstanceMethod("rename", &Smb2Client::Rename),
            InstanceMethod("truncate", &Smb2Client::Truncate),
            InstanceMethod("shareEnum", &Smb2Client::ShareEnum),
        });

    exports.Set("Smb2Client", func);
    return exports;
}

static Napi::Object InitAll(Napi::Env env, Napi::Object exports) {
    return Smb2Client::Init(env, exports);
}

NODE_API_MODULE(node_smb2, InitAll)
