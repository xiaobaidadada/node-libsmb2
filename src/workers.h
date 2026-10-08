#include <napi.h>
#include "smb2_wrap.h"

/**
 * 通用异步任务骨架：把一段阻塞逻辑丢进 libuv 线程池执行。
 *
 * 所有 libsmb2 调用都走这个模板，原因是它的同步 API 内部会 poll() 阻塞，
 * 直接在主线程调用会卡死 Node 的事件循环。
 *
 * 注意：AsyncWorker 会自行 delete this，所以 worker 必须 new 出来，
 * 且 deferred_ 在 OnOK/OnError 里使用（此时对象仍存活，回调结束后才析构）。
 */
template <typename Result>
class Smb2Worker : public Napi::AsyncWorker {
public:
    Smb2Worker(Napi::Env env, Smb2Client *client)
        : Napi::AsyncWorker(env), client_(client),
          deferred_(Napi::Promise::Deferred::New(env)) {}

    Napi::Promise Promise() { return deferred_.Promise(); }

protected:
    void Execute() override {
        try {
            Run();
        } catch (const std::exception &e) {
            SetError(e.what());
        } catch (...) {
            SetError("unknown error");
        }
    }

    void OnOK() override {
        Napi::Env env = Env();
        Napi::HandleScope scope(env);
        deferred_.Resolve(Build(env));
    }

    void OnError(const Napi::Error &e) override {
        Napi::HandleScope scope(Env());
        deferred_.Reject(e.Value());
    }

    // 子类实现：在工作线程里执行的实际逻辑
    virtual void Run() = 0;
    // 子类实现：把结果转成 JS 值
    virtual Napi::Value Build(Napi::Env env) = 0;

    Smb2Client *client_;
    Napi::Promise::Deferred deferred_;
    Result result_;
};

// ============================ 连接 ============================

class ConnectWorker : public Smb2Worker<int> {
public:
    ConnectWorker(Napi::Env env, Smb2Client *client, const std::string &server,
                  const std::string &share, const std::string &user,
                  const std::string &domain, const std::string &password,
                  uint16_t security_mode, int timeout)
        : Smb2Worker(env, client), server_(server), share_(share), user_(user),
          domain_(domain), password_(password), security_(security_mode),
          timeout_(timeout) {}

protected:
    void Run() override;
    Napi::Value Build(Napi::Env env) override;

private:
    std::string server_, share_, user_, domain_, password_;
    uint16_t security_;
    int timeout_;
};

// ============================ 列目录 ============================

struct DirEntry {
    std::string name;
    bool is_dir;
    uint64_t size;
    uint64_t mtime;
    uint64_t ctime;
    uint64_t atime;
};

class OpendirWorker : public Smb2Worker<std::vector<DirEntry>> {
public:
    OpendirWorker(Napi::Env env, Smb2Client *client, const std::string &path)
        : Smb2Worker(env, client), path_(path) {}

protected:
    void Run() override;
    Napi::Value Build(Napi::Env env) override;

private:
    std::string path_;
};

// ============================ 元信息 ============================

struct StatInfo {
    bool exists = false;
    uint32_t type;
    uint64_t size;
    uint64_t ino;
    uint64_t atime, mtime, ctime, btime;
    uint32_t nlink;
};

class StatWorker : public Smb2Worker<StatInfo> {
public:
    StatWorker(Napi::Env env, Smb2Client *client, const std::string &path)
        : Smb2Worker(env, client), path_(path) {}

protected:
    void Run() override;
    Napi::Value Build(Napi::Env env) override;

private:
    std::string path_;
};

// ============================ 读 ============================

class ReadWorker : public Smb2Worker<std::vector<uint8_t>> {
public:
    ReadWorker(Napi::Env env, Smb2Client *client, const std::string &path,
               uint64_t offset, uint32_t length)
        : Smb2Worker(env, client), path_(path), offset_(offset), length_(length) {}

protected:
    void Run() override;
    Napi::Value Build(Napi::Env env) override;

private:
    std::string path_;
    uint64_t offset_;
    uint32_t length_;
};

// ============================ 写 ============================

class WriteWorker : public Smb2Worker<uint32_t> {
public:
    WriteWorker(Napi::Env env, Smb2Client *client, const std::string &path,
                std::vector<uint8_t> data, uint64_t offset)
        : Smb2Worker(env, client), path_(path), data_(std::move(data)),
          offset_(offset) {}

protected:
    void Run() override;
    Napi::Value Build(Napi::Env env) override;

private:
    std::string path_;
    std::vector<uint8_t> data_;
    uint64_t offset_;
};

// ============================ 枚举共享 ============================

struct ShareEntry {
    std::string name;
    std::string remark;
    bool is_ipc;
};

// 枚举远程主机的共享列表。需要临时连到 IPC$ 共享（与业务共享是两个会话），
// 因此不走 client_ 上已有的 context，自己开一个用完即毁。
class ShareEnumWorker : public Smb2Worker<std::vector<ShareEntry>> {
public:
    ShareEnumWorker(Napi::Env env, Smb2Client *client, const std::string &server,
                    const std::string &user, const std::string &domain,
                    const std::string &password, uint16_t security_mode,
                    int timeout)
        : Smb2Worker(env, client), server_(server), user_(user), domain_(domain),
          password_(password), security_(security_mode), timeout_(timeout) {}

protected:
    void Run() override;
    Napi::Value Build(Napi::Env env) override;

private:
    std::string server_, user_, domain_, password_;
    uint16_t security_;
    int timeout_;
};

// ============================ 简单操作 ============================

// 用于 unlink / mkdir / rmdir / rename / truncate 这类无返回值操作
class SimpleWorker : public Smb2Worker<int> {
public:
    enum Op { UNLINK, MKDIR, RMDIR, RENAME, TRUNCATE };

    SimpleWorker(Napi::Env env, Smb2Client *client, Op op,
                 const std::string &path, const std::string &path2 = "")
        : Smb2Worker(env, client), op_(op), path_(path), path2_(path2) {}

protected:
    void Run() override;
    Napi::Value Build(Napi::Env env) override;

private:
    Op op_;
    std::string path_, path2_;
};
