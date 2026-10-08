#include "workers.h"
#include "smb2_wrap.h"
#include <fcntl.h>

// ============================ Connect ============================

void ConnectWorker::Run() {
    // 连接阶段自己创建 context，成功后交给 client 持有，
    // 避免连接失败时把 client 置成半残状态
    struct smb2_context *ctx = smb2_init_context();
    if (!ctx) {
        SetError("smb2_init_context 失败：内存不足");
        return;
    }

    smb2_set_security_mode(ctx, security_);
    if (timeout_ > 0) {
        smb2_set_timeout(ctx, timeout_);
    }
    if (!domain_.empty()) {
        smb2_set_domain(ctx, domain_.c_str());
    }
    if (!user_.empty()) {
        smb2_set_user(ctx, user_.c_str());
    }
    if (!password_.empty()) {
        smb2_set_password(ctx, password_.c_str());
    }
    // 允许未签名的 NTLM 会话，兼容大部分 Samba / 老 NAS
    smb2_set_seal(ctx, 0);
    smb2_set_sign(ctx, 0);

    int rc = smb2_connect_share(ctx, server_.c_str(), share_.c_str(),
                                user_.empty() ? nullptr : user_.c_str());
    if (rc < 0) {
        std::string err = smb2_get_error(ctx);
        smb2_destroy_context(ctx);
        SetError("连接共享失败: " + err);
        return;
    }

    std::lock_guard<std::mutex> lock(client_->mtx_);
    // 重复 connect 时先释放旧连接
    if (client_->ctx_) {
        smb2_disconnect_share(client_->ctx_);
        smb2_destroy_context(client_->ctx_);
    }
    client_->ctx_ = ctx;
    client_->connected_ = true;
    client_->server_ = server_;
    client_->share_ = share_;
}

Napi::Value ConnectWorker::Build(Napi::Env env) {
    return Napi::Boolean::New(env, true);
}

// ============================ Opendir ============================

void OpendirWorker::Run() {
    std::lock_guard<std::mutex> lock(client_->mtx_);
    if (!client_->ctx_) {
        SetError("未连接到共享");
        return;
    }

    struct smb2dir *dir =
        smb2_opendir(client_->ctx_, path_.c_str());
    if (!dir) {
        SetError("打开目录失败: " + std::string(smb2_get_error(client_->ctx_)));
        return;
    }

    struct smb2dirent *ent;
    while ((ent = smb2_readdir(client_->ctx_, dir)) != nullptr) {
        DirEntry e;
        e.name = ent->name;
        e.is_dir = (ent->st.smb2_type == SMB2_TYPE_DIRECTORY);
        e.size = ent->st.smb2_size;
        e.mtime = ent->st.smb2_mtime;
        e.ctime = ent->st.smb2_ctime;
        e.atime = ent->st.smb2_atime;
        result_.push_back(std::move(e));
    }

    smb2_closedir(client_->ctx_, dir);
}

Napi::Value OpendirWorker::Build(Napi::Env env) {
    auto arr = Napi::Array::New(env, result_.size());
    for (size_t i = 0; i < result_.size(); i++) {
        const auto &e = result_[i];
        auto obj = Napi::Object::New(env);
        obj.Set("name", e.name);
        obj.Set("type", e.is_dir ? "dir" : "file");
        obj.Set("size", Napi::BigInt::New(env, e.size));
        obj.Set("mtime", Napi::Number::New(env, (double)e.mtime));
        obj.Set("ctime", Napi::Number::New(env, (double)e.ctime));
        obj.Set("atime", Napi::Number::New(env, (double)e.atime));
        arr.Set(i, obj);
    }
    return arr;
}

// ============================ Stat ============================

void StatWorker::Run() {
    std::lock_guard<std::mutex> lock(client_->mtx_);
    if (!client_->ctx_) {
        SetError("未连接到共享");
        return;
    }

    struct smb2_stat_64 st;
    int rc = smb2_stat(client_->ctx_, path_.c_str(), &st);
    if (rc == 0) {
        result_.exists = true;
        result_.type = st.smb2_type;
        result_.size = st.smb2_size;
        result_.ino = st.smb2_ino;
        result_.nlink = st.smb2_nlink;
        result_.atime = st.smb2_atime;
        result_.mtime = st.smb2_mtime;
        result_.ctime = st.smb2_ctime;
        result_.btime = st.smb2_btime;
        return;
    }

    // stat 失败但目录能打开，说明是个目录（部分服务器不返回目录 stat）
    struct smb2dir *dir = smb2_opendir(client_->ctx_, path_.c_str());
    if (dir) {
        smb2_closedir(client_->ctx_, dir);
        result_.exists = true;
        result_.type = SMB2_TYPE_DIRECTORY;
        return;
    }

    result_.exists = false;
}

Napi::Value StatWorker::Build(Napi::Env env) {
    if (!result_.exists) {
        return env.Null();
    }
    auto obj = Napi::Object::New(env);
    obj.Set("type", result_.type == SMB2_TYPE_DIRECTORY ? "dir" : "file");
    obj.Set("size", Napi::BigInt::New(env, result_.size));
    obj.Set("ino", Napi::BigInt::New(env, result_.ino));
    obj.Set("nlink", Napi::Number::New(env, result_.nlink));
    obj.Set("atime", Napi::Number::New(env, (double)result_.atime));
    obj.Set("mtime", Napi::Number::New(env, (double)result_.mtime));
    obj.Set("ctime", Napi::Number::New(env, (double)result_.ctime));
    obj.Set("btime", Napi::Number::New(env, (double)result_.btime));
    return obj;
}

// ============================ Read ============================

void ReadWorker::Run() {
    std::lock_guard<std::mutex> lock(client_->mtx_);
    if (!client_->ctx_) {
        SetError("未连接到共享");
        return;
    }

    struct smb2fh *fh = smb2_open(client_->ctx_, path_.c_str(), O_RDONLY);
    if (!fh) {
        SetError("打开文件失败: " + std::string(smb2_get_error(client_->ctx_)));
        return;
    }

    if (offset_ > 0) {
        smb2_lseek(client_->ctx_, fh, (int64_t)offset_, SEEK_SET, nullptr);
    }

    result_.resize(length_);
    int rc = smb2_read(client_->ctx_, fh, result_.data(), length_);
    smb2_close(client_->ctx_, fh);

    if (rc < 0) {
        SetError("读取失败: " + std::string(smb2_get_error(client_->ctx_)));
        return;
    }
    result_.resize(rc);
}

Napi::Value ReadWorker::Build(Napi::Env env) {
    return Napi::Buffer<uint8_t>::Copy(env, result_.data(), result_.size());
}

// ============================ Write ============================

void WriteWorker::Run() {
    std::lock_guard<std::mutex> lock(client_->mtx_);
    if (!client_->ctx_) {
        SetError("未连接到共享");
        return;
    }

    int flags = O_WRONLY | O_CREAT;
    struct smb2fh *fh = smb2_open(client_->ctx_, path_.c_str(), flags);
    if (!fh) {
        SetError("打开文件失败: " + std::string(smb2_get_error(client_->ctx_)));
        return;
    }

    if (offset_ > 0) {
        smb2_lseek(client_->ctx_, fh, (int64_t)offset_, SEEK_SET, nullptr);
    }

    int rc = smb2_write(client_->ctx_, fh, data_.data(), (uint32_t)data_.size());
    smb2_close(client_->ctx_, fh);

    if (rc < 0) {
        SetError("写入失败: " + std::string(smb2_get_error(client_->ctx_)));
        return;
    }
    result_ = (uint32_t)rc;
}

Napi::Value WriteWorker::Build(Napi::Env env) {
    return Napi::Number::New(env, result_);
}

// ============================ Simple ============================

void SimpleWorker::Run() {
    std::lock_guard<std::mutex> lock(client_->mtx_);
    if (!client_->ctx_) {
        SetError("未连接到共享");
        return;
    }

    int rc = 0;
    switch (op_) {
        case UNLINK:
            rc = smb2_unlink(client_->ctx_, path_.c_str());
            break;
        case MKDIR:
            rc = smb2_mkdir(client_->ctx_, path_.c_str());
            break;
        case RMDIR:
            rc = smb2_rmdir(client_->ctx_, path_.c_str());
            break;
        case RENAME:
            rc = smb2_rename(client_->ctx_, path_.c_str(), path2_.c_str());
            break;
        case TRUNCATE:
            rc = smb2_truncate(client_->ctx_, path_.c_str(), 0);
            break;
    }

    if (rc < 0) {
        SetError("操作失败: " + std::string(smb2_get_error(client_->ctx_)));
        return;
    }
    result_ = rc;
}

Napi::Value SimpleWorker::Build(Napi::Env env) {
    return Napi::Boolean::New(env, true);
}

// ============================ 枚举共享 ============================

void ShareEnumWorker::Run() {
    struct smb2_context *ctx = smb2_init_context();
    if (!ctx) {
        SetError("smb2_init_context 失败：内存不足");
        return;
    }

    smb2_set_security_mode(ctx, security_);
    if (timeout_ > 0) {
        smb2_set_timeout(ctx, timeout_);
    }
    if (!domain_.empty()) {
        smb2_set_domain(ctx, domain_.c_str());
    }
    if (!user_.empty()) {
        smb2_set_user(ctx, user_.c_str());
    }
    if (!password_.empty()) {
        smb2_set_password(ctx, password_.c_str());
    }
    smb2_set_seal(ctx, 0);
    smb2_set_sign(ctx, 0);

    // 共享枚举只能通过 IPC$ 进行
    int rc = smb2_connect_share(ctx, server_.c_str(), "IPC$",
                                user_.empty() ? nullptr : user_.c_str());
    if (rc < 0) {
        std::string err = smb2_get_error(ctx);
        smb2_destroy_context(ctx);
        SetError("连接 IPC$ 失败: " + err);
        return;
    }

    struct smb2_share_enum_reply *rep =
        smb2_share_enum_sync(ctx, SMB2_SHARE_INFO_1);

    if (!rep) {
        std::string err = smb2_get_error(ctx);
        smb2_disconnect_share(ctx);
        smb2_destroy_context(ctx);
        SetError("枚举共享失败: " + err);
        return;
    }

    if (rep->level == SMB2_SHARE_INFO_1) {
        for (uint32_t i = 0; i < rep->entries_read; i++) {
            struct smb2_share_info_1 *s = &rep->share_info.info_1[i];
            if (!s->netname) {
                continue;
            }
            ShareEntry e;
            e.name = s->netname;
            e.remark = s->remark ? s->remark : "";
            // 低 2 位是共享类型，IPC 类型（IPC$）对用户无意义，标记出来由上层过滤
            e.is_ipc = ((s->type & 0x3) == SMB2_SHARE_TYPE_IPC);
            result_.push_back(std::move(e));
        }
    }

    smb2_free_data(ctx, rep);
    smb2_disconnect_share(ctx);
    smb2_destroy_context(ctx);
}

Napi::Value ShareEnumWorker::Build(Napi::Env env) {
    auto arr = Napi::Array::New(env, result_.size());
    for (size_t i = 0; i < result_.size(); i++) {
        const auto &e = result_[i];
        auto obj = Napi::Object::New(env);
        obj.Set("name", e.name);
        obj.Set("remark", e.remark);
        obj.Set("is_ipc", e.is_ipc);
        arr.Set(i, obj);
    }
    return arr;
}
