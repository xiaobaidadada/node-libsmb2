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
        // 当前不做用户校验，匿名放行
        return 0;
    }

    static int create_cmd(struct smb2_server *srvr, struct smb2_context *smb2,
                          struct smb2_create_request *req,
                          struct smb2_create_reply *rep) {
        Smb2Req r;
        r.op = "create";
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

    static int tree_connect_cmd(struct smb2_server *srvr, struct smb2_context *smb2,
                                struct smb2_tree_connect_request *req,
                                struct smb2_tree_connect_reply *rep) {
        // 只有一个共享，任何共享名都映射到 root_path
        rep->share_type = SMB2_SHARE_TYPE_DISK;
        rep->share_flags = 0;
        rep->capabilities = 0;
        rep->maximal_access = 0x001f01ff;  // 全权限
        return 0;
    }

    static int tree_disconnect_cmd(struct smb2_server *srvr, struct smb2_context *smb2,
                                   const uint32_t tree_id) {
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
        uint64_t h = file_id_to_handle(req->file_id);
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
    nullptr,                              // ioctl_cmd (0x0b)
    nullptr,                              // query_volume_info
    nullptr,                              // lock_cmd
    nullptr,                              // ioctl_cmd
    nullptr,                              // cancel_cmd
    nullptr,                              // echo_cmd
    ServerHandlers::query_directory_cmd,  // query_directory_cmd
    nullptr,                              // change_notify_cmd
    ServerHandlers::query_info_cmd,       // query_info_cmd
    nullptr,                              // set_info_cmd
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

    root_path_.clear();
    if (opts.Has("root") && opts.Get("root").IsString()) {
        root_path_ = opts.Get("root").As<Napi::String>().Utf8Value();
    }
    if (root_path_.empty()) {
        throw Napi::TypeError::New(env, "root 不能为空");
    }

    readonly_ = opts.Has("readonly") && opts.Get("readonly").IsBoolean()
                    ? opts.Get("readonly").As<Napi::Boolean>().Value()
                    : false;

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

    memset(&server_, 0, sizeof(server_));
    server_.handlers = &g_handlers;
    server_.port = port;
    // 签名关闭：开启后服务端在 NTLM 会话密钥就绪前就会给部分 reply 签名，
    // 客户端校验失败并断开。匿名/无签名模式足以本地文件服务使用。
    server_.signing_enabled = 1;
    server_.allow_anonymous = 1;
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
