/**
 * 在安装时生成本机可用的 config.h。
 *
 * libsmb2 上游要求先跑 ./configure 才会有 config.h，仓库里只带了 apple/ 那份。
 * 这里按平台生成：
 *   - macOS / Linux 等 POSIX 平台：打开常见 POSIX 头文件的 HAVE_*_H
 *   - Windows(MSVC/MinGW)：不打开 POSIX 头（那些头不存在），
 *     libsmb2 在 lib/compat.h 里已备好 Winsock 兼容层
 *     （poll→WSAPoll、readv/writev→WSARecv/WSASend、errno→WSA* 等）
 */
const fs = require("fs");
const path = require("path");

const OUT_DIR = path.join(__dirname, "..", "c-libsmb2", "build");
const OUT = path.join(OUT_DIR, "config.h");

/** 所有平台（含 Windows）都有的 C 标准库头文件 */
const STD_HEADERS = [
    "stdint.h",
    "stdio.h",
    "stdlib.h",
    "string.h",
];

/** 只在类 Unix 系统上存在的头文件，Windows 一律不开 */
const POSIX_HEADERS = [
    "arpa/inet.h",
    "dlfcn.h",
    "errno.h",
    "fcntl.h",
    "gssapi/gssapi.h",
    "inttypes.h",
    "netdb.h",
    "netinet/in.h",
    "netinet/tcp.h",
    "poll.h",
    "strings.h",
    "sys/errno.h",
    "sys/fcntl.h",
    "sys/ioctl.h",
    "sys/poll.h",
    "sys/socket.h",
    "sys/stat.h",
    "sys/time.h",
    "sys/types.h",
    "sys/uio.h",
    "sys/unistd.h",
    "time.h",
    "unistd.h",
];

/** 头文件名整体大写、非字母数字转下划线：sys/time.h -> HAVE_SYS_TIME_H */
function define_header(h) {
    const macro = "HAVE_" + h.toUpperCase().replace(/[^A-Z0-9]/g, "_");
    return `#define ${macro} 1`;
}

function generate() {
    const is_win = process.platform === "win32";
    const is_mac = process.platform === "darwin";

    // Windows 走 compat.h 的 Winsock 兼容层，POSIX 头一个都不能开；
    // C 标准库头各平台都有，照常打开
    const headers = is_win ? STD_HEADERS : [...STD_HEADERS, ...POSIX_HEADERS];

    const lines = [
        "/* 由 scripts/gen_config.js 按当前平台生成，不要手工修改 */",
        "",
        "#define CONFIGURE_OPTION_TCP_LINGER 1",
        "#define HAVE_LINGER 1",
        // sockaddr 带 sa_len 是 BSD/macOS 特有的，Windows/Linux 都没有
        is_mac ? "#define HAVE_SOCKADDR_LEN 1" : "/* #undef HAVE_SOCKADDR_LEN */",
        "#define HAVE_SOCKADDR_STORAGE 1",
        "/* #undef HAVE_LIBKRB5 */",
        "/* #undef HAVE_LIBNSL */",
        "/* #undef HAVE_LIBSOCKET */",
        "/* #undef HAVE_SYS__IOVEC_H */",
        "#define LT_OBJDIR \".libs/\"",
        "#define PACKAGE \"libsmb2\"",
        "#define PACKAGE_BUGREPORT \"ronniesahlberg@gmail.com\"",
        "#define PACKAGE_NAME \"libsmb2\"",
        "#define PACKAGE_STRING \"libsmb2 4.0.0\"",
        "#define PACKAGE_TARNAME \"libsmb2\"",
        "#define PACKAGE_URL \"\"",
        "#define PACKAGE_VERSION \"4.0.0\"",
        "#define STDC_HEADERS 1",
        "#define VERSION \"4.0.0\"",
        "",
        ...headers.map(define_header),
        "",
    ];
    fs.mkdirSync(OUT_DIR, {recursive: true});
    fs.writeFileSync(OUT, lines.join("\n"), "utf8");
    console.log(`[node-libsmb2] 已生成 ${path.relative(process.cwd(), OUT)} (${process.platform}/${process.arch})`);
}

generate();
