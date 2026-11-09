/*
 * Windows 没有 <unistd.h>，但 libdcerpc 的部分 .c 会无条件包含它。
 * 通过 binding.gyp 把 src/compat 加入 include 路径，这里提供一份空实现；
 * 真正需要的 POSIX 名字在 src/compat/win_net.h 里用 CRT 版本补齐。
 */
#ifndef FILECAT_UNISTD_COMPAT_H
#define FILECAT_UNISTD_H

#if defined(_WIN32)
#include <io.h>
#include <process.h>
#endif

#endif
