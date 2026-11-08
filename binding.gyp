{
  "targets": [
    {
      "target_name": "node_libsmb2",
      "sources": [
        "src/smb2_wrap.cpp",
        "src/workers.cpp",
        "src/smb2_server.cpp",
        "<!@(node -p \"require('fs').readdirSync('c-libsmb2/lib').filter(f=>f.endsWith('.c')).map(f=>'c-libsmb2/lib/'+f).join(' ')\")",
        "<!@(node -p \"const fs=require('fs'),p=require('path');const d='c-libsmb2/libdcerpc';const out=[];(function walk(dir){for(const e of fs.readdirSync(dir,{withFileTypes:true})){const f=p.join(dir,e.name);if(e.isDirectory()){if(e.name!=='dcerpc'&&e.name!=='examples'&&e.name!=='tests'&&e.name!=='utils'&&e.name!=='dcerpcd'&&e.name!=='packaging')walk(f);}else if(e.name.endsWith('.c'))out.push(f);}})(d);out.join(' ')\")"
      ],
      "include_dirs": [
        "node_modules/node-addon-api",
        "c-libsmb2/include",
        "c-libsmb2/include/smb2",
        "c-libsmb2/lib",
        "c-libsmb2/build",
        "c-libsmb2/libdcerpc",
        "c-libsmb2/libdcerpc/include",
        "c-libsmb2/libdcerpc/srvsvc",
        "c-libsmb2/libdcerpc/lsa",
        "c-libsmb2/libdcerpc/winreg",
        "c-libsmb2/libdcerpc/wkssvc",
        "c-libsmb2/libdcerpc/samr",
        "c-libsmb2/libdcerpc/dssetup",
        "c-libsmb2/libdcerpc/netlogon",
        "c-libsmb2/libdcerpc/epm",
        "src/compat"
      ],
      "defines": [
        "NAPI_DISABLE_CPP_EXCEPTIONS",
        "HAVE_CONFIG_H"
      ],
      "conditions": [
        [
          "OS==\"win\"",
          {
            "defines": [
              "_WINDOWS",
              "_U_=",
              "_CRT_SECURE_NO_WARNINGS",
              "WIN32_LEAN_AND_MEAN"
            ],
            "libraries": [
              "-lws2_32.lib"
            ],
            "msvs_settings": {
              "VCCLCompilerTool": {
                "ExceptionHandling": 0,
                "AdditionalOptions": [
                  "/utf-8"
                ],
                "DisableSpecificWarnings": [
                  "4100",
                  "4127",
                  "4189",
                  "4244",
                  "4267",
                  "4996"
                ]
              }
            }
          }
        ],
        [
          "OS==\"mac\"",
          {
            "defines": [
              "_U_="
            ],
            "xcode_settings": {
              "CLANG_CXX_LANGUAGE_STANDARD": "c++17",
              "GCC_ENABLE_CPP_EXCEPTIONS": "YES",
              "MACOSX_DEPLOYMENT_TARGET": "11.0",
              "OTHER_CFLAGS": [
                "-Wno-everything"
              ],
              "OTHER_CPLUSPLUSFLAGS": [
                "-Wno-everything"
              ]
            }
          }
        ],
        [
          "OS==\"linux\"",
          {
            "defines": [
              "_GNU_SOURCE",
              "_U_="
            ],
            "cflags": [
              "-w"
            ],
            "cflags_cc": [
              "-std=c++17",
              "-fexceptions",
              "-w"
            ],
            "ldflags": [
              "-Wl,-z,nodelete"
            ]
          }
        ]
      ]
    }
  ]
}
