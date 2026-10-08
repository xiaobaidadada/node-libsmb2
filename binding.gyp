{
  "targets": [
    {
      "target_name": "node_libsmb2",
      "sources": [
        "src/smb2_wrap.cpp",
        "src/workers.cpp",
        "<!@(node -p \"require('fs').readdirSync('c-libsmb2/lib').filter(f=>f.endsWith('.c')).map(f=>'c-libsmb2/lib/'+f).join(' ')\")"
      ],
      "include_dirs": [
        "<!@(node -p \"require('node-addon-api').include_dir\")",
        "c-libsmb2/include",
        "c-libsmb2/include/smb2",
        "c-libsmb2/lib",
        "c-libsmb2/build"
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
              "_U_=",
              "_CRT_SECURE_NO_WARNINGS",
              "WIN32_LEAN_AND_MEAN"
            ],
            "msvs_settings": {
              "VCCLCompilerTool": {
                "ExceptionHandling": 0,
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
