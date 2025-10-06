MinHook is not included in this archive to avoid license surprises.
The CMakeLists.txt uses FetchContent to download MinHook automatically from GitHub.
If you need an offline, fully self-contained archive, please clone MinHook into:
  third_party/MinHook

The required layout:
  third_party/MinHook/include/MinHook.h
  third_party/MinHook/lib/MinHook.lib

Or vendor the full MinHook source into third_party/MinHook so CMake can build it locally.
