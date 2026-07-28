# mmio-for-byovd

一个 **header-only** 的物理内存映射辅助库（仅 `mmio.hpp`）。提供「把脆弱驱动的物理内存映射能力包装为内核 VA 读写、页表翻译、System CR3 定位」的通用封装。

**一句话**：你提供 `FnMap`/`FnUnMap`（映射/取消映射物理页的回调），这个库帮你完成剩下的内核内存访问工作。

---

## 这个库有什么用

BYOVD（Bring Your Own Vulnerable Driver）场景下，你加载了一个有物理内存映射能力的驱动，但驱动通常只暴露最原始的 IOCTL——把某个物理页映射到用户态虚拟地址。在此之上你还需要：

- 定位 **ntoskrnl.exe** 基址
- 扫描物理内存找到 **System 进程的 CR3**（页表基址）
- 用该 CR3 把**内核虚拟地址翻译为物理地址**（走页表遍历，支持 4/5 级分页、2 MB/1 GB 大页）
- 在翻译好的地址上**安全地读写内核内存**（自动处理跨页分段、SEH 容错）

这些是每个 BYOVD 工具都要重复写的样板代码，`mmio.hpp` 把它们打包成一个头文件，你只需实现两个回调：

```cpp
FnMap  = std::function<bool(uint64_t pa, uintptr_t* outVa, size_t size)>
FnUnMap = std::function<void(uintptr_t va)>
```

---

## 平台要求

- **仅 x86-64** Windows 10 / 11（及 Server 版本）
- MSVC（C++20+），`/EHsc`
- 依赖：`windows.h`、`psapi.h`、`intrin.h`，无第三方库
- 需要**管理员权限** + 一个能映射物理内存的驱动

---

## 快速开始

```cpp
#include "mmio.hpp"

// 你自己实现的物理页映射回调
static bool MyMap(uint64_t pa, uintptr_t* outVa, size_t size)
{
    return Driver_MapPhysical(pa, size, outVa);
}
static void MyUnmap(uintptr_t va)
{
    Driver_UnmapPhysical(va);
}

int main()
{
    HANDLE hDriver = CreateFileW(L"\\\\.\\YourDriver", ...);

    Mmio mmio(hDriver, MyMap, MyUnmap);

    if (!mmio.Initialize()) {
        printf("init failed: status=%d  err=%lu\n",
               (int)mmio.last_status(), mmio.last_error());
        return 1;
    }

    printf("ntoskrnl  = 0x%llx\n", mmio.kernel_base());
    printf("System CR3 = 0x%llx\n", mmio.system_cr3pa());

    uint16_t mz = 0;
    mmio.ReadKernelMemory(mmio.kernel_base(), &mz, 2);
    printf("MZ = %s\n", mz == 0x5A4D ? "OK" : "FAIL");

    return 0;
}
```

---

## API

### 状态枚举

| 值 | 含义 |
|---|---|
| `Ok` | 成功 |
| `BadCallbacks` | `FnMap`/`FnUnMap` 为空 |
| `NoKernelBase` | 未能取得内核基址 |
| `NoSystemCr3` | 物理扫描未找到 System CR3 |
| `MappingFailed` | 回调拒绝映射 |
| `TranslationFailed` | VA→PA 翻译失败 |
| `NoSeDebugPrivilege` | 无法启用 SeDebugPrivilege（Win11 24H2+） |
| `Cancelled` | 扫描被 progress 回调取消 |
| `InternalError` | 其他底层失败 |

### 核心方法

| 方法 | 说明 |
|---|---|
| `Initialize()` | 一次性初始化：定位内核基址 + 扫描 System CR3 |
| `VaToPa(va, cr3pa=0)` | 内核 VA → 物理地址翻译（默认用缓存的 System CR3） |
| `ReadKernelMemory(va, buf, size)` | 安全读内核内存（自动跨页分段） |
| `WriteKernelMemory(va, buf, size)` | 安全写内核内存（自动跨页分段） |
| `ReadPhysicalMemory(pa, buf, size)` | 直接读物理内存（单次最多跨一页边界） |
| `WritePhysicalMemory(pa, buf, size)` | 直接写物理内存 |
| `GetKernelBase()` | 通过 `EnumDeviceDrivers` 获取 NT 内核基址 |
| `FindSystemCr3(progress)` | 扫描物理内存定位 System CR3 |
| `kernel_base()` | 缓存的内核基址（`Initialize()` 后可用） |
| `system_cr3pa()` | 缓存的 System CR3（`Initialize()` 后可用） |
| `last_status()` | 最近一次操作的状态 |
| `last_error()` | 最近一次 `GetLastError()` 值 |

### 回调契约

- **FnMap**(pa, &outVa, size)：把物理页 `[pa, pa+size)` 映射到用户态虚拟地址，成功置 `*outVa` 返回 `true`。size 常见取值 `0x1000`、`0x2000`、`0x200000`。回调内**不应抛异常**。
- **FnUnMap**(va)：释放 `FnMap` 返回的映射。
- 回调需要可重入（`VaToPa` 遍历中会反复调用）。

---

## 集成到你的工程

1. 把 `mmio.hpp` 加入 include 路径
2. 链接 `psapi.lib`（已 `#pragma comment(lib, "psapi.lib")`，可用 `#define MMIO_NO_LIB_PRAGMA` 关闭）
3. 工程需 C++20+ 且 `/EHsc`（已为 SEH 兼容性准备，详见代码注释）

```bat
msbuild mmio-for-byovd.slnx /p:Configuration=Release /p:Platform=x64
```

---

## 许可

MIT License。仅供合法安全研究、漏洞分析、受控环境调试使用。使用者须自行确保遵守所在地法律法规。
