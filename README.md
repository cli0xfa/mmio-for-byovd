# mmio-for-byovd

一个 **header-only** 的物理内存映射辅助库（单文件 `mmio.hpp`）。提供「把物理内存映射后端包装为内核 VA 读写、页表翻译、可用于内核映射的 CR3 定位」的通用封装。

**一句话**：你提供 `FnMap`/`FnUnMap`（映射/取消映射物理页的回调），这个库帮你完成剩下的内核内存访问工作。

---

## 这个库有什么用

BYOVD（Bring Your Own Vulnerable Driver）场景下，你加载了一个有物理内存映射能力的驱动，但驱动通常只暴露最原始的 IOCTL——把某个物理页映射到用户态虚拟地址。在此之上你还需要：

- 定位 **ntoskrnl.exe** 基址
- 扫描物理内存找到一个**可翻译内核映像的 CR3**（页表基址）
- 用该 CR3 把**内核虚拟地址翻译为物理地址**（走页表遍历，支持 4/5 级分页、2 MB/1 GB 大页）
- 在翻译好的地址上**安全地读写内核内存**（自动处理跨页分段、SEH 容错）

这些是每个 BYOVD 工具都要重复写的样板代码，`mmio.hpp` 封装了访问逻辑，你只需实现两个回调：

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
    printf("Kernel-mapping CR3 = 0x%llx\n", mmio.kernel_cr3pa());

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
| `NoKernelCr3` | 物理扫描未找到可翻译内核映像的 CR3 |
| `MappingFailed` | 回调拒绝映射 |
| `TranslationFailed` | VA→PA 翻译失败 |
| `NoSeDebugPrivilege` | 无法启用 SeDebugPrivilege（Win11 24H2+） |
| `Cancelled` | 扫描被 progress 回调取消 |
| `InternalError` | 其他底层失败 |
| `InvalidArgument` | 零长度、空缓冲区、地址溢出或无效映射结果 |
| `NotInitialized` | 内核读写前未成功调用 `Initialize()` |
| `UnsupportedPagingMode` | CR3 与内核映像无法唯一确认 4/5 级模式 |
| `PhysicalRangesUnavailable` | 物理范围提供器失败或未返回范围 |
| `InvalidPhysicalRange` | 范围未对齐、计算溢出或超出 MAXPHYADDR |
| `AccessDenied` | Windows API 因权限或系统策略拒绝访问 |

### 核心方法

| 方法 | 说明 |
|---|---|
| `Initialize()` | 清空旧缓存并重新定位内核基址、扫描内核映射 CR3 |
| `VaToPa(va, cr3pa=0)` | 内核 VA → 物理地址翻译（默认用缓存的内核映射 CR3） |
| `VaToPaWithMode(va, cr3pa, mode)` | 显式指定分页模式翻译，用于模式已知的调用方和模拟测试 |
| `ReadKernelMemory(va, buf, size)` | 安全读内核内存（自动跨页分段） |
| `WriteKernelMemory(va, buf, size)` | 安全写内核内存（自动跨页分段） |
| `ReadKernelMemoryDetailed(...)` / `WriteKernelMemoryDetailed(...)` | 返回状态、可用的 OS 错误码和已完成的页段字节数 |
| `ReadPhysicalMemory(pa, buf, size)` | 直接读物理内存（单次最多跨一页边界） |
| `WritePhysicalMemory(pa, buf, size)` | 直接写物理内存 |
| `GetKernelBase()` | 通过 `EnumDeviceDrivers` 获取 NT 内核基址 |
| `FindKernelCr3(progress)` | 扫描物理内存定位可翻译内核映像的 CR3 |
| `kernel_base()` | 缓存的内核基址（`Initialize()` 后可用） |
| `kernel_cr3pa()` | 缓存的内核映射 CR3（`Initialize()` 后可用） |
| `last_status()` | 最近一次操作的状态 |
| `last_error()` | 最近一次 `GetLastError()` 值 |

`GetKernelBase()` 会尝试启用当前进程令牌中的 `SeDebugPrivilege`。Windows 11 24H2 及更新版本要求该权限可用；若令牌没有此权限，方法会返回 0 并设置 `NoSeDebugPrivilege`。

### 回调契约

- **FnMap**(pa, &outVa, size)：把物理页 `[pa, pa+size)` 映射到用户态虚拟地址；返回 `true` 表示映射有效，并要求 `*outVa` 非零且整个区间不溢出。size 常见取值 `0x1000`、`0x2000`、`0x200000`。回调内**不应抛异常**。
- **FnUnMap**(va)：释放 `FnMap` 返回的映射。`FnMap` 返回 `true` 就产生一次清理义务，即使地址无效也会恰好尝试调用一次（零地址会调用 `FnUnMap(0)`）；返回 `false` 不得遗留映射。

`FnUnMap` 返回类型为 `void`，因此无法把清理失败写入 `MmioStatus`；异常会被吞掉，清理按尽力而为处理。
- **FnGetPhysicalRanges**(outRanges)：可选第四个构造参数，返回实际物理地址区间；每项必须页对齐、非空且不溢出。
- 构造函数默认拥有并关闭传入的设备句柄。传入借用句柄时，将第四参数设为 `nullptr`、第五参数设为 `false`。
- `Mmio` 在本版本中是 move-only；复制构造和复制赋值已禁用，以免两个对象重复关闭同一句柄。需要转移对象时使用 `std::move`。
- `FnMap` 返回 `false` 时不得留下仍需释放的映射；返回 `true` 时必须交付非零地址，库会在所有退出路径调用一次 `FnUnMap`。
- 两个回调必须可重入（`VaToPa` 遍历中会反复调用），且不应抛异常。`FnUnMap` 的异常会被吞掉并按尽力而为处理。
- 可选的 `FnGetPhysicalRanges(out)` 应返回真实的、页对齐的物理区间。提供它后，扫描会只遍历这些区间并检查长度溢出。为兼容原有三参数构造函数，未提供时仍使用已安装容量估算的回退路径；该回退可能漏掉高地址 RAM。
- 内存 API 对零长度、空缓冲区和溢出的地址区间返回 `false` 与 `InvalidArgument`，不会调用映射回调。
- 多页内核读写按页逐段执行。若中途失败，先前完成的段不会回滚；原有 `bool` API 不报告进度，`Detailed` 版本会返回已完整完成的页段字节数。
- `Mmio` 对象不提供并发安全保证；调用方必须串行化共享实例上的操作及状态查询。

`FindKernelCr3()` 的精确扫描依赖 `FnGetPhysicalRanges`。旧式三参数构造保留容量估算回退，以维持现有源代码兼容；含内存空洞或重映射的机器应提供真实范围，避免漏扫。

CR3 扫描只确认候选页表能映射内核映像，不识别它是否属于 System 进程。旧 API 名 `FindSystemCr3()`、`system_cr3pa()` 和状态值 `NoSystemCr3` 保留为 deprecated 兼容别名；新代码请使用 `FindKernelCr3()`、`kernel_cr3pa()` 和 `NoKernelCr3`。

4 级和 5 级共享高地址区时，分页模式不会从地址本身猜测。CR3 扫描会分别验证两种页表模型，并且只在内核映像签名唯一匹配时缓存模式；两种模式均匹配则返回 `UnsupportedPagingMode`。直接调用 `VaToPa()` 前若尚未识别模式，应使用 `VaToPaWithMode()` 并传入明确模式。普通内核读写和三参数 `Detailed` 调用需要先成功初始化；五参数 `Detailed` 重载允许调用方直接提供非零 CR3 与已确认的分页模式。

---

## 集成到你的工程

1. 把 `mmio-for-byovd/` 加入 include 路径，只需包含 `mmio.hpp`
2. 链接 `psapi.lib`（已 `#pragma comment(lib, "psapi.lib")`，可用 `#define MMIO_NO_LIB_PRAGMA` 关闭）
3. 工程需 C++20+ 且 `/EHsc`（已为 SEH 兼容性准备，详见代码注释）

```bat
cmake -S . -B build -A x64 -DMMIO_BUILD_TESTS=ON
cmake --build build --config Release
ctest --test-dir build -C Release --output-on-failure
```

`integration/winio/` contains a separate, opt-in Windows driver harness and the WinIo binary resource. It is excluded from CMake and CI; running that harness installs a kernel driver service.

---

## 许可

MIT License。仅供合法安全研究、漏洞分析、受控环境调试使用。使用者须自行确保遵守所在地法律法规。
