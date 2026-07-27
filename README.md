# mmio-for-byovd

一个 **header-only** 的物理内存映射辅助库（仅头文件 `mmio.hpp`），用于在指定一个「把物理页映射到当前进程虚拟地址空间」的回调对（`FnMap` / `FnUnMap`）之后，完成 NT 内核镜像基址定位、System CR3 值扫描、内核虚拟地址到物理地址的页表遍历，以及跨页安全的内核内存读写。

库适用于 **BYOVD（Bring Your Own Vulnerable Driver）** 类工具链：调用方自行负责加载一个具备物理内存映射能力的（通常是已签名但有缺陷的）内核驱动，并把该驱动的「map 一个物理页」接口实现为 `FnMap` / `FnUnMap` 两个回调传给库；本库仅在此基础上提供页表解析、内核定位与读写封装。

> **使用前提**：管理员权限 + 一个可正常工作的物理内存映射回调。本库本身不含驱动加载逻辑，不提供任何镜像或漏洞利用，仅做内存解析封装。
>
> **用途限定**：仅供合法安全研究、漏洞分析、固件/驱动调试等受控环境使用。请勿用于未授权目标。

---

## 平台要求

- 仅支持 **x86-64** 的 Windows 10 / 11（及对应 Server 版本）。库内部所有 VA / PA 推导按 64 位进行，在 32 位下不可用。
- 编译器：MSVC（项目 `mmio-for-byovd.vcxproj` 使用 v145 工具集、C++20 / `stdcpplatest`）。
- SDK：`windows.h`、`psapi.h`（链接 `psapi.lib`）、`intrin.h`（`__cpuidex`），无第三方依赖。
- 已验证配置：`Debug|x64`、`Release|x64`。Win32 配置在工程文件中仅作为兼容项保留，库本身在 32 位下不具备可用性。

---

## 文件结构

```
mmio-for-byovd/
├── README.md                 本文件
├── mmio-for-byovd.slnx       Visual Studio 解决方案
└── mmio-for-byovd/
    ├── mmio.hpp              唯一头文件，包含全部实现
    └── mmio-for-byovd.vcxproj  样例工程（App 类型，无 main，仅用于承载本头）
```

`mmio.hpp` 是唯一对外暴露的接口来源；整个库为 inline 实现，直接 `#include "mmio.hpp"` 即可使用，无需单独编译产物。

---

## 快速开始

```cpp
#include "mmio.hpp"

// 例：用一个已加载的脆弱驱动的接口实现 map/unmap 回调
static bool MyMap(uint64_t pa, uintptr_t* outVa, size_t size)
{
    // 调用你自己的驱动 IOCTL：把物理页 [pa, pa+size) 映射进本进程
    // 成功时把映射基址写入 *outVa 并返回 true
    return Driver_MapPhysical(pa, size, outVa);
}
static void MyUnmap(uintptr_t va)
{
    Driver_UnmapPhysical(va);
}

int main()
{
    HANDLE hDriver = CreateFileW(L"\\\\.\\YourDriver", GENERIC_READ | GENERIC_WRITE,
                                0, nullptr, OPEN_EXISTING, 0, nullptr);

    Mmio mmio(hDriver, MyMap, MyUnmap);

    if (!mmio.Initialize()) {
        printf("init failed: status=%d  GetLastError=%lu\n",
               (int)mmio.last_status(), mmio.last_error());
        return 1;
    }

    uint64_t kbase = mmio.kernel_base();
    printf("ntoskrnl base = 0x%llx, System CR3 = 0x%llx\n",
           (unsigned long long)kbase, (unsigned long long)mmio.system_cr3pa());

    // 读 2 字节校验 "MZ"
    uint16_t mz = 0;
    if (mmio.ReadKernelMemory(kbase, &mz, sizeof(mz)))
        printf("kernel magic = 0x%04X (MZ=%u)\n", mz, mz == 0x5A4D);

    // 任意跨页读取由库自动分段
    uint8_t buf[0x10];
    mmio.ReadKernelMemory(kbase + 0x1000 - 4, buf, sizeof(buf));

    return 0;
}
```

> 关于回调实现的更严格契约见下文「回调契约」一节。

---

## API 参考

### 类型别名

```cpp
using FnMap     = std::function<bool(uint64_t pa, uintptr_t* outVa, size_t size)>;
using FnUnMap   = std::function<void(uintptr_t va)>;
using FnProgress = std::function<bool(uint64_t scannedPa)>;
```

| 类型 | 含义 |
|---|---|
| `FnMap` | 把物理地址 `pa` 起 `size` 字节映射到本进程，成功时写入 `*outVa` 并返回 `true` |
| `FnUnMap` | 释放 `FnMap` 返回的 `va`；无返回值 |
| `FnProgress` | `FindSystemCr3` 扫描进度/取消回调；收到当前扫描物理地址，返回 `false` 取消扫描 |

### 状态枚举

```cpp
enum class MmioStatus {
    Ok,               // 成功
    BadCallbacks,     // 传入的 FnMap / FnUnMap 为空 std::function
    NoKernelBase,     // EnumDeviceDrivers 未能取得内核镜像基址
    NoSystemCr3,      // 物理扫描未找到 System CR3
    MappingFailed,    // FnMap 拒绝/未能产生可用映射
    TranslationFailed,// VaToPa 翻译失败（非规范地址 / PTE 不在场 / PTE 读取失败）
    InternalError,    // 其余意外低层失败（如经 SEH 捕获的访问违例 / 非法参数）
};
```

### `class Mmio`

```cpp
Mmio(HANDLE h, FnMap fm, FnUnMap fu);
```
- 构造时缓存设备句柄与回调。`h` 仅在析构时 `CloseHandle`，留作子类/消费方后续做 IOCTL 直连用；传 `nullptr` 表示不持有句柄。
- **不可拷贝**，**可移动**（move 后源对象的句柄置 `INVALID_HANDLE_VALUE`、缓存清零，避免双重关闭）。

#### 初始化与诊断

| 方法 | 说明 |
|---|---|
| `[[nodiscard]] bool Initialize()` | 一次性初始化：取内核基址 + 扫描 System CR3。成功后 `kernel_base()` / `system_cr3pa()` 可用。任何失败返回 `false`，配合 `last_status()` / `last_error()` 排障 |
| `MmioStatus last_status() const` | **最近一次** `Initialize` / `Read*` / `Write*` / `VaToPa` / `GetKernelBase` / `FindSystemCr3` 的结果分类。任一公开操作在入口将状态置 `Ok`，成功保持 `Ok`，失败写入对应分类（`BadCallbacks` / `NoKernelBase` / `NoSystemCr3` / `MappingFailed` / `TranslationFailed` / `NoSeDebugPrivilege` / `InternalError`） |
| `DWORD last_error() const` | 最近的底层 `GetLastError()` 值（例如 `EnumDeviceDrivers` 失败时记录）；纯翻译/映射类失败不设该值 |

#### 物理内存访问

| 方法 | 说明 |
|---|---|
| `[[nodiscard]] bool ReadPhysicalMemory(uint64_t pa, void* buf, size_t size)` | 读物理地址 `pa` 起 `size` 字节到 `buf`。**约束：`pageOffset(pa&0xFFF) + size ≤ 0x2000`**（单次映射最多跨一页边界）。跨页请用 `ReadKernelMemory` |
| `[[nodiscard]] bool WritePhysicalMemory(uint64_t pa, const void* buf, size_t size)` | 对应写接口，约束同上 |

入口校验：
- `size == 0` → 直接返回 `true`；
- `buf == nullptr`（且 `size>0`）→ 返回 `false` 并置 `last_status_ = InternalError`；
- 单段 `pageOffset+size > 0x2000` → 返回 `false`（交由上层 `Read/WriteKernelMemory` 分段）。

#### 内核内存访问（自动按 4 KB 分段）

| 方法 | 说明 |
|---|---|
| `[[nodiscard]] bool ReadKernelMemory(uint64_t va, void* buf, size_t size)` | 读内核虚拟地址 `va` 起 `size` 字节。内部按页边界分段，每段单独 `VaToPa` 翻译并调用 `ReadPhysicalMemory`；任意段失败整体返回 `false` |
| `[[nodiscard]] bool WriteKernelMemory(uint64_t va, const void* buf, size_t size)` | 对应写接口 |

可安全处理：跨页、跨多个 4 KB 边界的大块读写。注意 `buf` 可写性由调用方保证。

#### 地址翻译与定位

| 方法 | 说明 |
|---|---|
| `uint64_t VaToPa(uint64_t va, uint64_t cr3pa = 0)` | 把内核 VA 翻译为 PA。`cr3pa==0` 时使用 `Initialize()` 缓存的系统 CR3。返回 `0` 表示失败（非规范地址 / PTE not-present / 映射读失败） |
| `uint64_t GetKernelBase()` | 通过 `EnumDeviceDrivers` 取 NT 内核镜像基址（驱动枚举中的第一项），含最多 3 次 `ERROR_INSUFFICIENT_BUFFER` 重试。自 Windows 11 24H2 起，该 API 要求 `SeDebugPrivilege`；库在 `Initialize()` 入口会自动尝试启用 |
| `uint64_t FindSystemCr3(FnProgress progress = nullptr)` | 扫描物理内存定位 System 进程 CR3。`progress` 可选取消回调，每扫一个 2 MB 窗口调用一次 |
| `uint64_t kernel_base()  const` | 缓存的内核基址（`Initialize()` 后可用） |
| `uint64_t system_cr3pa() const` | 缓存的 System CR3 物理地址（`Initialize()` 后可用） |

---

## 内部行为说明

### 分页模式判定（LA57）
- **不再依赖 CPUID 能力位 `CPUID(7,0):ECX[16]`**。该位只表明 CPU 支持 5 级分页；现代 Intel（Alder Lake+）/ AMD（Zen4+）在 BIOS/OS 仍用 4 级分页时该位常被置位，旧实现据此会让 `VaToPa` 多走一层 PML5 而全程错乱。
- 改用**运行时内核 VA 规范位姿**判定：
  - 4 级规范：`bits[63:48] == 0xFFFF`（符号扩展自 bit 47），起始内核半区 `0xFFFF8000_00000000`
  - 5 级规范：`bits[63:56] == 0xFF` 且 `bits[55:48]` 非全 1（符号扩展自 bit 56），起始 `0xFF000000_00000000`
- 因此在「CPU 支持 LA57 但 OS 用 4 级」的常见机器上 `Initialize()` 不再必败。

### 大页翻译
- 大页叶节点（PTE 的 PS 位置位）只在 **PDPT（1 GB）** 与 **PD（2 MB）** 层出现，对应遍历索引 `i==2` 与 `i==3`。
- **PML4（i==1）层的 PS 位为保留位**，不再误判为 1 GB 叶节点；置位时按页目录指针继续向下遍历（标准要求忽略该保留位）。
- 旧实现把 `i==1` 当 1 GB、`i==2` 当 2 MB、漏掉 `i==3` 的 2 MB 大页，导致在用 2 MB 大页映射 `.text/.data` 的真实 `ntoskrnl` 上 `VaToPa` 返回错误 PA，进而 `FindSystemCr3` 校验 "MZ" 永远失败 → `Initialize()` 必返 `false`。此问题已修复。

### 物理地址位宽
- `PADDR_MASK` 由 `CPUID 0x80000008:EAX[7:0]`（MAXPHYADDR，通常 48 / 52）运行时计算并缓存，不再硬编码 52 位；规避了服务器 57 位 PA 等场景的截断风险。

### CR3 扫描
- 以 2 MB 为扫描窗口；若 `FnMap` 拒绝 2 MB 映射，自动**回退到逐 4 KB** 粒度继续命中候选（旧实现整段 `continue` 直接跳过，对仅支持页粒度的回调会漏掉真实 CR3）。
- 启发式：候选页须满足 `PML4[511].P=1` 且能经此 CR3 把 `kernelbase_` 翻译出有效 PA；再读其首字节校验 "MZ"。**新增二次校验**：解析 `e_lfanew` 并经同一 CR3 翻译 PE 头偏移，验证 `IMAGE_NT_HEADERS.Signature == "PE\0\0"`（`0x00004550`），显著降低假阳率。
- 全部裸内存访问收敛到唯一 `SehCopy` 叶子函数，使用 `__try/__except` 兜底；映射由 RAII 守卫管理，异常路径不泄漏。

### 异常 / 资源安全
- 全库仅 `SehCopy` 一个函数使用 `__try/__except`，其帧内无任何带析构的 C++ 对象——这是 MSVC `/EHsc` 下合法混用 SEH 的硬性要求（否则触发 `C2712`）。所有上层封装经 `ScopedMap` 守卫映射，再委托 `SehCopy` 完成原始 `memcpy`，折中兼顾 SEH 容错与 C++ 异常安全。
- 空 `std::function` 回调在入口即被 `CallbacksValid()` 拒绝并返回 `BadCallbacks`，避免 `std::bad_function_call` 在 `/EHsc` 下终止进程。

---

## 回调契约（`FnMap` / `FnUnMap`）

由调用方提供，必须满足：

- `FnMap(pa, &outVa, size)`：
  - `size` 是「期望映射大小」，常见取值 `0x1000`（单页）、`0x2000`（跨一页边界）、`0x200000`（2 MB 扫描窗）。
  - 成功后 `*outVa` 必须为可读写的用户态虚拟地址，覆盖 `[outVa, outVa + size)`。
  - 失败返回 `false`（合法；`FindSystemCr3` 会在 2 MB 失败时回退到 4 KB）。
  - 回调内部**不应抛 C++ 异常**；若抛出，`ScopedMap` 仍会保证 unmapped，但调用方需自行保证不依赖异常机制。
- `FnUnMap(va)`：
  - 必须能释放 `FnMap` 返回的任意 `va`，且可被重复场景中确保一一对应。
- 可重入性：`VaToPa` 在遍历中会反复调用 `FnMap` / `FnUnMap`（每次读一个 PTE 映射一次页），实现需无状态或自带锁。

---

## 已知限制

- **Windows 11 24H2+**：`EnumDeviceDrivers` 需 `SeDebugPrivilege` 才能返回有效内核基址。`Initialize()` 会自动尝试启用该特权（最佳努力），失败时 `last_status()` 可能为 `NoKernelBase` 且 `last_error()` 为 `ERROR_PRIVILEGE_NOT_HELD`（1314）。
- **仅 x64**：32 位下不可用（工程含 Win32 配置仅为 IDE 兼容）。
- **非线程安全**：`last_status_` / `last_error_` 以及缓存 `kernelbase_` / `system_cr3pa_` 在读路径被并发访问，无内部同步。同一 `Mmio` 实例的多线程并发调用需调用方加锁；跨实例无共享状态。`PaddrMask()` 的静态缓存是线程安全的（函数局部 static 初始化）。
- `Read/WritePhysicalMemory` 单次最多覆盖一页边界（`pageOffset+size ≤ 0x2000`）；更大或跨多页请求须经 `Read/WriteKernelMemory`。
- `VaToPa` / `Read*` / `Write*` 未标记 `const` / `noexcept`：它们确有可观察副作用（写 `last_status_` / `last_error_`），且回调路径可能抛。如需 const 对象调用，可日后将诊断成员置 `mutable` 再标 const——本次保留原始语义。
- `hDevice_` 仅在析构时 `CloseHandle`，当前无方法引用，作为「reserved for direct IOCTL usage」保留并注释。
- 未纳入工程级单测：消费方需按 [验证场景](#验证场景) 自行验证。
- **安全敏感**：依赖调用方提供物理内存映射能力，使用须遵守所在司法辖区的相关法律与许可授权；作者不承担滥用责任。

---

## 验证场景

建议消费方在具备真实 `FnMap` / `FnUnMap` 回调与管理员权限的环境下验证：

1. **4 级 + 2 MB 大页内核**：`Initialize()` 成功；`ReadKernelMemory(kernelbase_, 2)` 读到 `"MZ"`；读 2 MB 大页内部偏移 64 字节与基址处读连续字节拼接一致。
2. **LA57-capable 但 OS 4 级**（Alder Lake+ / Zen4+ 默认配置）：` VaToPa` 不误走 PML5，`Initialize()` 成功（修复前在此类机器上必败）。
3. **跨页读**：`ReadKernelMemory(va=页末-4, size=12)` 返回正确拼接字节（修复前错误）。
4. **空回调**：传入空 `std::function` → `Initialize()` 返回 `false` 且 `last_status()==BadCallbacks`，**不**终止进程。亦需验证直接调用 `ReadKernelMemory` / `WriteKernelMemory` / `VaToPa(va, cr3pa!=0)` 时返回 `false` / `0` 并置 `BadCallbacks`，而非 `std::bad_function_call` 崩溃（此前这些入口未校验）。
5. **映射异常模拟**：注入会在 map 后中间抛 C++ 异常的 `FnMap`，确认无映射句柄泄漏。特别在 `FindSystemCr3` 内部循环时长逆抛——验证 2 MB chunk 映射经 `chunkGuard`（RAII）被释放，而不会被栈展开跳过。
6. **CR3 扫描性能**：64 GB 机器下 `FindSystemCr3` 在合理上限内完成；`progress` 返回 `false` 可中途取消；`FnMap` 仅支持 4 KB 粒度时仍能命中（粒度回退路径）。直接调用未命中时 `last_status()==NoSystemCr3`。
7. **错误诊断**：失败路径下 `last_status()` / `last_error()` 能区分「无内核基址 / 无 CR3 / 回调缺失 / 映射拒绝 / 翻译失败 / SEH 违例」。并验证「最近一次调用」契约：一次失败后再调用成功的 `ReadKernelMemory`，`last_status()` 被重置为 `Ok`（此前会残留旧失败值）。
8. **`GetKernelBase` 回归**：`EnumDeviceDrivers` 传 `cb=0` 返回 `FALSE`+`ERROR_INSUFFICIENT_BUFFER` 是正常查询路径，`GetKernelBase()` 不再误判为重试而恒返 `0`；`Initialize()` 能实际取得 `kernel_base()`（此前该函数实现死锁于重试，使 `Initialize()` 在所有机器上必然 `NoKernelBase`）。

---

## 构建

```bat
:: 需 Visual Studio 2022（含 v145 工具集）或同版本 Build Tools
msbuild mmio-for-byovd.slnx /p:Configuration=Release /p:Platform=x64
```

若仅需将本库作为头文件集成到自己的工程：

1. 把 `mmio.hpp` 加入消费工程的 `#include` 路径；
2. 链接 `psapi.lib`（项目已 `#pragma comment(lib, "psapi.lib")`；如需关闭该隐式链接，在包含本头前 `#define MMIO_NO_LIB_PRAGMA`）；
3. 确保工程启用 C++20 或更高（`stdcpplatest` 已在样例工程验证）。

`/W3` 下应无新增警告。SEH 与 C++ 在 `/EHsc` 下的兼容性已在 `SehCopy` 的设计上提前规避（详见 [内部行为说明](#内部行为说明)）。

---

## 许可与免责

本代码按「原样」提供，不附带任何明示或默示担保。仅供合法安全研究、漏洞分析、受控环境调试使用。使用者须自行确保遵守所在地区法律法规及目标系统授权范围；作者不对任何滥用后果承担责任。