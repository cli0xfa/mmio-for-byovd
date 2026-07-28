# WinIo64.sys 逆向分析报告

## 基本信息

| 项目 | 内容 |
|------|------|
| **文件名** | WinIo64.sys |
| **PDB 路径** | `D:\Users\heavenluo\Documents\Visual Studio 2017\Projects\WinIo\x64\Release\WinIo64.pdb` |
| **架构** | x64 |
| **驱动类型** | 内核模式驱动 (Kernel-mode Driver) |
| **功能** | 用户态直接访问 I/O 端口和物理内存 |

---

## 设备名与符号链接

| 类型 | 名称 |
|------|------|
| **设备名** | `\Device\WinIo` |
| **符号链接** | `\DosDevices\WinIo` |
| **用户态路径** | `\\.\WinIo` |

符号链接由 `DriverEntry` → `sub_140001000` 在驱动加载时创建，驱动卸载时由 `sub_1400014D4` 删除。

---

## 驱动入口与分发函数

### DriverEntry (`0x140005000`)

调用 `sub_140001000(DriverObject)` 完成初始化：
- 调用 `IoCreateDevice` 创建设备 `\Device\WinIo`，设备类型 `0x8010`
- 注册分发函数：
  - `IRP_MJ_CREATE` (0) → `sub_1400012F8`
  - `IRP_MJ_CLOSE` (2) → `sub_1400012F8`
  - `IRP_MJ_DEVICE_CONTROL` (14) → `sub_1400012F8`
- 注册卸载函数 `sub_1400014D4`
- 调用 `IoCreateSymbolicLink` 创建符号链接 `\DosDevices\WinIo`

### 卸载函数 (`0x1400014D4`)

删除符号链接 `\DosDevices\WinIo` 后删除设备。

---

## IOCTL 码

所有 IOCTL 码均使用 `METHOD_BUFFERED` + `FILE_ANY_ACCESS`，设备类型为 `0x8010`。

| IOCTL 码 | 函数码 | 功能 | 输入/输出 |
|----------|--------|------|-----------|
| `0x80102040` | 0x810 | 映射物理内存 | 双向缓冲区 |
| `0x80102044` | 0x811 | 取消映射物理内存 | 输入缓冲区 |
| `0x80102050` | 0x814 | 读取 I/O 端口 | 输入缓冲区 → 输出 DWORD |
| `0x80102054` | 0x815 | 写入 I/O 端口 | 仅输入缓冲区 |

### IOCTL 码解析

```
CTL_CODE(DeviceType, Function, Method, Access)

0x80102040: DeviceType=0x8010, Function=0x810, Method=0 (METHOD_BUFFERED), Access=0 (FILE_ANY_ACCESS)
0x80102044: DeviceType=0x8010, Function=0x811, Method=0 (METHOD_BUFFERED), Access=0 (FILE_ANY_ACCESS)
0x80102050: DeviceType=0x8010, Function=0x814, Method=0 (METHOD_BUFFERED), Access=0 (FILE_ANY_ACCESS)
0x80102054: DeviceType=0x8010, Function=0x815, Method=0 (METHOD_BUFFERED), Access=0 (FILE_ANY_ACCESS)
```

---

## 结构体定义

### 物理内存映射结构体 (`WINIO_MAP_BUFFER`)

用于 IOCTL `0x80102040` (Map) 和 `0x80102044` (Unmap)，缓冲区大小 **0x28 字节**。

```c
typedef struct _WINIO_MAP_BUFFER {
    ULONG_PTR        CommitSize;      // +0x00: 映射大小 (字节数)
    PHYSICAL_ADDRESS BusAddress;      // +0x08: 物理地址 (PHYSICAL_ADDRESS.QuadPart)
    HANDLE           SectionHandle;   // +0x10: 段句柄 (Map 输出 / Unmap 输入)
    PVOID            BaseAddress;     // +0x18: 映射后的虚拟地址 (Map 输出 / Unmap 输入)
    PVOID            SectionObject;   // +0x20: 段对象指针 (Map 输出 / Unmap 输入)
} WINIO_MAP_BUFFER;
```

**Map 流程 (`0x80102040`)**:
1. 用户填充 `CommitSize` 和 `BusAddress`，`SectionHandle`/`BaseAddress`/`SectionObject` 置零
2. 驱动通过 `\Device\PhysicalMemory` → `ZwOpenSection` → `HalTranslateBusAddress` → `ZwMapViewOfSection` 映射物理内存
3. 输出缓冲区中的 `SectionHandle`、`BaseAddress`、`SectionObject` 被填入映射信息

**Unmap 流程 (`0x80102044`)**:
1. 用户传入 Map 时返回的完整结构体
2. 驱动调用 `ZwUnmapViewOfSection` → `ObfDereferenceObject` → `ZwClose` 释放映射

**内部实现 (`sub_1400010C0`)**:
1. 调用 `ZwOpenSection` 打开 `\Device\PhysicalMemory` (访问掩码 `0xF001F`)
2. 调用 `ObReferenceObjectByHandle` 获取段对象指针
3. 调用 `HalTranslateBusAddress(Isa, ...)` 将总线地址转换为系统物理地址
4. 调用 `ZwMapViewOfSection` 将物理地址映射到内核虚拟地址空间
5. 若首次映射失败 (`STATUS_CONFLICTING_ADDRESSES` / `0xC0000018`)，使用 `PAGE_NOACCESS` 保护重试

---

### I/O 端口读写结构体 (`WINIO_PORT_IO`)

用于 IOCTL `0x80102050` (Read) 和 `0x80102054` (Write)，缓冲区大小 **7 字节** (建议 8 字节对齐)。

```c
typedef struct _WINIO_PORT_IO {
    unsigned short PortNumber;    // +0x00: I/O 端口号
    unsigned int   Value;         // +0x02: 写入值 / 读取缓冲区 (仅 DWORD Read 使用)
    unsigned char  AccessSize;    // +0x06: 访问宽度: 1=BYTE, 2=WORD, 4=DWORD
} WINIO_PORT_IO;
```

**Read I/O Port (`0x80102050`)**:
- 输入: `PortNumber` + `AccessSize`
- 输出: 返回 4 字节 DWORD (通过 `Irp->IoStatus.Information = 4`)
- 实现: `AccessSize=1` → `in al, dx` / `AccessSize=2` → `in ax, dx` / `AccessSize=4` → `in eax, dx`

**Write I/O Port (`0x80102054`)**:
- 输入: `PortNumber` + `Value` + `AccessSize`
- 输出: 无
- 实现: `AccessSize=1` → `out dx, al` / `AccessSize=2` → `out dx, ax` / `AccessSize=4` → `out dx, eax`

---

## 导入函数

| 模块 | 函数 | 用途 |
|------|------|------|
| ntoskrnl | `IoCreateDevice` | 创建设备对象 |
| ntoskrnl | `IoCreateSymbolicLink` | 创建符号链接 |
| ntoskrnl | `IoDeleteDevice` | 删除设备对象 |
| ntoskrnl | `IoDeleteSymbolicLink` | 删除符号链接 |
| ntoskrnl | `IofCompleteRequest` | 完成 IRP 请求 |
| ntoskrnl | `ObfDereferenceObject` | 解除对象引用 |
| ntoskrnl | `ZwClose` | 关闭句柄 |
| ntoskrnl | `ZwOpenSection` | 打开 `\Device\PhysicalMemory` 段 |
| ntoskrnl | `ZwMapViewOfSection` | 映射物理内存视图 |
| ntoskrnl | `ZwUnmapViewOfSection` | 取消映射视图 |
| ntoskrnl | `ObReferenceObjectByHandle` | 通过句柄引用对象 |
| ntoskrnl | `RtlInitUnicodeString` | 初始化 UNICODE_STRING |
| HAL | `HalTranslateBusAddress` | 总线地址 → 系统物理地址转换 |

---

## 函数列表

| 地址 | 函数名 | 功能 |
|------|--------|------|
| `0x140005000` | `DriverEntry` | 驱动入口点 |
| `0x140001000` | `sub_140001000` | 初始化：创建设备 + 符号链接 + 注册分发函数 |
| `0x1400012F8` | `sub_1400012F8` | IRP 分发函数 (CREATE/CLOSE/DEVICE_CONTROL) |
| `0x1400010C0` | `sub_1400010C0` | 物理内存映射 |
| `0x1400012AC` | `sub_1400012AC` | 物理内存取消映射 |
| `0x1400014D4` | `sub_1400014D4` | 驱动卸载 |
| `0x140001568` | `sub_140001568` | GS Cookie 辅助 (安全检查) |
| `0x140001520` | `__security_check_cookie` | GS Cookie 校验 |
| `0x140001600` | `memmove` | 内存拷贝 (内联实现) |

---

## 调用流程

```
DriverEntry
  └── sub_140001000
        ├── IoCreateDevice("\Device\WinIo")
        ├── DriverObject->MajorFunction[0,2,14] = sub_1400012F8
        ├── DriverObject->DriverUnload = sub_1400014D4
        └── IoCreateSymbolicLink("\DosDevices\WinIo", "\Device\WinIo")

IRP_MJ_DEVICE_CONTROL → sub_1400012F8
  ├── 0x80102040 → memmove(输入) → sub_1400010C0 (物理内存映射) → memmove(输出)
  │                  └── ZwOpenSection("\Device\PhysicalMemory")
  │                    └── ObReferenceObjectByHandle
  │                    └── HalTranslateBusAddress(Isa, ...) ×2
  │                    └── ZwMapViewOfSection
  │
  ├── 0x80102044 → memmove(输入) → sub_1400012AC (取消映射)
  │                  └── ZwUnmapViewOfSection
  │                    └── ObfDereferenceObject
  │                    └── ZwClose
  │
  ├── 0x80102050 → memmove(输入) → __inbyte/__inword/__indword → 写入输出缓冲区
  │
  └── 0x80102054 → memmove(输入) → __outbyte/__outword/__outdword

IRP_MJ_CREATE   → 直接完成 (STATUS_SUCCESS)
IRP_MJ_CLOSE    → 直接完成 (STATUS_SUCCESS)
```

---

## 安全考虑

该驱动属于 **BYOVD (Bring Your Own Vulnerable Driver)** 典型样本：

1. **任意物理内存读写**: 通过 IOCTL `0x80102040` 可映射任意物理地址，实现内核内存任意读写
2. **任意 I/O 端口访问**: 通过 IOCTL `0x80102050`/`0x80102054` 可直接读写 I/O 端口
3. **无访问控制**: 所有 IOCTL 使用 `FILE_ANY_ACCESS`，任何用户态进程均可调用
4. **无输入验证**: 驱动未对物理地址范围、I/O 端口范围进行合法性校验

> **已知用途**: WinIo 通常用于硬件调试、风扇控制、RGB 灯光控制等工具软件，以及游戏外挂中绕过反作弊系统的内核保护。
