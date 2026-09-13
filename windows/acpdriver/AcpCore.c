// acpdriver — ACP kernel-mode helper (reference scaffold, WDM).
//
// PURPOSE
//   The ACP Windows scanner is entirely user-mode. It cannot see:
//     - modules that load and quickly unmap (stealth DLLs)
//     - kernel-mode cheats / rootkits
//     - process creation before a user-mode scan attaches
//     - memory while a cheat hooks the user-mode reading APIs
//   A tiny signed kernel helper closes that gap. It installs two notification callbacks so the
//   scanner learns about every process that starts and every image (DLL/EXE) that loads, and it
//   exposes an IOCTL that reads another process's memory through MmCopyVirtualMemory, which walks
//   the page tables and ignores user-mode API hooks.
//
// HARD REQUIREMENTS BEFORE THIS CAN RUN
//   - Windows SDK + Windows Driver Kit (WDK) 10.0.26100+ and a matching Visual Studio.
//   - A WHQL / EV-signed (or at least production-signed) driver. Windows 10 x64 refuses to load
//     an unsigned driver. Getting a real certificate and submitting to Microsoft's HLK is a
//     weeks-long, paid process — that is the genuine cost of "beating" kernel-level anti-cheats.
//   - You must NOT ship this as a naive anti-cheat: a kernel driver is a powerful, abuse-prone
//     primitive. Keep the IOCTL surface minimal and validate every caller.
//
// THIS FILE IS A REVIEWABLE STARTING POINT. IT IS NOT COMPILED OR SIGNED HERE. It is written
// against the WDK headers (wdm.h, ntifs.h); do not ship it without a full signing/HLK pipeline
// and a security review.

#include <wdm.h>
#include <ntifs.h>

#define ACP_DEVICE_NAME  L"\\Device\\ACPHelper"
#define ACP_SYMLINK_NAME L"\\DosDevices\\ACPHelper"
#define ACP_POOL_TAG     'pcAA'

// IOCTL: read |count| bytes from the memory of process |pid| at |baseAddress| into |buffer|.
//   Input in the single system buffer:
//       ACP_READ_REQUEST { ULONG ProcessId; ULONG Count; ULONGLONG BaseAddress; }
//   followed by |count| bytes of read data returned to the caller.
typedef struct _ACP_READ_REQUEST {
    ULONG     ProcessId;
    ULONG     Count;
    ULONGLONG BaseAddress;
} ACP_READ_REQUEST, *PACP_READ_REQUEST;

#define ACP_IOCTL_READ_MEMORY CTL_CODE(0x8200, 0x0800, METHOD_BUFFERED, FILE_READ_DATA | FILE_WRITE_DATA)

static PDEVICE_OBJECT  g_DeviceObject    = NULL;
static PUNICODE_STRING g_DeviceName      = NULL;
static PUNICODE_STRING g_SymlinkName     = NULL;
static PVOID           g_ProcessNotify   = NULL;
static PVOID           g_ImageNotify     = NULL;

VOID
AcpLoadImage(
    _In_opt_ PUNICODE_STRING FullImageName,
    _In_ HANDLE ProcessId,
    _In_ PIMAGE_INFO ImageInfo)
{
    UNREFERENCED_PARAMETER(FullImageName);
    UNREFERENCED_PARAMETER(ProcessId);
    UNREFERENCED_PARAMETER(ImageInfo);
    // TODO: forward to the user-mode consumer so the scanner learns about a module at load time,
    //       even before it can be enumerated through the PEB (e.g. 'unchained' stealth DLLs).
}

VOID
AcpCreateProcess(
    _In_ HANDLE ParentProcessId,
    _In_ HANDLE ProcessId,
    _In_ BOOLEAN Create)
{
    UNREFERENCED_PARAMETER(ParentProcessId);
    UNREFERENCED_PARAMETER(ProcessId);
    UNREFERENCED_PARAMETER(Create);
    // TODO: forward process create/exit so the scanner can watch for cheat launcher processes and
    //       hollowed child processes as they start, not on the next poll.
}

NTSTATUS
AcpReadProcessMemory(
    _In_ PACP_READ_REQUEST Request,
    _Out_writes_(Request->Count) PUCHAR Output)
{
    NTSTATUS status;
    PEPROCESS process = NULL;
    SIZE_T bytesRead = 0;

    if (Request->Count == 0 || Request->Count > 64 * 1024 || Request->BaseAddress == 0) {
        return STATUS_INVALID_PARAMETER;
    }

    status = PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)Request->ProcessId, &process);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    // MmCopyVirtualMemory walks the target's page tables; it cannot be hooked from the target
    // user mode and works even if the target has tampered with its own import table.
    status = MmCopyVirtualMemory(
        process,
        (PVOID)(ULONG_PTR)Request->BaseAddress,
        PsGetCurrentProcess(),
        (PVOID)Output,
        (SIZE_T)Request->Count,
        KernelMode,
        &bytesRead);

    ObDereferenceObject(process);

    if (NT_SUCCESS(status) && bytesRead != Request->Count) {
        RtlZeroMemory(Output + bytesRead, Request->Count - bytesRead);
    }

    return status;
}

NTSTATUS
AcpDeviceControl(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP Irp)
{
    UNREFERENCED_PARAMETER(DeviceObject);
    PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(Irp);
    ULONG code = stack->Parameters.DeviceIoControl.IoControlCode;
    ULONG inLen = stack->Parameters.DeviceIoControl.InputBufferLength;
    ULONG outLen = stack->Parameters.DeviceIoControl.OutputBufferLength;
    PVOID buffer = Irp->AssociatedIrp.SystemBuffer;
    NTSTATUS status = STATUS_INVALID_DEVICE_REQUEST;
    ULONG info = 0;

    if (code == ACP_IOCTL_READ_MEMORY) {
        if (buffer != NULL && inLen >= sizeof(ACP_READ_REQUEST)) {
            PACP_READ_REQUEST req = (PACP_READ_REQUEST)buffer;
            SIZE_T needed = sizeof(ACP_READ_REQUEST) + req->Count;
            if (outLen >= needed) {
                status = AcpReadProcessMemory(req, (PUCHAR)req + sizeof(ACP_READ_REQUEST));
                info = (ULONG)needed;
            } else {
                status = STATUS_BUFFER_TOO_SMALL;
            }
        } else {
            status = STATUS_INVALID_PARAMETER;
        }
    }

    Irp->IoStatus.Status = status;
    Irp->IoStatus.Information = info;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return status;
}

NTSTATUS AcpDeviceCreate(_In_ PDEVICE_OBJECT, _In_ PIRP Irp)
{
    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

static VOID AcpInitUnicode(PUNICODE_STRING u, PCWCH literal)
{
    u->Buffer = (PWCH)ExAllocatePoolWithTag(NonPagedPool, (wcslen(literal) + 1) * sizeof(WCHAR), ACP_POOL_TAG);
    if (u->Buffer != NULL) {
        wcscpy_s(u->Buffer, wcslen(literal) + 1, literal);
        u->Length = (USHORT)(wcslen(u->Buffer) * sizeof(WCHAR));
        u->MaximumLength = (USHORT)((wcslen(u->Buffer) + 1) * sizeof(WCHAR));
    }
}

NTSTATUS AcpUnload(_In_ PDRIVER_OBJECT DriverObject)
{
    if (g_ProcessNotify != NULL) {
        PsSetCreateProcessNotifyRoutineEx(NULL, g_ProcessNotify, TRUE);
        g_ProcessNotify = NULL;
    }
    if (g_ImageNotify != NULL) {
        PsRemoveLoadImageNotifyRoutine(g_ImageNotify);
        g_ImageNotify = NULL;
    }

    if (g_SymlinkName != NULL && g_SymlinkName->Buffer != NULL) {
        IoDeleteSymbolicLink(g_SymlinkName);
    }
    if (g_DeviceObject != NULL) {
        IoDeleteDevice(g_DeviceObject);
    }
    if (g_DeviceName != NULL && g_DeviceName->Buffer != NULL) {
        ExFreePoolWithTag(g_DeviceName->Buffer, ACP_POOL_TAG);
    }
    if (g_SymlinkName != NULL && g_SymlinkName->Buffer != NULL) {
        ExFreePoolWithTag(g_SymlinkName->Buffer, ACP_POOL_TAG);
    }
    if (g_DeviceName != NULL) {
        ExFreePoolWithTag(g_DeviceName, ACP_POOL_TAG);
    }
    if (g_SymlinkName != NULL) {
        ExFreePoolWithTag(g_SymlinkName, ACP_POOL_TAG);
    }

    return STATUS_SUCCESS;
}

NTSTATUS DriverEntry(_In_ PDRIVER_OBJECT DriverObject, _In_ PUNICODE_STRING RegistryPath)
{
    UNREFERENCED_PARAMETER(RegistryPath);
    NTSTATUS status;
    PDEVICE_OBJECT device = NULL;

    g_DeviceName = (PUNICODE_STRING)ExAllocatePoolWithTag(NonPagedPool, sizeof(UNICODE_STRING), ACP_POOL_TAG);
    g_SymlinkName = (PUNICODE_STRING)ExAllocatePoolWithTag(NonPagedPool, sizeof(UNICODE_STRING), ACP_POOL_TAG);
    if (g_DeviceName == NULL || g_SymlinkName == NULL) {
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto fail;
    }

    AcpInitUnicode(g_DeviceName, ACP_DEVICE_NAME);
    AcpInitUnicode(g_SymlinkName, ACP_SYMLINK_NAME);
    if (g_DeviceName->Buffer == NULL || g_SymlinkName->Buffer == NULL) {
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto fail;
    }

    status = IoCreateDevice(DriverObject, 0, g_DeviceName, FILE_DEVICE_UNKNOWN, FILE_DEVICE_SECURE_OPEN, FALSE, &device);
    if (!NT_SUCCESS(status)) {
        goto fail;
    }
    g_DeviceObject = device;

    status = IoCreateSymbolicLink(g_SymlinkName, g_DeviceName);
    if (!NT_SUCCESS(status)) {
        goto fail;
    }

    DriverObject->MajorFunction[IRP_MJ_CREATE] = AcpDeviceCreate;
    DriverObject->MajorFunction[IRP_MJ_CLOSE] = AcpDeviceCreate;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = AcpDeviceControl;
    DriverObject->DriverUnload = AcpUnload;

    status = PsSetCreateProcessNotifyRoutineEx(AcpCreateProcess, FALSE);
    if (!NT_SUCCESS(status)) {
        status = PsSetCreateProcessNotifyRoutine(AcpCreateProcess, FALSE);
        if (!NT_SUCCESS(status)) {
            goto fail;
        }
    }

    status = PsSetLoadImageNotifyRoutine(AcpLoadImage);
    if (!NT_SUCCESS(status)) {
        goto fail;
    }

    return STATUS_SUCCESS;

fail:
    AcpUnload(DriverObject);
    return status;
}
