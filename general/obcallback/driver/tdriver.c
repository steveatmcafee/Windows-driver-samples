/*++

Module Name:

    tdriver.c

Abstract:

    Main module for the Ob and Ps sample code

Notice:
    Use this sample code at your own risk; there is no support from Microsoft for the sample code.
    In addition, this sample code is licensed to you under the terms of the Microsoft Public License
    (http://www.microsoft.com/opensource/licenses.mspx)


--*/

#include "pch.h"
#include "tdriver.h"

//
// Process notify routines.
//

BOOLEAN TdProcessNotifyRoutineSet2 = FALSE;

// allow filter the requested access
BOOLEAN TdbProtectName = FALSE;
BOOLEAN TdbRejectName = FALSE;
#define TAGDEF(a,b,c,d) ((a)+((b)<<8)+((c)<<16)+((d)<<24))
#define TAGDEFS(s) (TAGDEF( s[0], s[1], s[2], s[3]) )
ULONG DRIVER_TAG = TAGDEF('M', 'F', 'E', '0');

//
// Function declarations
//
DRIVER_INITIALIZE  DriverEntry;
_Dispatch_type_(IRP_MJ_CREATE) DRIVER_DISPATCH TdDeviceCreate;
_Dispatch_type_(IRP_MJ_CLOSE) DRIVER_DISPATCH TdDeviceClose;
_Dispatch_type_(IRP_MJ_CLEANUP) DRIVER_DISPATCH TdDeviceCleanup;
_Dispatch_type_(IRP_MJ_DEVICE_CONTROL) DRIVER_DISPATCH TdDeviceControl;
extern int fibValue;
DRIVER_UNLOAD   TdDeviceUnload;

VOID
TdCreateProcessNotifyRoutine2 (
    _Inout_ PEPROCESS Process,
    _In_ HANDLE ProcessId,
    _In_opt_ PPS_CREATE_NOTIFY_INFO CreateInfo
    )
{
    NTSTATUS Status = STATUS_SUCCESS;

    if (CreateInfo != NULL)
    {

        DbgPrintEx (
            DPFLTR_IHVDRIVER_ID, DPFLTR_TRACE_LEVEL,
            "ObCallbackTest: TdCreateProcessNotifyRoutine2: process %p (ID 0x%p) created, creator %Ix:%Ix\n"
            "    command line %wZ\n"
            "    file name %wZ (FileOpenNameAvailable: %d)\n",
            Process,
            (PVOID)ProcessId,
            (ULONG_PTR)CreateInfo->CreatingThreadId.UniqueProcess,
            (ULONG_PTR)CreateInfo->CreatingThreadId.UniqueThread,
            CreateInfo->CommandLine,
            CreateInfo->ImageFileName,
            CreateInfo->FileOpenNameAvailable
        );

        // Search for matching process to protect only if filtering
        if (TdbProtectName) {
            if (CreateInfo->CommandLine != NULL)
            {
                Status = TdCheckProcessMatch(CreateInfo->CommandLine, Process, ProcessId);

                if (Status == STATUS_SUCCESS) {
                    DbgPrintEx (
                        DPFLTR_IHVDRIVER_ID, DPFLTR_TRACE_LEVEL, "ObCallbackTest: TdCreateProcessNotifyRoutine2: PROTECTING process %p (ID 0x%p)\n",
                        Process,
                        (PVOID)ProcessId
                    );
                }
            }

        }

        // Search for matching process to reject process creation
        if (TdbRejectName) {
            if (CreateInfo->CommandLine != NULL)
            {
                Status = TdCheckProcessMatch(CreateInfo->CommandLine, Process, ProcessId);

                if (Status == STATUS_SUCCESS) {
                    DbgPrintEx (
                        DPFLTR_IHVDRIVER_ID, DPFLTR_TRACE_LEVEL, "ObCallbackTest: TdCreateProcessNotifyRoutine2: REJECTING process %p (ID 0x%p)\n",
                        Process,
                        (PVOID)ProcessId
                    );

                    CreateInfo->CreationStatus = STATUS_ACCESS_DENIED;
                }
            }

        }
    }
    else
    {
        DbgPrintEx (
            DPFLTR_IHVDRIVER_ID, DPFLTR_TRACE_LEVEL, "ObCallbackTest: TdCreateProcessNotifyRoutine2: process %p (ID 0x%p) destroyed\n",
            Process,
            (PVOID)ProcessId
        );
    }
}

ULONG GetKeyInfoSize(HANDLE hRegistryKey, PUNICODE_STRING pValueName) {
    NTSTATUS ntStatus = STATUS_SUCCESS;

    ULONG ulKeyInfoSizeNeeded;
    ntStatus = ZwQueryValueKey(hRegistryKey, pValueName, KeyValueFullInformation, 0, 0, &ulKeyInfoSizeNeeded);
    if (ntStatus == STATUS_BUFFER_TOO_SMALL || ntStatus == STATUS_BUFFER_OVERFLOW) {
        // Expected don't worry - when ZwQueryValueKey fails with one of the above statuses, it returns the size needed
        return ulKeyInfoSizeNeeded;
    }
    else {
        KdPrint((DRIVER_PREFIX "Could not get key info size (0x%08X)\n", ntStatus));
    }

    return 0;
}

void ReadRegistryValue(PUNICODE_STRING RegistryPath)
{
    NTSTATUS ntStatus = STATUS_SUCCESS;

    UNICODE_STRING valueName = RTL_CONSTANT_STRING(L"FibName");
    HANDLE hRegistryKey;
    PKEY_VALUE_FULL_INFORMATION pKeyInfo = NULL;

    // Create object attributes for registry key querying
    OBJECT_ATTRIBUTES ObjectAttributes = { 0 };
    InitializeObjectAttributes(&ObjectAttributes, RegistryPath, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);

    do {
        ntStatus = ZwOpenKey(&hRegistryKey, KEY_QUERY_VALUE, &ObjectAttributes);
        if (!NT_SUCCESS(ntStatus)) {
            KdPrint((DRIVER_PREFIX "Registry key open failed (0x%08X)\n", ntStatus));
            break;
        }

        ULONG ulKeyInfoSize;
        ULONG ulKeyInfoSizeNeeded = GetKeyInfoSize(hRegistryKey, &valueName);
        if (ulKeyInfoSizeNeeded == 0) {
            KdPrint((DRIVER_PREFIX "Value not found\n"));
            break;
        }
        ulKeyInfoSize = ulKeyInfoSizeNeeded;

        pKeyInfo = (PKEY_VALUE_FULL_INFORMATION)ExAllocatePoolWithTag(NonPagedPool, ulKeyInfoSize, DRIVER_TAG);
        if (pKeyInfo == NULL) {
            KdPrint((DRIVER_PREFIX "Could not allocate memory for KeyValueInfo\n"));
            break;
        }
        RtlZeroMemory(pKeyInfo, ulKeyInfoSize);

        ntStatus = ZwQueryValueKey(hRegistryKey, &valueName, KeyValueFullInformation, pKeyInfo, ulKeyInfoSize, &ulKeyInfoSizeNeeded);
        if (!NT_SUCCESS(ntStatus) || ulKeyInfoSize != ulKeyInfoSizeNeeded) {
            KdPrint((DRIVER_PREFIX "Registry value querying failed (0x%08X)\n", ntStatus));
            break;
        }

        // your data
        ULONG someLong = *(ULONG*)((ULONG_PTR)pKeyInfo + pKeyInfo->DataOffset);
        fibValue = someLong;
    } while (0);

    // cleanup
    if (hRegistryKey) {
        ZwClose(hRegistryKey);
    }

    if (pKeyInfo) {
        ExFreePoolWithTag(pKeyInfo, DRIVER_TAG);
    }

    if (!NT_SUCCESS(ntStatus)) {
        // Here you can set a default data if something failed it the way
    }

    // ...
}


//
// DriverEntry
//

NTSTATUS
DriverEntry (
    _In_ PDRIVER_OBJECT  DriverObject,
    _In_ PUNICODE_STRING RegistryPath
)
{
    NTSTATUS Status;
    UNICODE_STRING NtDeviceName = RTL_CONSTANT_STRING (TD_NT_DEVICE_NAME);
    UNICODE_STRING DosDevicesLinkName = RTL_CONSTANT_STRING (TD_DOS_DEVICES_LINK_NAME);
    PDEVICE_OBJECT Device = NULL;
    BOOLEAN SymLinkCreated = FALSE;
    USHORT CallbackVersion;

    UNREFERENCED_PARAMETER (RegistryPath);

    DbgPrintEx (DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "ObCallbackTest: DriverEntry: Driver loaded. Use ed nt!Kd_IHVDRIVER_Mask f (or 7) to enable more traces\n");

    CallbackVersion = ObGetFilterVersion();

    DbgPrintEx (DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "ObCallbackTest: DriverEntry: Callback version 0x%hx\n", CallbackVersion);

    //
    // Initialize globals.
    //

    KeInitializeGuardedMutex (&TdCallbacksMutex);
    
    //
    // Create our device object.
    //

    Status = IoCreateDevice (                    
        DriverObject,                 // pointer to driver object
        0,                            // device extension size
        &NtDeviceName,                // device name
        FILE_DEVICE_UNKNOWN,          // device type
        0,                            // device characteristics
        FALSE,                        // not exclusive
        &Device);                     // returned device object pointer

    if (! NT_SUCCESS(Status))
    {
        goto Exit;
    }

    TD_ASSERT (Device == DriverObject->DeviceObject);

    //
    // Set dispatch routines.
    //

    DriverObject->MajorFunction[IRP_MJ_CREATE]         = TdDeviceCreate;
    DriverObject->MajorFunction[IRP_MJ_CLOSE]          = TdDeviceClose;
    DriverObject->MajorFunction[IRP_MJ_CLEANUP]        = TdDeviceCleanup;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = TdDeviceControl;
    DriverObject->DriverUnload                         = TdDeviceUnload;

    //
    // Create a link in the Win32 namespace.
    //
    
    Status = IoCreateSymbolicLink (&DosDevicesLinkName, &NtDeviceName);

    if (! NT_SUCCESS(Status))
    {
        goto Exit;
    }

    SymLinkCreated = TRUE;

    //
    // Set process create routines.
    //

    Status = PsSetCreateProcessNotifyRoutineEx (
        TdCreateProcessNotifyRoutine2,
        FALSE
    );

    if (! NT_SUCCESS(Status))
    {
        DbgPrintEx (DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "ObCallbackTest: DriverEntry: PsSetCreateProcessNotifyRoutineEx(2) returned 0x%x\n", Status);
        goto Exit;
    }

    TdProcessNotifyRoutineSet2 = TRUE;

Exit:

    if (!NT_SUCCESS (Status))
    {
        if (TdProcessNotifyRoutineSet2 == TRUE)
        {
            Status = PsSetCreateProcessNotifyRoutineEx (
                TdCreateProcessNotifyRoutine2,
                TRUE
            );

            TD_ASSERT (Status == STATUS_SUCCESS);

            TdProcessNotifyRoutineSet2 = FALSE;
        }

        if (SymLinkCreated == TRUE)
        {
            IoDeleteSymbolicLink (&DosDevicesLinkName);
        }

        if (Device != NULL)
        {
            IoDeleteDevice (Device);
        }
    }

    return Status;
}

//
// Function:
//
//     TdDeviceUnload
//
// Description:
//
//     This function handles driver unloading. All this driver needs to do 
//     is to delete the device object and the symbolic link between our 
//     device name and the Win32 visible name.
//

VOID
TdDeviceUnload (
    _In_ PDRIVER_OBJECT DriverObject
)
{
    NTSTATUS Status = STATUS_SUCCESS;
    UNICODE_STRING DosDevicesLinkName = RTL_CONSTANT_STRING (TD_DOS_DEVICES_LINK_NAME);

    DbgPrintEx (DPFLTR_IHVDRIVER_ID, DPFLTR_TRACE_LEVEL, "ObCallbackTest: TdDeviceUnload\n");

    //
    // Unregister process notify routines.
    //

    if (TdProcessNotifyRoutineSet2 == TRUE)
    {
        Status = PsSetCreateProcessNotifyRoutineEx (
            TdCreateProcessNotifyRoutine2,
            TRUE
        );

        TD_ASSERT (Status == STATUS_SUCCESS);

        TdProcessNotifyRoutineSet2 = FALSE;
    }

    // remove filtering and remove any OB callbacks
    TdbProtectName = FALSE;
    Status = TdDeleteProtectNameCallback();
    TD_ASSERT (Status == STATUS_SUCCESS);

    //
    // Delete the link from our device name to a name in the Win32 namespace.
    //

    Status = IoDeleteSymbolicLink (&DosDevicesLinkName);
    if (Status != STATUS_INSUFFICIENT_RESOURCES) {
        //
        // IoDeleteSymbolicLink can fail with STATUS_INSUFFICIENT_RESOURCES.
        //
    
        TD_ASSERT (NT_SUCCESS (Status));

    }


    //
    // Delete our device object.
    //

    IoDeleteDevice (DriverObject->DeviceObject);
}

//
// Function:
//
//     TdDeviceCreate
//
// Description:
//
//     This function handles the 'create' irp.
//


NTSTATUS
TdDeviceCreate (
    IN PDEVICE_OBJECT  DeviceObject,
    IN PIRP  Irp
)
{
    UNREFERENCED_PARAMETER (DeviceObject);

    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest (Irp, IO_NO_INCREMENT);

    return STATUS_SUCCESS;
}

//
// Function:
//
//     TdDeviceClose
//
// Description:
//
//     This function handles the 'close' irp.
//

NTSTATUS
TdDeviceClose (
    IN PDEVICE_OBJECT  DeviceObject,
    IN PIRP  Irp
)
{
    UNREFERENCED_PARAMETER (DeviceObject);

    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest (Irp, IO_NO_INCREMENT);

    return STATUS_SUCCESS;
}

//
// Function:
//
//     TdDeviceCleanup
//
// Description:
//
//     This function handles the 'cleanup' irp.
//

NTSTATUS
TdDeviceCleanup (
    IN PDEVICE_OBJECT  DeviceObject,
    IN PIRP  Irp
)
{
    UNREFERENCED_PARAMETER (DeviceObject);

    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest (Irp, IO_NO_INCREMENT);

    return STATUS_SUCCESS;
}

//
// TdControlProtectName
//

NTSTATUS TdControlProtectName (
    IN PDEVICE_OBJECT  DeviceObject,
    IN PIRP  Irp
)
{
    NTSTATUS Status = STATUS_SUCCESS;
    PIO_STACK_LOCATION IrpStack = NULL;
    ULONG InputBufferLength = 0;
    PTD_PROTECTNAME_INPUT pProtectNameInput = NULL;

    UNREFERENCED_PARAMETER (DeviceObject);


    DbgPrintEx (
        DPFLTR_IHVDRIVER_ID, DPFLTR_TRACE_LEVEL,
        "ObCallbackTest: TdControlProtectName: Entering\n");

    IrpStack = IoGetCurrentIrpStackLocation (Irp);
    InputBufferLength = IrpStack->Parameters.DeviceIoControl.InputBufferLength;

    if (InputBufferLength < sizeof (TD_PROTECTNAME_INPUT))
    {
        Status = STATUS_BUFFER_OVERFLOW;
        goto Exit;
    }

    pProtectNameInput = (PTD_PROTECTNAME_INPUT)Irp->AssociatedIrp.SystemBuffer;

    Status = TdProtectNameCallback (pProtectNameInput);

    switch (pProtectNameInput->Operation) {
        case TDProtectName_Protect:
            // Begin filtering access rights
            TdbProtectName = TRUE;
            TdbRejectName = FALSE;
            break;
    
        case TDProtectName_Reject:
            // Begin reject process creation on match
            TdbProtectName = FALSE;
            TdbRejectName = TRUE;
            break;
    }


Exit:
    DbgPrintEx (
        DPFLTR_IHVDRIVER_ID, DPFLTR_TRACE_LEVEL,
        "ObCallbackTest: TD_IOCTL_PROTECTNAME: Status %x\n", Status);

    return Status;
}

//
// TdControlUnprotect
//

NTSTATUS TdControlUnprotect (
    IN PDEVICE_OBJECT  DeviceObject,
    IN PIRP  Irp
)
{
    NTSTATUS Status = STATUS_SUCCESS;
    // PIO_STACK_LOCATION IrpStack = NULL;
    // ULONG InputBufferLength = 0;

    UNREFERENCED_PARAMETER (DeviceObject);
    UNREFERENCED_PARAMETER (Irp);

    // IrpStack = IoGetCurrentIrpStackLocation (Irp);
    // InputBufferLength = IrpStack->Parameters.DeviceIoControl.InputBufferLength;

    // No need to check length of passed in parameters as we do not need any information from that

    // do not filter requested access
    Status = TdDeleteProtectNameCallback();
    if (Status != STATUS_SUCCESS) {
        DbgPrintEx (
            DPFLTR_IHVDRIVER_ID, DPFLTR_TRACE_LEVEL,
            "ObCallbackTest: TdDeleteProtectNameCallback:  status 0x%x\n", Status);
        }
    TdbProtectName = FALSE;
    TdbRejectName = FALSE;

//Exit:
    DbgPrintEx (
        DPFLTR_IHVDRIVER_ID, DPFLTR_TRACE_LEVEL,
        "ObCallbackTest: TD_IOCTL_UNPROTECT: exiting - status 0x%x\n", Status);

    return Status;
}


//
// Function:
//
//     TdDeviceControl
//
// Description:
//
//     This function handles 'control' irp.
//

NTSTATUS
TdDeviceControl (
    IN PDEVICE_OBJECT  DeviceObject,
    IN PIRP  Irp
)
{
    PIO_STACK_LOCATION IrpStack;
    ULONG Ioctl;
    NTSTATUS Status;

    UNREFERENCED_PARAMETER (DeviceObject);


    Status = STATUS_SUCCESS;

    IrpStack = IoGetCurrentIrpStackLocation (Irp);
    Ioctl = IrpStack->Parameters.DeviceIoControl.IoControlCode;

    DbgPrintEx (DPFLTR_IHVDRIVER_ID, DPFLTR_TRACE_LEVEL, "TdDeviceControl: entering - ioctl code 0x%x\n", Ioctl);

    switch (Ioctl)
    {
    case TD_IOCTL_PROTECT_NAME_CALLBACK:

        Status = TdControlProtectName (DeviceObject, Irp);
        break;

    case TD_IOCTL_UNPROTECT_CALLBACK:

        Status = TdControlUnprotect (DeviceObject, Irp);
        break;


    default:
        DbgPrintEx (DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "TdDeviceControl: unrecognized ioctl code 0x%x\n", Ioctl);
        break;
    }

    //
    // Complete the irp and return.
    //

    Irp->IoStatus.Status = Status;
    IoCompleteRequest (Irp, IO_NO_INCREMENT);

    DbgPrintEx (DPFLTR_IHVDRIVER_ID, DPFLTR_TRACE_LEVEL, "TdDeviceControl leaving - status 0x%x\n", Status);
    return Status;
}
