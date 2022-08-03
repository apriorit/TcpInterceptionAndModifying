#include "pch.h"
#include "NetFilter.h"

static PDEVICE_OBJECT g_deviceObject = nullptr;

static void DriverUnload(PDRIVER_OBJECT /*driverObject*/)
{
    DeinitializeFilter();

    if (g_deviceObject)
    {
        IoDeleteDevice(g_deviceObject);
        g_deviceObject = nullptr;
    }
}

EXTERN_C NTSTATUS DriverEntry(PDRIVER_OBJECT driverObject, PUNICODE_STRING /*registryPath*/)
{
    NTSTATUS status = IoCreateDevice(driverObject, 0, nullptr, FILE_DEVICE_UNKNOWN, 0, false, &g_deviceObject);
    if (!NT_SUCCESS(status))
    {
        return status;
    }

    driverObject->DriverUnload = DriverUnload;

    status = InitializeFilter(g_deviceObject);
    if (!NT_SUCCESS(status))
    {
        DriverUnload(driverObject);
    }

    return status;
}