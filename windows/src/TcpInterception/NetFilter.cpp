#include "pch.h"
#include "NetFilter.h"

#ifndef FlagOn
#define FlagOn(_F,_SF)        ((_F) & (_SF))
#endif

#ifndef ClearFlag
#define ClearFlag(_F,_SF)     ((_F) &= ~(_SF))
#endif

#ifndef SetFlag
#define SetFlag(_F,_SF)       ((_F) |= (_SF))
#endif

#define Add2Ptr(P,I) ((PVOID)((PUCHAR)(P) + (I)))

// {B8F58E09-BA43-4837-9723-AD80258E8C0A}
DEFINE_GUID(TCP_INTERCEPTION_SUBLAYER, 0xb8f58e09, 0xba43, 0x4837, 0x97, 0x23, 0xad, 0x80, 0x25, 0x8e, 0x8c, 0xa);

// {47896A45-35FB-4EFF-92D5-5BC8A91343C3}
DEFINE_GUID(TCP_INTERCEPTION_OUTBOUND_TRANSPORT_V4_CALLOUT, 0x47896a45, 0x35fb, 0x4eff, 0x92, 0xd5, 0x5b, 0xc8, 0xa9, 0x13, 0x43, 0xc3);

#define NET_BUFFER_LIST_STORAGE_TAG      'gTlB'
#define NET_BUFFER_LIST_PTR_TAG          'gTtP'
#define SEND_PARAMETERS_TAG              'gTpS'

const wchar_t g_displayName[] = L"TCP Interception Filter";

#pragma pack(push, 1)
struct TcpHeader
{
    UINT16 source;
    UINT16 dest;
    UINT32 seq;
    UINT32 ackSeq;

    UINT8 ns : 1;
    UINT8 reserved : 3;
    UINT8 offset : 4;

    UINT8 fin : 1;
    UINT8 syn : 1;
    UINT8 rst : 1;
    UINT8 psh : 1;
    UINT8 ack : 1;
    UINT8 urg : 1;
    UINT8 ece : 1;
    UINT8 cwr : 1;

    UINT16 window;
    UINT16 check;
    UINT16 urgPointer;
};
#pragma pack(pop)

struct SendParameters
{
    IN_ADDR                    addr;
    FWPS_TRANSPORT_SEND_PARAMS params;
};

struct NetworkBufferListStorage
{
    NDIS_HANDLE             handle;
    PVOID                   ptr;
    PMDL                    mdl;
    PNET_BUFFER_LIST        list;
    SendParameters*         params;
};

static HANDLE g_engineHandle = nullptr;
static NDIS_HANDLE g_netBufferListHandle = nullptr;
static HANDLE g_injectionHandle = nullptr;
static UINT32 g_id = 0;

static ULONG GetTcpHeaderSize(const TcpHeader& tcpHeader)
{
    // TCP offset is specified in 32-bit words so need to multiply its value by 4 
    return tcpHeader.offset * 4;
}

static void FreeNetworkBufferListStorage(NetworkBufferListStorage* storage)
{
    if (!storage)
    {
        return;
    }

    if (storage->ptr)
    {
        ExFreePoolWithTag(storage->ptr, NET_BUFFER_LIST_PTR_TAG);
    }

    if (storage->mdl)
    {
        IoFreeMdl(storage->mdl);
    }

    if (storage->list)
    {
        FwpsFreeNetBufferList(storage->list);
    }

    if (storage->params)
    {
        ExFreePoolWithTag(storage->params, SEND_PARAMETERS_TAG);
    }

    ExFreePoolWithTag(storage, NET_BUFFER_LIST_STORAGE_TAG);
}

static void CompleteCallback(PVOID context,
    PNET_BUFFER_LIST /*netBufferList*/,
    BOOLEAN /*dispatchLevel*/
)
{
    FreeNetworkBufferListStorage(reinterpret_cast<NetworkBufferListStorage*>(context));
}

static NTSTATUS InitializeNetworkBufferListStorage(NetworkBufferListStorage& storage,
    SendParameters* params,
    ULONG size)
{
    storage.ptr = ExAllocatePoolWithTag(NonPagedPoolNx,
        size,
        NET_BUFFER_LIST_PTR_TAG);
    if (!storage.ptr)
    {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    storage.mdl = IoAllocateMdl(storage.ptr, size, false, false, nullptr);
    if (!storage.mdl)
    {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    MmBuildMdlForNonPagedPool(storage.mdl);

    NTSTATUS status = FwpsAllocateNetBufferAndNetBufferList(g_netBufferListHandle,
        0,
        0,
        storage.mdl,
        0,
        size,
        &storage.list);
    if (NT_SUCCESS(status))
    {
        storage.params = params;
    }

    return status;
}

static NetworkBufferListStorage* CreateNetworkBufferListStorage(ULONG size, SendParameters* params)
{
    auto netBufferStorage = reinterpret_cast<NetworkBufferListStorage*>(ExAllocatePoolWithTag(
        NonPagedPoolNx,
        sizeof(NetworkBufferListStorage),
        NET_BUFFER_LIST_STORAGE_TAG));
    if (!netBufferStorage)
    {
        return nullptr;
    }

    NTSTATUS status = InitializeNetworkBufferListStorage(*netBufferStorage, params, size);
    if (!NT_SUCCESS(status))
    {
        FreeNetworkBufferListStorage(netBufferStorage);
        netBufferStorage = nullptr;
    }

    return netBufferStorage;
}

static SendParameters* CreateSendParameters(const SCOPE_ID& scopeId, UINT32 address)
{
     auto params = reinterpret_cast<SendParameters*>(ExAllocatePoolWithTag(NonPagedPoolNx,
        sizeof(SendParameters),
        SEND_PARAMETERS_TAG));

    if (!params)
    {
        return nullptr;
    }

    RtlZeroMemory(params, sizeof(SendParameters));

    params->params.remoteAddress = reinterpret_cast<UCHAR*>(&params->addr);
    params->params.remoteScopeId = scopeId;
    params->addr.S_un.S_addr = _byteswap_ulong(address);

    return params;
}

static NTSTATUS InsertUpdatedTcpPacket(NetworkBufferListStorage& storage,
    const TcpHeader& origTcpHeader,
    ULONG newTcpHeaderSize,
    UINT64 endpointHandle,
    COMPARTMENT_ID compId)
{
    auto newTcpHeader = reinterpret_cast<TcpHeader*>(NdisGetDataBuffer(NET_BUFFER_LIST_FIRST_NB(storage.list),
        newTcpHeaderSize,
        nullptr,
        1,
        0));
    if (!newTcpHeader)
    {
        return STATUS_UNSUCCESSFUL;
    }

    const auto origTcpHeaderSize = GetTcpHeaderSize(origTcpHeader);
    RtlCopyMemory(newTcpHeader, &origTcpHeader, origTcpHeaderSize);

    // TCP offset is specified in 32-bit words so need to multiply its value by 4 
    char* extraOptions = reinterpret_cast<char*>(Add2Ptr(newTcpHeader, origTcpHeaderSize));
    // TCP options from 79-252 reserved so we can use value from this range
    extraOptions[0] = 100;
    // Size in bytes of TCP option including Kind and Size fields
    extraOptions[1] = 3;
    // Set option value 1 for Windows
    extraOptions[2] = 1;
    // Need to set padding byte to 0
    extraOptions[3] = 0;

    // DataSize specifies the size of the TCP header in 32 - bit words
    newTcpHeader->offset = newTcpHeaderSize / 4;
    newTcpHeader->check = 0;

    return FwpsInjectTransportSendAsync(g_injectionHandle,
        nullptr,
        endpointHandle,
        0,
        &storage.params->params,
        AF_INET,
        compId,
        storage.list,
        CompleteCallback,
        &storage);
}

static void ProcessTransportData(const FWPS_INCOMING_VALUES0* inFixedValues,
    const FWPS_INCOMING_METADATA_VALUES0* inMetaValues,
    void* layerData,
    FWPS_CLASSIFY_OUT0* classifyOut)
{
    // Skip packet not connected to our target port 
    if (_byteswap_ushort(inFixedValues->incomingValue[FWPS_FIELD_OUTBOUND_TRANSPORT_V4_IP_REMOTE_PORT].value.uint16) == 6044)
    {
        return;
    }

    const auto injectionState = FwpsQueryPacketInjectionState0(g_injectionHandle,
        static_cast<NET_BUFFER_LIST*>(layerData),
        nullptr);

    // Skip packets injected by our driver
    if (FWPS_PACKET_INJECTED_BY_SELF == injectionState ||
        FWPS_PACKET_PREVIOUSLY_INJECTED_BY_SELF == injectionState)
    {
        return;
    }

    NET_BUFFER_LIST* netBufferList = static_cast<NET_BUFFER_LIST*>(layerData);
    // TCP header always stored in the first NET_BUFFER_LIST
    ASSERT(NET_BUFFER_LIST_NEXT_NBL(netBufferList) == nullptr);

    // For the SYN packet NET_BUFFER_LIST will contain only one net buffer
    NET_BUFFER* netBuffer = NET_BUFFER_LIST_FIRST_NB(netBufferList);

    // TCP header size without options equals 20 bytes
    static const ULONG tcpHeaderSize = 20;
    const auto origTcpHeader = reinterpret_cast<TcpHeader*>(NdisGetDataBuffer(netBuffer, tcpHeaderSize, nullptr, 1, 0));
    // Skip packets that doesn't have SYN flag set
    if (!origTcpHeader || !origTcpHeader->syn)
    {
        return;
    }

    // Need to block and absorb current packet to inject new packet with options instead of it
    classifyOut->actionType = FWP_ACTION_BLOCK;
    SetFlag(classifyOut->flags, FWPS_CLASSIFY_OUT_FLAG_ABSORB);

    const ULONG originalTcpHeaderSize = GetTcpHeaderSize(*origTcpHeader);

    // Get the size of the TCP header with options
    const auto origTcpHeaderWithOptions = reinterpret_cast<TcpHeader*>(NdisGetDataBuffer(netBuffer, originalTcpHeaderSize, nullptr, 1, 0));
    if (!origTcpHeaderWithOptions)
    {
        DbgPrint("Failed to get TCP header with options\n");
        return;
    }

    auto sendParams = CreateSendParameters(inMetaValues->remoteScopeId,
        inFixedValues->incomingValue[FWPS_FIELD_OUTBOUND_TRANSPORT_V4_IP_REMOTE_ADDRESS].value.uint32);
    if (!sendParams)
    {
        return;
    }

    // TCP header size should be aligned in the 32-bit words
    // Need to extend packet by new options size and padding bytes
    // In our case it is 1 byte
    static const int extraOptionSize = 3;
    const ULONG newTcpHeaderSize = extraOptionSize + originalTcpHeaderSize + 1;

    // Need to allocate new NET_BUFFER_LIST for new packet with new TCP header
    auto netBufferListStorage = CreateNetworkBufferListStorage(newTcpHeaderSize, sendParams);
    if (!netBufferListStorage)
    {
        ExFreePoolWithTag(sendParams, SEND_PARAMETERS_TAG);
        return;
    }
    sendParams = nullptr;

    NTSTATUS status = InsertUpdatedTcpPacket(*netBufferListStorage,
        *origTcpHeader,
        newTcpHeaderSize,
        inMetaValues->transportEndpointHandle,
        static_cast<COMPARTMENT_ID>(inMetaValues->compartmentId));
    if (!NT_SUCCESS(status))
    {
        FreeNetworkBufferListStorage(netBufferListStorage);
        netBufferListStorage = nullptr;
    }
}

static void CalloutConnectClassifyFn(
    const FWPS_INCOMING_VALUES0* inFixedValues,
    const FWPS_INCOMING_METADATA_VALUES0* inMetaValues,
    void* layerData,
    const FWPS_FILTER0* filter,
    UINT64 /*flowContext*/,
    FWPS_CLASSIFY_OUT0* classifyOut)
{
    // Allowing the traffic for another filter to make a final decision.
    if (FlagOn(classifyOut->rights, FWPS_RIGHT_ACTION_WRITE))
    {
        classifyOut->actionType = FWP_ACTION_CONTINUE;
    }

    if (layerData)
    {
        ProcessTransportData(inFixedValues, inMetaValues, layerData, classifyOut);
    }

    // Callout function should clear the FWPS_RIGHT_ACTION_WRITE flag when it returns FWP_ACTION_BLOCK for the suggested action
    // and if FWPS_FILTER_FLAG_CLEAR_ACTION_RIGHT flag is set
    if (FWP_ACTION_BLOCK == classifyOut->actionType || FlagOn(filter->flags, FWPS_FILTER_FLAG_CLEAR_ACTION_RIGHT))
    {
        ClearFlag(classifyOut->rights, FWPS_RIGHT_ACTION_WRITE);
    }
}

static NTSTATUS CalloutNotifyFn(
    FWPS_CALLOUT_NOTIFY_TYPE /*notifyType*/,
    const GUID* /*filterKey*/,
    FWPS_FILTER0* /*filter*/)
{
    return STATUS_SUCCESS;
}

static NTSTATUS InitializeCallout(PDEVICE_OBJECT deviceObject)
{
    FWPM_SUBLAYER subLayer = {};
    subLayer.displayData.name = const_cast<wchar_t*>(L"TcpInterception Sub-Layer");
    subLayer.subLayerKey = TCP_INTERCEPTION_SUBLAYER;

    NTSTATUS status = FwpmSubLayerAdd(g_engineHandle, &subLayer, nullptr);
    if (!NT_SUCCESS(status))
    {
        return status;
    }

    FWPS_CALLOUT0 sCallout =
    {
        TCP_INTERCEPTION_OUTBOUND_TRANSPORT_V4_CALLOUT,
        0,
        CalloutConnectClassifyFn,
        CalloutNotifyFn,
        nullptr
    };

    status = FwpsCalloutRegister0(deviceObject, &sCallout, &g_id);
    if (!NT_SUCCESS(status))
    {
        return status;
    }

    FWPM_CALLOUT mCallout = {};
    mCallout.calloutKey = TCP_INTERCEPTION_OUTBOUND_TRANSPORT_V4_CALLOUT;
    mCallout.applicableLayer = FWPM_LAYER_OUTBOUND_TRANSPORT_V4;
    mCallout.displayData.name = const_cast<wchar_t*>(g_displayName);

    status = FwpmCalloutAdd(g_engineHandle, &mCallout, nullptr, nullptr);
    if (!NT_SUCCESS(status))
    {
        return status;
    }

    // Add Filter for TCP only
    FWPM_FILTER_CONDITION filterCondition = {};
    filterCondition.fieldKey = FWPM_CONDITION_IP_PROTOCOL;
    filterCondition.matchType = FWP_MATCH_EQUAL;
    filterCondition.conditionValue.type = FWP_UINT8;
    filterCondition.conditionValue.uint16 = IPPROTO_TCP;

    FWPM_FILTER filter = {};
    filter.layerKey = FWPM_LAYER_OUTBOUND_TRANSPORT_V4;
    filter.displayData.name = const_cast<wchar_t*>(g_displayName);;
    filter.displayData.description = filter.displayData.name;

    filter.action.type = FWP_ACTION_CALLOUT_UNKNOWN;
    filter.action.calloutKey = TCP_INTERCEPTION_OUTBOUND_TRANSPORT_V4_CALLOUT;
    filter.filterCondition = &filterCondition;
    filter.numFilterConditions = 1;
    filter.subLayerKey = FWPM_SUBLAYER_UNIVERSAL;
    filter.weight.type = FWP_EMPTY;

    status = FwpmFilterAdd(g_engineHandle, &filter, NULL, NULL);
    if (!NT_SUCCESS(status))
    {
        return status;
    }

    status = FwpsInjectionHandleCreate(AF_UNSPEC, 0, &g_injectionHandle);
    if (!NT_SUCCESS(status))
    {
        return status;
    }

    return status;
}

NTSTATUS InitializeFilter(PDEVICE_OBJECT deviceObject)
{
    FWPM_SESSION session = {};
    session.flags = FWPM_SESSION_FLAG_DYNAMIC;

    NTSTATUS status = FwpmEngineOpen(nullptr, RPC_C_AUTHN_WINNT, nullptr, &session, &g_engineHandle);
    if (!NT_SUCCESS(status))
    {
        return status;
    }

    // Need to allocate NET_BUFFER_LIST pool to create NET_BUFFER_LISTs for new packets
    NET_BUFFER_LIST_POOL_PARAMETERS netBufferListParameters = {};
    netBufferListParameters.Header.Type = NDIS_OBJECT_TYPE_DEFAULT;
    netBufferListParameters.Header.Revision = NET_BUFFER_LIST_POOL_PARAMETERS_REVISION_1;
    netBufferListParameters.Header.Size = NDIS_SIZEOF_NET_BUFFER_LIST_POOL_PARAMETERS_REVISION_1;
    netBufferListParameters.ProtocolId = NDIS_PROTOCOL_ID_DEFAULT;
    netBufferListParameters.PoolTag = 'IpcT';
    // NdisAllocateNetBufferAndNetBufferList can be called only if fAllocateNetBuffer is TRUE and DataSize is zero.
    netBufferListParameters.DataSize = 0;
    netBufferListParameters.fAllocateNetBuffer = TRUE;

    g_netBufferListHandle = NdisAllocateNetBufferListPool(nullptr, &netBufferListParameters);
    if (!g_netBufferListHandle)
    {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    status = FwpmTransactionBegin(g_engineHandle, 0);
    if (!NT_SUCCESS(status))
    {
        return status;
    }

    status = InitializeCallout(deviceObject);
    if (NT_SUCCESS(status))
    {
        FwpmTransactionCommit(g_engineHandle);
    }
    else
    {
        FwpmTransactionAbort(g_engineHandle);
    }

    return status;
}

void DeinitializeFilter()
{
    if (g_id)
    {
        FwpsCalloutUnregisterById(g_id);
    }

    if (g_injectionHandle)
    {
        FwpsInjectionHandleDestroy(g_injectionHandle);
    }

    if (g_netBufferListHandle)
    {
        NdisFreeNetBufferListPool(g_netBufferListHandle);
    }

    if (g_engineHandle)
    {
        FwpmEngineClose(g_engineHandle);
        g_engineHandle = nullptr;
    }
}