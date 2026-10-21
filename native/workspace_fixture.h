/* Synthetic FreeRDP Sample server extension, TEST ONLY. Not in the runtime.
 * Uses upstream public server APIs to observe actual Unicode clipboard and
 * display-control PDUs. Only fixed markers reach the Go parent, never text. */
#include <freerdp/server/cliprdr.h>
#include <freerdp/server/disp.h>
#include <winpr/clipboard.h>
#include <winpr/interlocked.h>

static const WCHAR kb_remote_text[] = {'R','e','m','o','t','e',' ',0x018f,'z',0x0259,'r','b','a','y','c','a','n',' ',0xd83d,0xdd11,0};
static const WCHAR kb_local_text[] = {'L','o','c','a','l',' ',0x018f,'z',0x0259,'r','b','a','y','c','a','n',' ',0xd83d,0xdd11,10,'l','i','n','e',0};

static UINT kb_clip_capabilities(CliprdrServerContext* ctx, const CLIPRDR_CAPABILITIES* caps) {
    (void)caps;
    CLIPRDR_FORMAT format = {.formatId = CF_UNICODETEXT, .formatName = NULL};
    CLIPRDR_FORMAT_LIST list = {0};
    list.numFormats = 1; list.formats = &format;
    return ctx->ServerFormatList(ctx, &list);
}
static UINT kb_clip_formats(CliprdrServerContext* ctx, const CLIPRDR_FORMAT_LIST* list) {
    CLIPRDR_FORMAT_LIST_RESPONSE response = {0};
    response.common.msgFlags = CB_RESPONSE_OK;
    UINT rc = ctx->ServerFormatListResponse(ctx, &response);
    if (rc) return rc;
    for (UINT32 i=0;i<list->numFormats;i++) if (list->formats[i].formatId == CF_UNICODETEXT) {
        CLIPRDR_FORMAT_DATA_REQUEST request = {0};
        request.requestedFormatId = CF_UNICODETEXT;
        return ctx->ServerFormatDataRequest(ctx, &request);
    }
    return CHANNEL_RC_OK;
}
static UINT kb_clip_response(CliprdrServerContext* ctx, const CLIPRDR_FORMAT_DATA_RESPONSE* response) {
    (void)ctx;
    if (response->common.msgFlags == CB_RESPONSE_OK && response->common.dataLen == sizeof(kb_local_text) &&
        response->requestedFormatData && memcmp(response->requestedFormatData,kb_local_text,sizeof(kb_local_text))==0) {
        puts("KB_CLIPBOARD_LOCAL"); fflush(stdout);
    }
    return CHANNEL_RC_OK;
}
static UINT kb_clip_request(CliprdrServerContext* ctx, const CLIPRDR_FORMAT_DATA_REQUEST* request) {
    CLIPRDR_FORMAT_DATA_RESPONSE response = {0};
    if (request->requestedFormatId != CF_UNICODETEXT) return ERROR_INVALID_DATA;
    response.common.msgFlags = CB_RESPONSE_OK;
    response.common.dataLen = sizeof(kb_remote_text);
    response.requestedFormatData = (const BYTE*)kb_remote_text;
    return ctx->ServerFormatDataResponse(ctx,&response);
}
static UINT kb_disp_layout(DispServerContext* ctx, const DISPLAY_CONTROL_MONITOR_LAYOUT_PDU* pdu) {
    testPeerContext* peer = (testPeerContext*)ctx->custom;
    if (pdu->NumMonitors != 1 || !pdu->Monitors) return ERROR_INVALID_DATA;
    const DISPLAY_CONTROL_MONITOR_LAYOUT* monitor = &pdu->Monitors[0];
    if (monitor->Width<64 || monitor->Width>1920 || monitor->Height<64 || monitor->Height>1080) return ERROR_INVALID_DATA;
    LONG64 size = ((LONG64)monitor->Width<<32) | monitor->Height;
    InterlockedExchange64(&peer->kb_size,size);
    return SetEvent(peer->kb_resize_event) ? CHANNEL_RC_OK : ERROR_INTERNAL_ERROR;
}
static BOOL kb_workspace_start(freerdp_peer* client) {
    testPeerContext* peer = (testPeerContext*)client->context;
    if (WTSVirtualChannelManagerIsChannelJoined(peer->vcm,"cliprdr") && !peer->kb_clip) {
        peer->kb_clip=cliprdr_server_context_new(peer->vcm);
        if (!peer->kb_clip) return FALSE;
        peer->kb_clip->rdpcontext=client->context;
        peer->kb_clip->ClientCapabilities=kb_clip_capabilities;
        peer->kb_clip->ClientFormatList=kb_clip_formats;
        peer->kb_clip->ClientFormatDataRequest=kb_clip_request;
        peer->kb_clip->ClientFormatDataResponse=kb_clip_response;
        peer->kb_clip->streamFileClipEnabled=FALSE;
        peer->kb_clip->canLockClipData=FALSE;
        if (peer->kb_clip->Start(peer->kb_clip)!=CHANNEL_RC_OK) return FALSE;
    }
    return TRUE;
}
static BOOL kb_workspace_events(freerdp_peer* client) {
    testPeerContext* peer=(testPeerContext*)client->context;
    if (WTSVirtualChannelManagerGetDrdynvcState(peer->vcm)==DRDYNVC_STATE_READY) {
        if (!peer->kb_disp) {
            peer->kb_disp=disp_server_context_new(peer->vcm);
            if (!peer->kb_disp) return FALSE;
            peer->kb_disp->rdpcontext=client->context; peer->kb_disp->custom=peer;
            peer->kb_disp->MaxNumMonitors=1;peer->kb_disp->MaxMonitorAreaFactorA=1920;peer->kb_disp->MaxMonitorAreaFactorB=1080;
            peer->kb_disp->DispMonitorLayout=kb_disp_layout;
            if (peer->kb_disp->Open(peer->kb_disp)!=CHANNEL_RC_OK) return FALSE;
        }
        if (!peer->kb_caps_sent && peer->kb_disp->DisplayControlCaps(peer->kb_disp)==CHANNEL_RC_OK) peer->kb_caps_sent=TRUE;
    }
    LONG64 size=InterlockedExchange64(&peer->kb_size,0);
    if (size) {
        UINT32 width=(UINT32)((UINT64)size>>32),height=(UINT32)size;
        if (!freerdp_settings_set_uint32(client->context->settings,FreeRDP_DesktopWidth,width) ||
            !freerdp_settings_set_uint32(client->context->settings,FreeRDP_DesktopHeight,height) ||
            !rfx_context_reset(peer->rfx_context,width,height) ||
            !client->context->update->DesktopResize(client->context->update->context)) return FALSE;
        peer->activated=FALSE;
        if (width==1280 && height==720) {puts("KB_DESKTOP_RESIZED");fflush(stdout);}
    }
    return TRUE;
}
static void kb_workspace_free(testPeerContext* peer) {
    if (peer->kb_clip) {peer->kb_clip->Stop(peer->kb_clip);cliprdr_server_context_free(peer->kb_clip);peer->kb_clip=NULL;}
    if (peer->kb_disp) {UINT rc=peer->kb_disp->Close(peer->kb_disp);(void)rc;disp_server_context_free(peer->kb_disp);peer->kb_disp=NULL;}
    if (peer->kb_resize_event) {(void)CloseHandle(peer->kb_resize_event);peer->kb_resize_event=NULL;}
}
