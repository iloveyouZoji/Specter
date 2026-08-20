// Specter - Dynamic API Resolution Framework
// Runtime function lookup via PEB/module walking

#include <windows.h>
#include <winternl.h>
#include <stdint.h>
#include <stdio.h>

// ─────────────────────────────────────────────
//  Hashing - djb2 variant, compile-time friendly
// ─────────────────────────────────────────────

constexpr uint32_t SPECTER_SEED = 0x1337CAFE;

inline uint32_t specter_hash(const char* str) {
    uint32_t h = SPECTER_SEED;
    while (*str) {
        h = ((h << 5) + h) ^ (uint8_t)*str++;
    }
    return h;
}

// Pre-hashed targets (no plaintext strings at import time)
constexpr uint32_t HASH_LoadLibraryA       = specter_hash("LoadLibraryA");
constexpr uint32_t HASH_GetProcAddress     = specter_hash("GetProcAddress");
constexpr uint32_t HASH_VirtualAlloc       = specter_hash("VirtualAlloc");
constexpr uint32_t HASH_VirtualProtect     = specter_hash("VirtualProtect");
constexpr uint32_t HASH_CreateThread       = specter_hash("CreateThread");
constexpr uint32_t HASH_OpenProcess        = specter_hash("OpenProcess");
constexpr uint32_t HASH_WriteProcessMemory = specter_hash("WriteProcessMemory");
constexpr uint32_t HASH_CloseHandle        = specter_hash("CloseHandle");

// ─────────────────────────────────────────────
//  PEB walking to get module base
// ─────────────────────────────────────────────

inline HMODULE specter_get_module_base(uint32_t module_hash) {
#ifdef _WIN64
    PEB* peb = (PEB*)__readgsqword(0x60);
#else
    PEB* peb = (PEB*)__readfsdword(0x30);
#endif

    PEB_LDR_DATA* ldr = peb->Ldr;
    LIST_ENTRY* head  = &ldr->InMemoryOrderModuleList;
    LIST_ENTRY* entry = head->Flink;

    while (entry != head) {
        LDR_DATA_TABLE_ENTRY* mod = CONTAINING_RECORD(
            entry, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks
        );

        if (mod->FullDllName.Buffer && mod->DllBase) {
            // Convert wide module name to narrow for hashing
            WCHAR* wname = mod->FullDllName.Buffer;
            char   narrow[256] = {};
            int    i = 0;

            // Grab just the filename portion after last backslash
            int last_slash = -1;
            for (int j = 0; wname[j]; j++)
                if (wname[j] == L'\\' || wname[j] == L'/') last_slash = j;

            WCHAR* fname = wname + last_slash + 1;

            // To lowercase narrow
            for (; fname[i] && i < 255; i++) {
                narrow[i] = (char)(fname[i] >= L'A' && fname[i] <= L'Z'
                                   ? fname[i] + 32
                                   : fname[i]);
            }
            narrow[i] = '\0';

            if (specter_hash(narrow) == module_hash)
                return (HMODULE)mod->DllBase;
        }
        entry = entry->Flink;
    }
    return nullptr;
}

// ─────────────────────────────────────────────
//  Export table walking to resolve function
// ─────────────────────────────────────────────

inline void* specter_resolve(HMODULE base, uint32_t func_hash) {
    if (!base) return nullptr;

    uint8_t* raw = (uint8_t*)base;

    IMAGE_DOS_HEADER*  dos = (IMAGE_DOS_HEADER*)raw;
    IMAGE_NT_HEADERS*  nt  = (IMAGE_NT_HEADERS*)(raw + dos->e_lfanew);

    DWORD export_rva = nt->OptionalHeader
                         .DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT]
                         .VirtualAddress;
    if (!export_rva) return nullptr;

    IMAGE_EXPORT_DIRECTORY* exp =
        (IMAGE_EXPORT_DIRECTORY*)(raw + export_rva);

    DWORD*  names    = (DWORD*) (raw + exp->AddressOfNames);
    WORD*   ordinals = (WORD*)  (raw + exp->AddressOfNameOrdinals);
    DWORD*  funcs    = (DWORD*) (raw + exp->AddressOfFunctions);

    for (DWORD i = 0; i < exp->NumberOfNames; i++) {
        const char* name = (const char*)(raw + names[i]);
        if (specter_hash(name) == func_hash) {
            DWORD fn_rva = funcs[ordinals[i]];
            return (void*)(raw + fn_rva);
        }
    }
    return nullptr;
}

// ─────────────────────────────────────────────
//  Specter context - resolved function table
// ─────────────────────────────────────────────

struct SpecterCtx {
    // Typedefs
    using fn_LoadLibraryA       = HMODULE  (WINAPI*)(LPCSTR);
    using fn_GetProcAddress     = FARPROC  (WINAPI*)(HMODULE, LPCSTR);
    using fn_VirtualAlloc       = LPVOID   (WINAPI*)(LPVOID, SIZE_T, DWORD, DWORD);
    using fn_VirtualProtect     = BOOL     (WINAPI*)(LPVOID, SIZE_T, DWORD, PDWORD);
    using fn_CreateThread       = HANDLE   (WINAPI*)(LPSECURITY_ATTRIBUTES, SIZE_T,
                                                     LPTHREAD_START_ROUTINE,
                                                     LPVOID, DWORD, LPDWORD);
    using fn_OpenProcess        = HANDLE   (WINAPI*)(DWORD, BOOL, DWORD);
    using fn_WriteProcessMemory = BOOL     (WINAPI*)(HANDLE, LPVOID,
                                                     LPCVOID, SIZE_T, SIZE_T*);
    using fn_CloseHandle        = BOOL     (WINAPI*)(HANDLE);

    fn_LoadLibraryA       LoadLibraryA       = nullptr;
    fn_GetProcAddress     GetProcAddress     = nullptr;
    fn_VirtualAlloc       VirtualAlloc       = nullptr;
    fn_VirtualProtect     VirtualProtect     = nullptr;
    fn_CreateThread       CreateThread       = nullptr;
    fn_OpenProcess        OpenProcess        = nullptr;
    fn_WriteProcessMemory WriteProcessMemory = nullptr;
    fn_CloseHandle        CloseHandle        = nullptr;

    bool ready = false;
};

// ─────────────────────────────────────────────
//  Initialization
// ─────────────────────────────────────────────

static SpecterCtx g_specter;

bool specter_init() {
    // kernel32.dll hash at call time, not link time
    constexpr uint32_t H_KERNEL32 = specter_hash("kernel32.dll");

    HMODULE k32 = specter_get_module_base(H_KERNEL32);
    if (!k32) return false;

    #define SPECTER_BIND(ctx, mod, name) \
        ctx.name = (SpecterCtx::fn_##name) specter_resolve(mod, HASH_##name); \
        if (!ctx.name) return false;

    SPECTER_BIND(g_specter, k32, LoadLibraryA);
    SPECTER_BIND(g_specter, k32, GetProcAddress);
    SPECTER_BIND(g_specter, k32, VirtualAlloc);
    SPECTER_BIND(g_specter, k32, VirtualProtect);
    SPECTER_BIND(g_specter, k32, CreateThread);
    SPECTER_BIND(g_specter, k32, OpenProcess);
    SPECTER_BIND(g_specter, k32, WriteProcessMemory);
    SPECTER_BIND(g_specter, k32, CloseHandle);

    #undef SPECTER_BIND

    g_specter.ready = true;
    return true;
}

// ─────────────────────────────────────────────
//  Convenience accessor (post-init calls)
// ─────────────────────────────────────────────

inline SpecterCtx& specter() {
    return g_specter;
}

// ─────────────────────────────────────────────
//  Demo main
// ─────────────────────────────────────────────

int main() {
    if (!specter_init()) {
        printf("[specter] resolution failed\n");
        return 1;
    }

    printf("[specter] all functions resolved at runtime\n");
    printf("  LoadLibraryA       -> %p\n", (void*)specter().LoadLibraryA);
    printf("  GetProcAddress     -> %p\n", (void*)specter().GetProcAddress);
    printf("  VirtualAlloc       -> %p\n", (void*)specter().VirtualAlloc);
    printf("  VirtualProtect     -> %p\n", (void*)specter().VirtualProtect);
    printf("  CreateThread       -> %p\n", (void*)specter().CreateThread);
    printf("  OpenProcess        -> %p\n", (void*)specter().OpenProcess);
    printf("  WriteProcessMemory -> %p\n", (void*)specter().WriteProcessMemory);
    printf("  CloseHandle        -> %p\n", (void*)specter().CloseHandle);

    // Example: use resolved VirtualAlloc without ever importing it
    LPVOID buf = specter().VirtualAlloc(
        nullptr, 4096,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE
    );
    printf("  VirtualAlloc buf   -> %p\n", buf);

    if (buf) specter().VirtualProtect(buf, 4096, PAGE_NOACCESS, nullptr);

    return 0;
}
