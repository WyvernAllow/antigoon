#include <Windows.h>

#include <cstdlib>
#include <fstream>
#include <iostream>
#include <string>
#include <unordered_set>

typedef NTSTATUS(NTAPI* pdef_NtRaiseHardError)(
    NTSTATUS err_stat, ULONG num_params, ULONG unicode_mask OPTIONAL,
    PULONG_PTR params, ULONG response_option, PULONG response);

typedef NTSTATUS(NTAPI* pdef_RtlAdjustPrivilege)(ULONG privilege,
                                                 BOOLEAN enable,
                                                 BOOLEAN current_thread,
                                                 PBOOLEAN enabled);

static std::string get_last_error_string() {
    DWORD id = GetLastError();
    if (id == 0) {
        return "No error";
    }

    LPSTR msg_buffer = nullptr;
    size_t size = FormatMessageA(
        FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM |
            FORMAT_MESSAGE_IGNORE_INSERTS,
        nullptr, id, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
        (LPSTR)&msg_buffer, 0, nullptr);

    std::string message(msg_buffer, size);

    LocalFree(msg_buffer);

    return message;
}

static void raise_hard_error() {
    HMODULE ntdll = LoadLibraryA("ntdll.dll");
    if (!ntdll) {
        std::cerr << "LoadLibraryA failed. Could not load ntdll.dll: "
                  << get_last_error_string() << std::endl;
        exit(EXIT_FAILURE);
    }

    LPVOID adjust_privilege_addr = GetProcAddress(ntdll, "RtlAdjustPrivilege");
    if (!adjust_privilege_addr) {
        std::cerr << "GetProcAddress failed. Could not find address of "
                     "RtlAdjustPrivilege: "
                  << get_last_error_string() << std::endl;
        exit(EXIT_FAILURE);
    }

    HMODULE ntdll_handle = GetModuleHandle("ntdll.dll");
    if (!ntdll_handle) {
        std::cerr << "GetModuleHandle failed. Could not load ntdll.dll: "
                  << get_last_error_string() << std::endl;
        exit(EXIT_FAILURE);
    }

    LPVOID raise_hard_error_addr =
        GetProcAddress(ntdll_handle, "NtRaiseHardError");
    if (!raise_hard_error_addr) {
        std::cerr << "GetProcAddress failed. Could not find address of "
                     "NtRaiseHardError: "
                  << get_last_error_string() << std::endl;
        exit(EXIT_FAILURE);
    }

    pdef_RtlAdjustPrivilege rtl_adjust_privilege =
        (pdef_RtlAdjustPrivilege)adjust_privilege_addr;

    pdef_NtRaiseHardError nt_raise_hard_error =
        (pdef_NtRaiseHardError)raise_hard_error_addr;

    BOOLEAN enabled;
    NTSTATUS adjust_status = rtl_adjust_privilege(19, TRUE, FALSE, &enabled);
    if (adjust_status != 0) {
        std::cout << "Failed to adjust privilege: NTSTATUS: 0x" << std::hex
                  << adjust_status << std::endl;
        exit(EXIT_FAILURE);
    }

    ULONG resp;
    NTSTATUS hard_err_status =
        nt_raise_hard_error(STATUS_FLOAT_MULTIPLE_FAULTS, 0, 0, 0, 6, &resp);
    if (hard_err_status != 0) {
        std::cout << "Failed to raise hard error: NTSTATUS: 0x" << std::hex
                  << adjust_status << std::endl;
        exit(EXIT_FAILURE);
    }
}

static HHOOK keyboard_hook;
static std::string last_word;
static std::unordered_set<std::string> blacklist;

static void load_blacklist(const std::string& filename) {
    std::ifstream file(filename);
    if (!file.is_open()) {
        std::cerr << "Failed to load blacklist from " << filename << std::endl;
        exit(EXIT_FAILURE);
    }

    std::string line;
    while (std::getline(file, line)) {
        if (line.starts_with("#")) {
            continue;
        }

        blacklist.insert(line);
    }
}

static LRESULT CALLBACK keyboard_proc(int n_code, WPARAM w_param,
                                      LPARAM l_param) {
    if (n_code != HC_ACTION) {
        return CallNextHookEx(keyboard_hook, n_code, w_param, l_param);
    }

    KBDLLHOOKSTRUCT* keyboard = reinterpret_cast<KBDLLHOOKSTRUCT*>(l_param);
    if (w_param == WM_KEYDOWN || w_param == WM_SYSKEYDOWN) {
        BYTE keyboard_state[256];
        if (!GetKeyboardState(keyboard_state)) {
            std::cerr << "GetKeyboardState failed: " << get_last_error_string()
                      << std::endl;
            exit(EXIT_FAILURE);
            return CallNextHookEx(keyboard_hook, n_code, w_param, l_param);
        }

        if (keyboard->vkCode == VK_BACK) {
            if (last_word.size() > 0) {
                last_word.pop_back();
            }
        }

        UINT scancode = MapVirtualKey(keyboard->vkCode, MAPVK_VK_TO_VSC);
        CHAR ascii_char[2] = {};

        if (ToAscii(keyboard->vkCode, scancode, keyboard_state,
                    reinterpret_cast<LPWORD>(ascii_char), 0) == 1) {
            char c = ascii_char[0];

            if (std::isspace(c)) {
                if (blacklist.contains(last_word)) {
                    std::cout << "Found blacklisted word: " << last_word;
                    raise_hard_error();
                }
                last_word.clear();
            } else {
                last_word.push_back(c);
            }
        }
    }

    return CallNextHookEx(keyboard_hook, n_code, w_param, l_param);
}

int main(int argc, char* argv[]) {
    keyboard_hook = SetWindowsHookEx(WH_KEYBOARD_LL, keyboard_proc, NULL, 0);
    if (!keyboard_hook) {
        std::cerr << "Failed to install hook: " << get_last_error_string()
                  << std::endl;
        return EXIT_FAILURE;
    }

    std::string filename;
    if (argc > 1) {
        filename = argv[1];
    } else {
        filename = "blacklist.txt";
    }

    load_blacklist(filename);

    MSG msg;
    while (GetMessage(&msg, NULL, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }

    UnhookWindowsHookEx(keyboard_hook);
    return EXIT_SUCCESS;
}