#include<stdio.h>
#include<Windows.h>
#include<tlhelp32.h>

typedef enum AVType {DEFENDER, NONE} AVType;

void printAVType(AVType *av) {
	switch (*av) {
	case DEFENDER:
		printf("[+] Found Windows Defender on the system!\n");
		break;
	default:
		printf("[-] Somehow no anti-virus is running on the system\n");
		break;

	}
}

void enumerateAV(AVType *def) {
	HANDLE hProc = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	PROCESSENTRY32 proc;
	proc.dwSize = sizeof(proc);
	Process32First(hProc, &proc);

	do {
		
		if (wcscmp(proc.szExeFile, L"MsMpEng.exe") == 0) {
			*def = DEFENDER;
		}


	} while (Process32Next(hProc, &proc));

	CloseHandle(hProc);
}

int main(void) {
	AVType myAV;
	enumerateAV(&myAV);
	printAVType(&myAV);
}