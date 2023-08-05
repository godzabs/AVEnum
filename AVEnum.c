#include<stdio.h>
#include<Windows.h>
#include<tlhelp32.h>

typedef enum AVType {DEFENDER, AVIRA, MCAFEE, NONE} AVType;

//hash ExeName's to switch/case process name
//using djb2 hash, hash *33 + c(int val of char)
unsigned long hash(wchar_t* str) {
	unsigned long hash = 5381;
	int c;
	while (c = *str++) {
		hash = ((hash << 5) + hash) + c;

	}
	return hash;
}


void printAVType(AVType *av) {
	switch (*av) {
	case DEFENDER:
		printf("[+] Found Windows Defender on the system!\n");
		break;
	case AVIRA:
		printf("[+] Found Avira running on the system!\n");
		break;
	case MCAFEE:
		printf("[+] Found McAfee running on the system!\n");
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
	unsigned long hashVal = 0;
	do {
		hashVal = hash(proc.szExeFile);

		switch (hashVal) {
			case 112412172: //MsMpEng.exe = Defender
				*def = DEFENDER;
				break;
			case 4146825939: //Avira.Spotlight.Service.exe = Avira
				*def = AVIRA;
				break;
			case 3201222415: //masvc.exe = McAfee user agent
				*def = MCAFEE;
				break;
			default:
				break;
		}

		
	} while (Process32Next(hProc, &proc));

	CloseHandle(hProc);
}

int main(void) {
	AVType myAV;
	enumerateAV(&myAV);
	printAVType(&myAV);
	getchar();
	getchar();
	return EXIT_SUCCESS;
}