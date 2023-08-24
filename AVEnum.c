/*
Basic program that enumerates A/V process currently running on the system
For now it prints A/V names, but will add functionality that will quit if any A/V is detected
*/
#include<stdio.h>
#include<Windows.h>
#include<tlhelp32.h>
#include<stdbool.h>
#pragma warning(disable: 4996) // needed to use GetVersionExW since it's a deprecated windows function 
BOOL found = 0; //used in the FindFileT function. Makes it easy to track if the file is found since it's a recurisve function 
typedef enum AVType {DEFENDER, AVIRA, MCAFEE, KASPERSKY, NONE} AVType;

//start typedef for MPClient.h, there is no offcial header file so I have to rip it off MSDN
typedef struct tagMPCOMPONENT_VERSION {
	ULONGLONG      Version;
	ULARGE_INTEGER UpdateTime;
} MPCOMPONENT_VERSION, * PMPCOMPONENT_VERSION;

typedef struct tagMPVERSION_INFO {
	MPCOMPONENT_VERSION Product;
	MPCOMPONENT_VERSION Service;
	MPCOMPONENT_VERSION FileSystemFilter;
	MPCOMPONENT_VERSION Engine;
	MPCOMPONENT_VERSION ASSignature;
	MPCOMPONENT_VERSION AVSignature;
	MPCOMPONENT_VERSION NISEngine;
	MPCOMPONENT_VERSION NISSignature;
	MPCOMPONENT_VERSION Reserved[4];
} MPVERSION_INFO, * PMPVERSION_INFO;

// Definitions for MpManager functions , so I can call them via GetProcAddress
typedef HRESULT(WINAPI* PFN_MpManagerOpen)(
	_In_  DWORD     dwReserved,
	_Out_ HANDLE* phMpMgr
	);

typedef HRESULT(WINAPI* PFN_MpManagerStatusQuery)(
	_In_ HANDLE hMpMgr,
	_Out_ PMPVERSION_INFO pVersionInfo
	);

typedef HRESULT(WINAPI* PFN_MpHandleClose)(
	_In_ HANDLE hMpHandle
	);

//struct where I will store the system information like major,minor,build, and revision number
typedef struct SysInfo {
	DWORD majorVersion; 
	DWORD minorVersion;
	DWORD buildNumber;
	DWORD revisionNumber;
	WCHAR defenderVersion[MAX_PATH];
}SysInfo;

//This will be used in the later function to find the MpClient.dll on a host machine. The version folder changes,
//thus using a search function to look for it
void findFileT(const wchar_t* directory, const wchar_t* targetFile, wchar_t* f) {
	wchar_t* theFile = (wchar_t*)malloc(sizeof(wchar_t) * MAX_PATH);

	wchar_t query[MAX_PATH];
	WIN32_FIND_DATA data;
	swprintf(query, MAX_PATH, L"%s%s", directory, L"\\*\0");
	//printf("Query should be: %ls\n",query);
	HANDLE findFile = FindFirstFileW(query, &data);
	if (findFile == INVALID_HANDLE_VALUE) {
		//  printf("FindFirstFile failed (%d)\n", GetLastError());
		return;
	}
	do {
		if (wcscmp(data.cFileName, L".") == 0 || wcscmp(data.cFileName, L"..") == 0) {
			continue;
		}
		wchar_t subDir[MAX_PATH];
		swprintf(subDir, MAX_PATH, L"%s\\%s", directory, data.cFileName);// --> errors out here, find out why
		if (wcscmp(targetFile, data.cFileName) == 0) {
			found = 1;
			wcscpy_s(f, MAX_PATH, subDir);
			return;

		}
		else {
			if (!found) {
				findFileT(subDir, targetFile, f);
			}
			else {
				return;
			}
		}
	} while (FindNextFile(findFile, &data));
	FindClose(findFile);

	return;
}

//will enumerate the windows defender version 
void enumerateDefenderClientVer(SysInfo *d) {

	wchar_t loadMpClient[MAX_PATH];
	findFileT(L"C:\\ProgramData\\Microsoft\\Windows Defender", L"MpClient.dll", loadMpClient);
	HMODULE hModule = LoadLibrary(loadMpClient);
	//HMODULE hModule = LoadLibrary(L"C:\\ProgramData\\Microsoft\\Windows Defender\\Platform\\4.18.23070.1004-0\\MpClient.dll");
	if (hModule)
	{
		PFN_MpManagerOpen pfnMpManagerOpen = (PFN_MpManagerOpen)GetProcAddress(hModule, "MpManagerOpen");
		PFN_MpManagerStatusQuery pfnManagerVersionQuery = (PFN_MpManagerStatusQuery)GetProcAddress(hModule, "MpManagerVersionQuery");
		PFN_MpHandleClose pfnManager = (PFN_MpHandleClose)GetProcAddress(hModule, "MpHandleClose");
		if (pfnMpManagerOpen && pfnManagerVersionQuery)
		{
			HANDLE hMpMgr = NULL;
			HRESULT hr = pfnMpManagerOpen(0, &hMpMgr);
			if (hr == S_OK)
			{
				MPVERSION_INFO dwVersion;
				hr = pfnManagerVersionQuery(hMpMgr, &dwVersion);
				if (hr == 0){
					DWORD major = ((dwVersion.Product.Version) >> 48) & 0xFFFF;
					DWORD minor = ((dwVersion.Product.Version) >> 32) & 0xFFFF;
					DWORD build = ((dwVersion.Product.Version) >> 16) & 0xFFFF;
					DWORD revesion = ((dwVersion.Product.Version)) & 0xFFFF;
					//printf("Windows Defender Version: %d.%d.%d.%d\n", major, minor, build, revesion);
					swprintf(d->defenderVersion, MAX_PATH, L"Windows Defender Version: %d.%d.%d.%d", major, minor, build, revesion);
				}
				else{
					printf("MpManagerStatusQuery failed with HRESULT 0x%08X\n", hr);
				}

				// Close the MpManager handle
				pfnManager(hMpMgr);
			}
			else{
				printf("MpManagerOpen failed with HRESULT 0x%08X\n", hr);
			}
		}
		else{
			printf("Failed to find MpManagerOpen and/or MpManagerStatusQuery functions in MpClient.dll\n");
		}

		FreeLibrary(hModule);
	}
	else
	{
		printf("Failed to load MpClient.dll\n");
	}
}

void getWindowsVersion(SysInfo *p) {
	OSVERSIONINFOEXW myOS;
	myOS.dwOSVersionInfoSize = sizeof(OSVERSIONINFOEX);
	//ZeroMemory(&myOS, sizeof(OSVERSIONINFOEX));
	if ((GetVersionEx((OSVERSIONINFOEX *)&myOS)) !=0 ) {
		p->majorVersion = myOS.dwMajorVersion;
		p->minorVersion = myOS.dwMinorVersion;
		p->buildNumber = myOS.dwBuildNumber;
		p->revisionNumber = myOS.wServicePackMajor;
		
	}
	else {
		printf("GetVersionExW() failed!, GetLastError() = %d \n", GetLastError());
	}
}

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
		SysInfo myInfo;
		enumerateDefenderClientVer(&myInfo);
		getWindowsVersion(&myInfo);
		wprintf(L"[+]%s\n[+]Build of OS(major,minor,build,revision): %d.%d.%d.%d",myInfo.defenderVersion,myInfo.majorVersion,myInfo.minorVersion,
				myInfo.buildNumber, myInfo.revisionNumber);
		break;
	case AVIRA:
		printf("[+] Found Avira running on the system!\n");
		break;
	case MCAFEE:
		printf("[+] Found McAfee running on the system!\n");
		break;
	case KASPERSKY:
		printf("[+] Found Kaspersky running on the system!\n");
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
			case 1238830108: //avp.exe = Kaspersky anti virus
				*def = KASPERSKY;
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