#include <stdio.h>
#include <string.h>
#include <iostream> 
#include <string>
#include <winsock2.h> // include must before window.h
#include <iphlpapi.h>
#include <windows.h>  

#include <curl/curl.h>   

#pragma comment(lib, "iphlpapi.lib")



#pragma warning(disable: 4996) // avoid GetVersionEx to be warned 
using namespace std;

// ***** global macros ***** //
static const int kMaxInfoBuffer = 256;
#define  GBYTES  1073741824  
#define  MBYTES  1048576  
#define  KBYTES  1024  
#define  DKBYTES 1024.0  

char* prt(char c);
char* execIntro();
char* getOsInfo();
char* getCpuInfo();
char* getMemoryInfo();
char* getHardDiskInfo();
char* getNetworkInfo();
void usage_print();

int main() {

	// 初始化
	CURL *hnd = curl_easy_init();

	curl_easy_setopt(hnd, CURLOPT_CUSTOMREQUEST, "POST");
	curl_easy_setopt(hnd, CURLOPT_URL, "http://118.24.22.235:8080/upload");

	struct curl_slist *headers = NULL;
	headers = curl_slist_append(headers, "Authorization: Bearer I am a login token");
	headers = curl_slist_append(headers, "Content-Type: application/json");
	headers = curl_slist_append(headers, "accept: application/json");
	curl_easy_setopt(hnd, CURLOPT_HTTPHEADER, headers);


	FILE* log_fp = fopen("./log_result.txt", "w");
	char final_str[40000] = "";
	int flag = 0;
	char flag_buffer[5] = "";
	usage_print();
	printf("%s\n", "请输入您当前运行环境的代码：");
	printf("%s\n", "1. 物理环境");
	printf("%s\n", "2. VMware");
	printf("%s\n", "3. Virtual Box");
	printf("%s\n", "4. Parallel");
	printf("%s\n", "5. Xen");


	printf("============================请您输入:");
	scanf("%d", &flag);
	printf("%d\n", flag);
	itoa(flag, flag_buffer, 5);
	strcat(final_str, "execute environment: ");
	strcat(final_str, flag_buffer);
	strcat(final_str, "\n");

	printf("%s\n", flag_buffer);

	strcat(final_str, execIntro());
	strcat(final_str,getOsInfo());
	strcat(final_str, getCpuInfo());
	strcat(final_str, getMemoryInfo());
	strcat(final_str,getHardDiskInfo());
	strcat(final_str, getNetworkInfo());
	fprintf(log_fp, "%s",final_str);
	fclose(log_fp);

	curl_easy_setopt(hnd, CURLOPT_POSTFIELDS, final_str);
	CURLcode ret = curl_easy_perform(hnd);
	printf("ret0:%d\n", ret);
	LONG nHttpCode = 0;
	// 取下HTTP返回状态码(200为成功)
	ret = curl_easy_getinfo(hnd, CURLINFO_RESPONSE_CODE, &nHttpCode);
	printf("ret1:%d\n", ret);
	printf("nHttpCode:%d\n", nHttpCode);

	// 回收资源
	curl_easy_cleanup(hnd);

	Sleep(500);
	return 0;
}


void usage_print() {
	printf("%s\n", "================================================================================");
	printf("%s\n\n", "==================================声明==========================================");
	//printf("%s\n", "================================================================================");
	printf("%s\n", "1. 本程序仅用于实验数据收集，不涉及隐私数据，绝无恶意行为，收集到的信息仅用于实验使用。");
	printf("%s\n", "2. 为表明收集到的数据并无隐私信息，您可在当前程序运行的目录下看到log_result.txt文件，其文件内容与本人所收集到的数据一致。");
	printf("%s\n\n", "3. 如果可以的话，请分别在虚拟机和物理机中运行；如果您仍然顾虑安全问题，可以仅运行于虚拟机中。");
	printf("%s\n\n", "4. 如果可以的话，请分别在虚拟机和物理机中运行；如果您仍然顾虑安全问题，可以仅运行于虚拟机中。");
	printf("%s\n\n", "===============================感谢您的帮助=====================================");


}

char* prt(char c)
{
	int i;
	char result_str[70] = "";
	char flag[2]="";
	for (i = 7; i >= 0; i--) {
		printf("%d", (c & 1 << i) != 0);
		sprintf(flag, "%d", (c & 1 << i) != 0);
		strcat(result_str,flag);
	}
	printf(" ");
	return result_str;
}

// ---- get os info ---- //
char* getOsInfo()
{
	// get os name according to version number
	OSVERSIONINFO osver = { sizeof(OSVERSIONINFO) };
	GetVersionEx(&osver);
	char os_name[30] = "";
	char os_version[10] = "";
	char os_info[200] = "";
	//fprintf(log_fp, "%s", os_name);
	if (osver.dwMajorVersion == 5 && osver.dwMinorVersion == 0) {
		strcpy(os_name, "Windows 2000");
		strcpy(os_version, "5.0");
	}
	else if (osver.dwMajorVersion == 5 && osver.dwMinorVersion == 1) {
		strcpy(os_name, "Windows XP");
		strcpy(os_version, "5.1");
	}
	else if (osver.dwMajorVersion == 6 && osver.dwMinorVersion == 0) {
		strcpy(os_name, "Windows 2003");
		strcpy(os_version, "6.0");
	}
	else if (osver.dwMajorVersion == 5 && osver.dwMinorVersion == 2) {
		strcpy(os_name, "Windows vista");
		strcpy(os_version, "5.2");
	}
	else if (osver.dwMajorVersion == 6 && osver.dwMinorVersion == 1) {
		strcpy(os_name, "Windows 7");
		strcpy(os_version, "6.1");
	}
	else if (osver.dwMajorVersion == 6 && osver.dwMinorVersion == 2) {
		strcpy(os_name, "Windows 10");
		strcpy(os_version, "6.2");
	}
	strcat(os_info, "\n\nos name: ");
	strcat(os_info, os_name);
	strcat(os_info,"\n");

	strcat(os_info, "os version: ");
	strcat(os_info, os_version);
	strcat(os_info, "\n");
	printf("%s", os_info);

	return os_info;
}


// ---- get cpu info ---- //
#ifdef _WIN64

// method 2: usde winapi, works for x86 and x64
#include <intrin.h>
char* getCpuInfo()
{
	int cpuInfo[4] = { -1 };
	char cpu_manufacture[32] = { 0 };
	char cpu_type[100] = { 0 };
	char cpu_freq[100] = { 0 };
	char cpu_info[400] = { 0 };

	__cpuid(cpuInfo, 0x80000002);
	memcpy(cpu_manufacture, cpuInfo, sizeof(cpuInfo));

	__cpuid(cpuInfo, 0x80000003);
	memcpy(cpu_type, cpuInfo, sizeof(cpuInfo));

	__cpuid(cpuInfo, 0x80000004);
	memcpy(cpu_freq, cpuInfo, sizeof(cpuInfo));

	printf("CPU manufacture: %s\n", cpu_manufacture);
	printf("CPU type: %s\n", cpu_type);
	printf("CPU main frequency:%s\n", cpu_freq);
	

	/*strcat(cpu_info, "CPU manufacture: ");
	strcat(cpu_info, cpu_manufacture);
	strcat(cpu_info, "\nCPU type: ");
	strcat(cpu_info, cpu_type);
	strcat(cpu_info, "\nCPU main frequency(MHz): ");
	strcat(cpu_info, cpu_freq);
	*/
	return cpu_info;
}

#else

// mothed 1: this kind asm embedded in code only works in x86 build
// save 4 register variables
DWORD deax;
DWORD debx;
DWORD decx;
DWORD dedx;

// init cpu in assembly language
void initCpu(DWORD veax)
{
	__asm
	{
		mov eax, veax
		cpuid
		mov deax, eax
		mov debx, ebx
		mov decx, ecx
		mov dedx, edx
	}
}

long getCpuFreq()
{
	int start, over;
	_asm
	{
		RDTSC
		mov start, eax
	}
	Sleep(50);
	_asm
	{
		RDTSC
		mov over, eax
	}
	return (over - start) / 50000;
}

void getManufactureID(char* ManufactureID)
{
	char manuID[25];
	memset(manuID, 0, sizeof(manuID));

	initCpu(0);
	memcpy(manuID + 0, &debx, 4); // copy to array
	memcpy(manuID + 4, &dedx, 4);
	memcpy(manuID + 8, &decx, 4);

	strcpy(ManufactureID, manuID);
	//return manuID;
}

void getCpuType(char* CpuType)
{
	const DWORD id = 0x80000002; // start 0x80000002 end to 0x80000004
	char cpuType[100];
	memset(cpuType, 0, sizeof(cpuType));

	for (DWORD t = 0; t < 3; t++)
	{
		initCpu(id + t);

		memcpy(cpuType + 16 * t + 0, &deax, 4);
		memcpy(cpuType + 16 * t + 4, &debx, 4);
		memcpy(cpuType + 16 * t + 8, &decx, 4);
		memcpy(cpuType + 16 * t + 16, &dedx, 4);
	}
	strcpy(CpuType, cpuType);
}

char* getCpuInfo()
{
	char ManufactureID[25] = "";
	char CpuType[100] = "";
	long int CpuFreq = getCpuFreq();
	char cpu_freq[10] = "";
	char cpu_info[200] = "";

	getManufactureID(ManufactureID);
	getCpuType(CpuType);

	//std::cout << "CPU main frequency: " << getCpuFreq() << "MHz" << std::endl;

	printf("CPU manufacture: %s\n", ManufactureID);
	printf("CPU type: %s\n", CpuType);
	printf("CPU main frequency:%ldMhz\n", CpuFreq);


	strcat(cpu_info, "CPU manufacture: ");
	strcat(cpu_info, ManufactureID);
	strcat(cpu_info, "\nCPU type: ");
	strcat(cpu_info, CpuType);
	strcat(cpu_info, "\nCPU main frequency(MHz): ");
	sprintf(cpu_freq, "%d\n", CpuFreq);
	strcat(cpu_info, cpu_freq);
	return cpu_info;
}
#endif



// ---- get memory info ---- //
char* getMemoryInfo()
{
	char memory_info[256]="";
	MEMORYSTATUSEX statusex;
	statusex.dwLength = sizeof(statusex);
	if (GlobalMemoryStatusEx(&statusex))
	{
		unsigned long long total = 0, remain_total = 0, avl = 0, remain_avl = 0;
		double decimal_total = 0, decimal_avl = 0;
		remain_total = statusex.ullTotalPhys % GBYTES;
		total = statusex.ullTotalPhys / GBYTES;
		avl = statusex.ullAvailPhys / GBYTES;
		remain_avl = statusex.ullAvailPhys % GBYTES;
		if (remain_total > 0)
			decimal_total = (remain_total / MBYTES) / DKBYTES;
		if (remain_avl > 0)
			decimal_avl = (remain_avl / MBYTES) / DKBYTES;

		decimal_total += (double)total;
		decimal_avl += (double)avl;
		char  buffer[kMaxInfoBuffer];
		sprintf_s(buffer, kMaxInfoBuffer, "memory info: total %.2f GB (%.2f GB available)\n", decimal_total, decimal_avl);
		strcat(memory_info, buffer);
	}
	printf("%s\n", memory_info);
	return memory_info;
}


// ---- get harddisk info ---- //
char* getHardDiskInfo()
{
	char buffer[168] = { 0 };
	char result[168] = { 0 };
	FILE *pipe = _popen("wmic path win32_physicalmedia get SerialNumber", "r");
	if (!pipe) throw std::runtime_error("_popen() failed!");
	while (!feof(pipe))
	{
		if (fgets(buffer, 168, pipe) != NULL)
			strcat(result, buffer);
	}
	_pclose(pipe);
	printf("HardDisk Serial Number: %s", result);
	strcat(result, "\n");
	return result;
}

// ---- get network info ---- //
char* getNetworkInfo()
{
	// PIP_ADAPTER_INFO struct contains network information
	PIP_ADAPTER_INFO pIpAdapterInfo = new IP_ADAPTER_INFO();
	unsigned long adapter_size = sizeof(IP_ADAPTER_INFO);
	int ret = GetAdaptersInfo(pIpAdapterInfo, &adapter_size);
	char net_info[500] = "";
	char netcard_num[2] = "";

	if (ret == ERROR_BUFFER_OVERFLOW)
	{
		// overflow, use the output size to recreate the handler
		delete pIpAdapterInfo;
		pIpAdapterInfo = (PIP_ADAPTER_INFO)new BYTE[adapter_size];
		ret = GetAdaptersInfo(pIpAdapterInfo, &adapter_size);
	}

	if (ret == ERROR_SUCCESS)
	{
		int card_index = 0;

		// may have many cards, it saved in linklist
		while (pIpAdapterInfo)
		{
			printf("NetworkCard %d\n", card_index);
			printf("Network Card Name: %s\n", pIpAdapterInfo->AdapterName);
			printf("Network Card Description: %s\n", pIpAdapterInfo->Description);

			strcat(net_info, "networkCard: ");
			sprintf(netcard_num, "%d", card_index);
			strcat(net_info, netcard_num);

			strcat(net_info, "\nNetwork Card Name: ");
			strcat(net_info, pIpAdapterInfo->AdapterName);

			strcat(net_info, "\nNetwork Card Description: ");
			strcat(net_info, pIpAdapterInfo->Description);

			card_index++;

			// get IP, one card may have many IPs
			PIP_ADDR_STRING pIpAddr = &(pIpAdapterInfo->IpAddressList);
			while (pIpAddr)
			{
				char local_ip[168] = { 0 };
				strcpy(local_ip, pIpAddr->IpAddress.String);
				printf("Local IP: %s\n", local_ip);

				strcat(net_info, "\nLocal IP: ");
				strcat(net_info, local_ip);

				pIpAddr = pIpAddr->Next;
			}

			char local_mac[168] = { 0 };
			int char_index = 0;
			for (int i = 0; i < (pIpAdapterInfo->AddressLength); i++)
			{
				char temp_str[10] = { 0 };
				sprintf(temp_str, "%02X-", pIpAdapterInfo->Address[i]); // X for uppercase, x for lowercase
				strcpy(local_mac + char_index, temp_str);
				char_index += 3;
			}
			local_mac[17] = '\0'; // remove tail '-'

			printf("Local Mac: %s\n", local_mac);

			strcat(net_info, "\nLocal Mac: ");
			strcat(net_info, local_mac);
			// here just need the first card info
			break;
			// iterate next
			//pIpAdapterInfo = pIpAdapterInfo->Next;
		}
	}
	if (pIpAdapterInfo)
		delete pIpAdapterInfo;
	return net_info;
}


char* execIntro() {
	unsigned int s1, s2, s3, s4;
	int i = 0;
	char exec_info[60000] = "";

	//0x10000c8b;EAX=0h;ECX=0h
	char signature_0[16];
	_asm {
		push eax
		push ebx
		push ecx
		push edx
		mov  eax, 0x0
		mov  ecx, 0x0
		cpuid
		mov s1, eax
		mov s2, ebx
		mov s3, ecx
		mov s4, edx
		pop edx
		pop ecx
		pop ebx
		pop eax
	}
	*(unsigned int*)(signature_0 + 0) = s1;
	*(unsigned int*)(signature_0 + 4) = s2;
	*(unsigned int*)(signature_0 + 8) = s3;
	*(unsigned int*)(signature_0 + 12) = s4;


	//0x10000c8c;EAX=01h;ECX=0h
	char signature_1[16];
	_asm {
		push eax
		push ebx
		push ecx
		push edx
		mov  eax, 0x01
		mov  ecx, 0x00
		cpuid
		mov s1, eax
		mov s2, ebx
		mov s3, ecx
		mov s4, edx
		pop edx
		pop ecx
		pop ebx
		pop eax
	}
	*(unsigned int*)(signature_1 + 0) = s1;
	*(unsigned int*)(signature_1 + 4) = s2;
	*(unsigned int*)(signature_1 + 8) = s3;
	*(unsigned int*)(signature_1 + 12) = s4;
	//printf("%s\n", signature_1);
	for (i = 0; i < 16; i++) {
		strcat(exec_info, prt(signature_1[i]));
	}
	printf("\n");
	strcat(exec_info, "\n");


	//0x10000c8d;EAX=02h;ECX=0h
	char signature_2[16];
	_asm {
		push eax
		push ebx
		push ecx
		push edx
		mov  eax, 0x02
		mov  ecx, 0x00
		cpuid
		mov s1, eax
		mov s2, ebx
		mov s3, ecx
		mov s4, edx
		pop edx
		pop ecx
		pop ebx
		pop eax
	}
	*(unsigned int*)(signature_2 + 0) = s1;
	*(unsigned int*)(signature_2 + 4) = s2;
	*(unsigned int*)(signature_2 + 8) = s3;
	*(unsigned int*)(signature_2 + 12) = s4;
	//printf("%s\n", signature_4);
	for (i = 0; i < 16; i++) {
		strcat(exec_info, prt(signature_2[i]));
	}
	printf("\n");
	strcat(exec_info, "\n");


	//0x10000c8e;EAX=03h;ECX=0h
	char signature_3[16];
	_asm {
		push eax
		push ebx
		push ecx
		push edx
		mov  eax, 0x03
		mov  ecx, 0x00
		cpuid
		mov s1, eax
		mov s2, ebx
		mov s3, ecx
		mov s4, edx
		pop edx
		pop ecx
		pop ebx
		pop eax
	}
	*(unsigned int*)(signature_3 + 0) = s1;
	*(unsigned int*)(signature_3 + 4) = s2;
	*(unsigned int*)(signature_3 + 8) = s3;
	*(unsigned int*)(signature_3 + 12) = s4;
	for (i = 0; i < 16; i++) {
		strcat(exec_info, prt(signature_3[i]));
	}
	printf("\n");
	strcat(exec_info, "\n");


	//0x10000c8f;EAX=04h;ECX=0h
	char signature_4[16];
	_asm {
		push eax
		push ebx
		push ecx
		push edx
		mov  eax, 0x04
		mov  ecx, 0x00
		cpuid
		mov s1, eax
		mov s2, ebx
		mov s3, ecx
		mov s4, edx
		pop edx
		pop ecx
		pop ebx
		pop eax
	}
	*(unsigned int*)(signature_4 + 0) = s1;
	*(unsigned int*)(signature_4 + 4) = s2;
	*(unsigned int*)(signature_4 + 8) = s3;
	*(unsigned int*)(signature_4 + 12) = s4;
	for (i = 0; i < 16; i++) {
		strcat(exec_info, prt(signature_4[i]));
	}
	printf("\n");
	strcat(exec_info, "\n");


	//0x10000c90；EAX=05h；ECX=01h
	char signature_5[16];
	_asm {
		push eax
		push ebx
		push ecx
		push edx
		mov  eax, 0x05
		mov  ecx, 0x01
		cpuid
		mov s1, eax
		mov s2, ebx
		mov s3, ecx
		mov s4, edx
		pop edx
		pop ecx
		pop ebx
		pop eax
	}
	*(unsigned int*)(signature_5 + 0) = s1;
	*(unsigned int*)(signature_5 + 4) = s2;
	*(unsigned int*)(signature_5 + 8) = s3;
	*(unsigned int*)(signature_5 + 12) = s4;
	//printf("%s\n", signature_5);
	for (i = 0; i < 16; i++) {
		strcat(exec_info, prt(signature_5[i]));
		//fprintf(log_fp, "%d", i);
	}
	printf("\n");
	strcat(exec_info, "\n");


	//0x10000c91;EAX=06h;ECX=08h
	char signature_6[16];
	_asm {
		push eax
		push ebx
		push ecx
		push edx
		mov  eax, 0x06
		mov  ecx, 0x08
		cpuid
		mov s1, eax
		mov s2, ebx
		mov s3, ecx
		mov s4, edx
		pop edx
		pop ecx
		pop ebx
		pop eax
	}
	*(unsigned int*)(signature_6 + 0) = s1;
	*(unsigned int*)(signature_6 + 4) = s2;
	*(unsigned int*)(signature_6 + 8) = s3;
	*(unsigned int*)(signature_6 + 12) = s4;
	//printf("%s\n", signature_6);
	for (i = 0; i < 16; i++) {
		strcat(exec_info, prt(signature_6[i]));
	}
	printf("\n");
	strcat(exec_info, "\n");


	//0x10000c92;EAX=07h;ECX=09h
	char signature_7[16];
	_asm {
		push eax
		push ebx
		push ecx
		push edx
		mov  eax, 0x07
		mov  ecx, 0x09
		cpuid
		mov s1, eax
		mov s2, ebx
		mov s3, ecx
		mov s4, edx
		pop edx
		pop ecx
		pop ebx
		pop eax
	}
	*(unsigned int*)(signature_7 + 0) = s1;
	*(unsigned int*)(signature_7 + 4) = s2;
	*(unsigned int*)(signature_7 + 8) = s3;
	*(unsigned int*)(signature_7 + 12) = s4;
	//printf("%s\n", signature_7);
	for (i = 0; i < 16; i++) {
		strcat(exec_info, prt(signature_7[i]));
	}
	printf("\n");
	strcat(exec_info, "\n");


	//0x10000c93;EAX=08h;ECX=0h
	char signature_8[16];
	_asm {
		push eax
		push ebx
		push ecx
		push edx
		mov  eax, 0x08
		mov  ecx, 0x00
		cpuid
		mov s1, eax
		mov s2, ebx
		mov s3, ecx
		mov s4, edx
		pop edx
		pop ecx
		pop ebx
		pop eax
	}
	*(unsigned int*)(signature_8 + 0) = s1;
	*(unsigned int*)(signature_8 + 4) = s2;
	*(unsigned int*)(signature_8 + 8) = s3;
	*(unsigned int*)(signature_8 + 12) = s4;
	//printf("%s\n", signature_8);
	for (i = 0; i < 16; i++) {
		strcat(exec_info, prt(signature_8[i]));
	}
	printf("\n");
	strcat(exec_info, "\n");


	//0x10000c94;EAX=09h;ECX=09h
	char signature_9[16];
	_asm {
		push eax
		push ebx
		push ecx
		push edx
		mov  eax, 0x09
		mov  ecx, 0x09
		cpuid
		mov s1, eax
		mov s2, ebx
		mov s3, ecx
		mov s4, edx
		pop edx
		pop ecx
		pop ebx
		pop eax
	}
	*(unsigned int*)(signature_9 + 0) = s1;
	*(unsigned int*)(signature_9 + 4) = s2;
	*(unsigned int*)(signature_9 + 8) = s3;
	*(unsigned int*)(signature_9 + 12) = s4;
	//printf("%s\n", signature_9);
	for (i = 0; i < 16; i++) {
		strcat(exec_info, prt(signature_9[i]));
	}
	printf("\n");
	strcat(exec_info, "\n");


	//0x10000c95;EAX=0ah;ECX=09h
	char signature_10[16];
	_asm {
		push eax
		push ebx
		push ecx
		push edx
		mov  eax, 0x0a
		mov  ecx, 0x09
		cpuid
		mov s1, eax
		mov s2, ebx
		mov s3, ecx
		mov s4, edx
		pop edx
		pop ecx
		pop ebx
		pop eax
	}
	*(unsigned int*)(signature_10 + 0) = s1;
	*(unsigned int*)(signature_10 + 4) = s2;
	*(unsigned int*)(signature_10 + 8) = s3;
	*(unsigned int*)(signature_10 + 12) = s4;
	//printf("%s\n", signature_10);
	for (i = 0; i < 16; i++) {
		strcat(exec_info, prt(signature_10[i]));
	}
	printf("\n");
	strcat(exec_info, "\n");


	//0x10000c96;EAX=0bh;ECX=0h
	char signature_11[16];
	_asm {
		push eax
		push ebx
		push ecx
		push edx
		mov  eax, 0x0b
		mov  ecx, 0x00
		cpuid
		mov s1, eax
		mov s2, ebx
		mov s3, ecx
		mov s4, edx
		pop edx
		pop ecx
		pop ebx
		pop eax
	}
	*(unsigned int*)(signature_11 + 0) = s1;
	*(unsigned int*)(signature_11 + 4) = s2;
	*(unsigned int*)(signature_11 + 8) = s3;
	*(unsigned int*)(signature_11 + 12) = s4;
	//printf("%s\n", signature_11);
	for (i = 0; i < 16; i++) {
		strcat(exec_info, prt(signature_11[i]));
	}
	printf("\n");
	strcat(exec_info, "\n");


	//0x10000c97;EAX=0ch;ECX=0h
	char signature_12[16];
	_asm {
		push eax
		push ebx
		push ecx
		push edx
		mov  eax, 0x0c
		mov  ecx, 0x00
		cpuid
		mov s1, eax
		mov s2, ebx
		mov s3, ecx
		mov s4, edx
		pop edx
		pop ecx
		pop ebx
		pop eax
	}
	*(unsigned int*)(signature_12 + 0) = s1;
	*(unsigned int*)(signature_12 + 4) = s2;
	*(unsigned int*)(signature_12 + 8) = s3;
	*(unsigned int*)(signature_12 + 12) = s4;
	//printf("%s\n", signature_12);
	for (i = 0; i < 16; i++) {
		strcat(exec_info, prt(signature_12[i]));
	}
	printf("\n");
	strcat(exec_info, "\n");


	//0x10000c98;EAX=0dh;ECX=0dh
	char signature_13[16];
	_asm {
		push eax
		push ebx
		push ecx
		push edx
		mov  eax, 0x0d
		mov  ecx, 0x0d
		cpuid
		mov s1, eax
		mov s2, ebx
		mov s3, ecx
		mov s4, edx
		pop edx
		pop ecx
		pop ebx
		pop eax
	}
	*(unsigned int*)(signature_13 + 0) = s1;
	*(unsigned int*)(signature_13 + 4) = s2;
	*(unsigned int*)(signature_13 + 8) = s3;
	*(unsigned int*)(signature_13 + 12) = s4;
	//printf("%s\n", signature_13);
	for (i = 0; i < 16; i++) {
		strcat(exec_info, prt(signature_13[i]));
	}
	printf("\n");
	strcat(exec_info, "\n");

	//0x10000c99;EAX=80000000h
	char signature_14[16];
	_asm {
		push eax
		push ebx
		push ecx
		push edx
		mov  eax, 0x80000000
		cpuid
		mov s1, eax
		mov s2, ebx
		mov s3, ecx
		mov s4, edx
		pop edx
		pop ecx
		pop ebx
		pop eax
	}
	*(unsigned int*)(signature_14 + 0) = s1;
	*(unsigned int*)(signature_14 + 4) = s2;
	*(unsigned int*)(signature_14 + 8) = s3;
	*(unsigned int*)(signature_14 + 12) = s4;
	//printf("%s\n", signature_14);
	for (i = 0; i < 16; i++) {
		strcat(exec_info, prt(signature_14[i]));
	}
	printf("\n");
	strcat(exec_info, "\n");


	//0x10000c9a;EAX=80000001h
	char signature_15[16];
	_asm {
		push eax
		push ebx
		push ecx
		push edx
		mov  eax, 0x80000001
		cpuid
		mov s1, eax
		mov s2, ebx
		mov s3, ecx
		mov s4, edx
		pop edx
		pop ecx
		pop ebx
		pop eax
	}
	*(unsigned int*)(signature_15 + 0) = s1;
	*(unsigned int*)(signature_15 + 4) = s2;
	*(unsigned int*)(signature_15 + 8) = s3;
	*(unsigned int*)(signature_15 + 12) = s4;
	//printf("%s\n", signature_15);
	for (i = 0; i < 16; i++) {
		strcat(exec_info, prt(signature_15[i]));
	}
	printf("\n");
	strcat(exec_info, "\n");



	//f0x10000c9b;EAX=80000002h
	char signature_16[16];
	_asm {
		push eax
		push ebx
		push ecx
		push edx
		mov  eax, 0x80000002
		cpuid
		mov s1, eax
		mov s2, ebx
		mov s3, ecx
		mov s4, edx
		pop edx
		pop ecx
		pop ebx
		pop eax
	}
	*(unsigned int*)(signature_16 + 0) = s1;
	*(unsigned int*)(signature_16 + 4) = s2;
	*(unsigned int*)(signature_16 + 8) = s3;
	*(unsigned int*)(signature_16 + 12) = s4;
	//printf("%s\n", signature_16);
	for (i = 0; i < 16; i++) {
		strcat(exec_info, prt(signature_16[i]));
	}
	printf("\n");
	strcat(exec_info, "\n");


	//0x10000c9c;EAX=80000003h
	char signature_17[16];
	_asm {
		push eax
		push ebx
		push ecx
		push edx
		mov  eax, 0x80000003
		cpuid
		mov s1, eax
		mov s2, ebx
		mov s3, ecx
		mov s4, edx
		pop edx
		pop ecx
		pop ebx
		pop eax
	}
	*(unsigned int*)(signature_17 + 0) = s1;
	*(unsigned int*)(signature_17 + 4) = s2;
	*(unsigned int*)(signature_17 + 8) = s3;
	*(unsigned int*)(signature_17 + 12) = s4;
	//printf("%s\n", signature_17);
	for (i = 0; i < 16; i++) {
		strcat(exec_info, prt(signature_17[i]));
	}
	printf("\n");
	strcat(exec_info, "\n");


	//0x10000c9d;EAX=80000004h
	char signature_18[16];
	_asm {
		push eax
		push ebx
		push ecx
		push edx
		mov  eax, 0x80000004
		cpuid
		mov s1, eax
		mov s2, ebx
		mov s3, ecx
		mov s4, edx
		pop edx
		pop ecx
		pop ebx
		pop eax
	}
	*(unsigned int*)(signature_18 + 0) = s1;
	*(unsigned int*)(signature_18 + 4) = s2;
	*(unsigned int*)(signature_18 + 8) = s3;
	*(unsigned int*)(signature_18 + 12) = s4;
	//printf("%s\n", signature_18);
	for (i = 0; i < 16; i++) {
		strcat(exec_info, prt(signature_18[i]));
	}
	printf("\n");
	strcat(exec_info, "\n");


	//0x10000c9e;EAX=80000005h
	char signature_19[16];
	_asm {
		push eax
		push ebx
		push ecx
		push edx
		mov  eax, 0x80000005
		cpuid
		mov s1, eax
		mov s2, ebx
		mov s3, ecx
		mov s4, edx
		pop edx
		pop ecx
		pop ebx
		pop eax
	}
	*(unsigned int*)(signature_19 + 0) = s1;
	*(unsigned int*)(signature_19 + 4) = s2;
	*(unsigned int*)(signature_19 + 8) = s3;
	*(unsigned int*)(signature_19 + 12) = s4;
	//printf("%s\n", signature_19);
	for (i = 0; i < 16; i++) {
		strcat(exec_info, prt(signature_19[i]));
	}
	printf("\n");
	strcat(exec_info, "\n");


	//0x10000c9f;EAX=80000006h
	char signature_20[16];
	_asm {
		push eax
		push ebx
		push ecx
		push edx
		mov  eax, 0x80000006
		cpuid
		mov s1, eax
		mov s2, ebx
		mov s3, ecx
		mov s4, edx
		pop edx
		pop ecx
		pop ebx
		pop eax
	}
	*(unsigned int*)(signature_20 + 0) = s1;
	*(unsigned int*)(signature_20 + 4) = s2;
	*(unsigned int*)(signature_20 + 8) = s3;
	*(unsigned int*)(signature_20 + 12) = s4;
	//printf("%s\n", signature_20);
	for (i = 0; i < 16; i++) {
		strcat(exec_info, prt(signature_20[i]));
	}
	printf("\n");
	strcat(exec_info, "\n");


	//0x10000ca0;EAX=80000007h
	char signature_21[16];
	_asm {
		push eax
		push ebx
		push ecx
		push edx
		mov  eax, 0x80000007
		cpuid
		mov s1, eax
		mov s2, ebx
		mov s3, ecx
		mov s4, edx
		pop edx
		pop ecx
		pop ebx
		pop eax
	}
	*(unsigned int*)(signature_21 + 0) = s1;
	*(unsigned int*)(signature_21 + 4) = s2;
	*(unsigned int*)(signature_21 + 8) = s3;
	*(unsigned int*)(signature_21 + 12) = s4;
	//printf("%s\n", signature_21);
	for (i = 0; i < 16; i++) {
		strcat(exec_info, prt(signature_21[i]));
	}
	printf("\n");
	strcat(exec_info, "\n");


	//0x10000ca1;EAX=80000008h
	char signature_22[16];
	_asm {
		push eax
		push ebx
		push ecx
		push edx
		mov  eax, 0x80000008
		cpuid
		mov s1, eax
		mov s2, ebx
		mov s3, ecx
		mov s4, edx
		pop edx
		pop ecx
		pop ebx
		pop eax
	}
	*(unsigned int*)(signature_22 + 0) = s1;
	*(unsigned int*)(signature_22 + 4) = s2;
	*(unsigned int*)(signature_22 + 8) = s3;
	*(unsigned int*)(signature_22 + 12) = s4;
	//printf("%s\n", signature_22);
	for (i = 0; i < 16; i++) {
		strcat(exec_info, prt(signature_22[i]));
	}
	printf("\n");
	strcat(exec_info, "\n");


	//0x10000ca2;EAX=80000009h
	char signature_23[16];
	_asm {
		push eax
		push ebx
		push ecx
		push edx
		mov  eax, 0x80000009
		cpuid
		mov s1, eax
		mov s2, ebx
		mov s3, ecx
		mov s4, edx
		pop edx
		pop ecx
		pop ebx
		pop eax
	}
	*(unsigned int*)(signature_23 + 0) = s1;
	*(unsigned int*)(signature_23 + 4) = s2;
	*(unsigned int*)(signature_23 + 8) = s3;
	*(unsigned int*)(signature_23 + 12) = s4;
	//printf("%s\n", signature_23);
	for (i = 0; i < 16; i++) {
		strcat(exec_info, prt(signature_23[i]));
	}
	printf("\n");
	strcat(exec_info, "\n");


	//0x10000ca3;EAX=8000000ah
	char signature_24[16];
	_asm {
		push eax
		push ebx
		push ecx
		push edx
		mov  eax, 0x8000000a
		cpuid
		mov s1, eax
		mov s2, ebx
		mov s3, ecx
		mov s4, edx
		pop edx
		pop ecx
		pop ebx
		pop eax
	}
	*(unsigned int*)(signature_24 + 0) = s1;
	*(unsigned int*)(signature_24 + 4) = s2;
	*(unsigned int*)(signature_24 + 8) = s3;
	*(unsigned int*)(signature_24 + 12) = s4;
	//printf("%s\n", signature_24);
	for (i = 0; i < 16; i++) {
		strcat(exec_info, prt(signature_24[i]));
	}
	printf("\n");
	strcat(exec_info, "\n");


	//0x10000ca4;EAX=8000000bh
	char signature_25[16];
	_asm {
		push eax
		push ebx
		push ecx
		push edx
		mov  eax, 0x8000000b
		cpuid
		mov s1, eax
		mov s2, ebx
		mov s3, ecx
		mov s4, edx
		pop edx
		pop ecx
		pop ebx
		pop eax
	}
	*(unsigned int*)(signature_25 + 0) = s1;
	*(unsigned int*)(signature_25 + 4) = s2;
	*(unsigned int*)(signature_25 + 8) = s3;
	*(unsigned int*)(signature_25 + 12) = s4;
	//printf("%s\n", signature_25);
	for (i = 0; i < 16; i++) {
		strcat(exec_info, prt(signature_25[i]));
	}
	printf("\n");
	strcat(exec_info, "\n");


	//0x10000ca5;EAX=40000000h
	char signature_26[16];
	_asm {
		push eax
		push ebx
		push ecx
		push edx
		mov  eax, 0x40000000
		cpuid
		mov s1, eax
		mov s2, ebx
		mov s3, ecx
		mov s4, edx
		pop edx
		pop ecx
		pop ebx
		pop eax
	}
	*(unsigned int*)(signature_26 + 0) = s1;
	*(unsigned int*)(signature_26 + 4) = s2;
	*(unsigned int*)(signature_26 + 8) = s3;
	*(unsigned int*)(signature_26 + 12) = s4;
	//printf("%s\n", signature_26);
	for (i = 0; i < 16; i++) {
		strcat(exec_info, prt(signature_26[i]));
	}
	printf("\n");
	strcat(exec_info, "\n");


	//0x10000ca6;EAX=40000004h
	char signature_27[16];
	_asm {
		push eax
		push ebx
		push ecx
		push edx
		mov  eax, 0x40000004
		cpuid
		mov s1, eax
		mov s2, ebx
		mov s3, ecx
		mov s4, edx
		pop edx
		pop ecx
		pop ebx
		pop eax
	}
	*(unsigned int*)(signature_27 + 0) = s1;
	*(unsigned int*)(signature_27 + 4) = s2;
	*(unsigned int*)(signature_27 + 8) = s3;
	*(unsigned int*)(signature_27 + 12) = s4;
	//printf("%s\n", signature_27);
	for (i = 0; i < 16; i++) {
		strcat(exec_info, prt(signature_27[i]));
	}
	printf("\n");
	strcat(exec_info, "\n");


	//0x10000ca7;EAX=4fffffffh
	char signature_28[16];
	_asm {
		push eax
		push ebx
		push ecx
		push edx
		mov  eax, 0x4fffffff
		cpuid
		mov s1, eax
		mov s2, ebx
		mov s3, ecx
		mov s4, edx
		pop edx
		pop ecx
		pop ebx
		pop eax
	}
	*(unsigned int*)(signature_28 + 0) = s1;
	*(unsigned int*)(signature_28 + 4) = s2;
	*(unsigned int*)(signature_28 + 8) = s3;
	*(unsigned int*)(signature_28 + 12) = s4;
	//printf("%s\n", signature_28);
	for (i = 0; i < 16; i++) {
		strcat(exec_info, prt(signature_28[i]));
	}
	printf("\n");
	strcat(exec_info, "\n");


	//0x10000ca8;EAX=30000004h
	char signature_29[16];
	_asm {
		push eax
		push ebx
		push ecx
		push edx
		mov  eax, 0x30000004
		cpuid
		mov s1, eax
		mov s2, ebx
		mov s3, ecx
		mov s4, edx
		pop edx
		pop ecx
		pop ebx
		pop eax
	}
	*(unsigned int*)(signature_29 + 0) = s1;
	*(unsigned int*)(signature_29 + 4) = s2;
	*(unsigned int*)(signature_29 + 8) = s3;
	*(unsigned int*)(signature_29 + 12) = s4;
	//printf("%s\n", signature_29);
	for (i = 0; i < 16; i++) {
		strcat(exec_info, prt(signature_29[i]));
	}
	printf("\n");
	strcat(exec_info, "\n");


	//0x10000ca9;EAX=50000000h
	char signature_30[16];
	_asm {
		push eax
		push ebx
		push ecx
		push edx
		mov  eax, 0x50000000
		cpuid
		mov s1, eax
		mov s2, ebx
		mov s3, ecx
		mov s4, edx
		pop edx
		pop ecx
		pop ebx
		pop eax
	}
	*(unsigned int*)(signature_30 + 0) = s1;
	*(unsigned int*)(signature_30 + 4) = s2;
	*(unsigned int*)(signature_30 + 8) = s3;
	*(unsigned int*)(signature_30 + 12) = s4;
	//printf("%s\n", signature_30);
	for (i = 0; i < 16; i++) {
		strcat(exec_info, prt(signature_30[i]));
	}
	printf("\n");
	strcat(exec_info, "\n");

	return exec_info;

}