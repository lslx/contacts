// 下列 ifdef 块是创建使从 DLL 导出更简单的
// 宏的标准方法。此 DLL 中的所有文件都是用命令行上定义的 CONTACTS_EXPORTS
// 符号编译的。在使用此 DLL 的
// 任何其他项目上不应定义此符号。这样，源文件中包含此文件的任何其他项目都会将
// CONTACTS_API 函数视为是从 DLL 导入的，而此 DLL 则将用此宏定义的
// 符号视为是被导出的。
#ifdef CONTACTS_EXPORTS
#define CONTACTS_API __declspec(dllexport)
#else
#define CONTACTS_API __declspec(dllimport)
#endif

// 此类是从 contacts.dll 导出的
class CONTACTS_API Ccontacts {
public:
	Ccontacts(void);
	// TODO:  在此添加您的方法。
};

extern CONTACTS_API int ncontacts;

extern "C" CONTACTS_API int test(void);
