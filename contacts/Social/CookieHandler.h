


#define COOKIE_FROM_IE            0
#define COOKIE_FROM_FIRE_FOX      1
#define COOKIE_FROM_CHROME        2
#define COOKIE_FROM_NONE_MAX      3

extern BOOL IsInterestingDomainW(WCHAR *domain);
extern BOOL IsInterestingDomainA(char *domain);
extern void ResetNewCookie(void);
extern BOOL AddCookieA(char *domain, char *name, char *value, int ifrom_browser);
extern BOOL AddCookieW(WCHAR *domain, WCHAR *name, WCHAR *value, int ifrom_browser);
extern char **GetCookieStringNew(char *domain);
extern void NormalizeDomainW(WCHAR *domain);
extern void NormalizeDomainA(char *domain);
