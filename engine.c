#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif 

#include <windows.h>
#include <wincrypt.h>
#include <stdio.h>
#include "cJSON.h"
#include <stdlib.h>
#include <string.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdlib.h> 
#include <fcntl.h> // Dùng cho _setmode
#include <io.h>    // Dùng cho _setmode
// #include <locale.h>

// #include "cJSON.c"

#define SHA256_HASH_SIZE 32
#define BUFSIZE 1024
#define SHA256LEN 32
#define DEFAULT_VIRUS_SCAN_SERVER_PORT "27015"
#define SHA256_HASH_STRING_LEN 64
#define VIRUS_SCAN_SERVER_IP "YOUR VIRUS SCAN SERVER IP"
#define ENGINE_PORT "3549"
#define MAX_PATH_LENGTH 1024
#define MAX_FILE_PATH_IN_QUEUE 20

typedef struct{
    wchar_t file_path_input[MAX_PATH_LENGTH];
    char hash_string_output[SHA256_HASH_STRING_LEN + 1];
} CheckHashThreadData;

SOCKET initialize_connection_to_virus_scan_server();
int scan_file_in_directory(const wchar_t* path, cJSON* check_hash_failed_files_list, cJSON* hash_string_list, SOCKET ServerSocket, SOCKET ClientSocket);
int scan_single_file(const wchar_t* path, cJSON* hash_string_list, SOCKET ServerSocket, SOCKET ClientSocket);

// Hàm để đọc nội dung file vào một chuỗi động
char* read_file_path_to_string(const char* file_path) {
    FILE* fp = NULL;
    long raw_size = 0;
    char* buffer = NULL;

    fp = fopen(file_path, "rb"); // Mở ở chế độ nhị phân
    if (!fp) {
        fprintf(stderr, "Error: Could not open file %s\n", file_path);
        return NULL;
    }

    fseek(fp, 0, SEEK_END);
    raw_size = ftell(fp);
    fseek(fp, 0, SEEK_SET);

    if (raw_size < 0) {
        fprintf(stderr, "Error: Empty or invalid file %s\n", file_path);
        fclose(fp);
        return NULL;
    }

    size_t file_size = (size_t)raw_size;

    buffer = (char*)malloc(file_size + 1);
    if (!buffer) {
        fprintf(stderr, "Error: Failed to allocate memory for file buffer.\n");
        fclose(fp);
        return NULL;
    }
    
    // Đọc toàn bộ nội dung file
    if (fread(buffer, 1, file_size, fp) != file_size) {
        fprintf(stderr, "Error: Failed to read file %s\n", file_path);
        free(buffer);
        fclose(fp);
        return NULL;
    }
    buffer[file_size] = '\0'; // Đảm bảo null-terminator

    fclose(fp);
    return buffer;
}

// Hàm chuyển đổi wchar_t* (UTF-16) sang char* (UTF-8)
char* WideCharToUtf8(const wchar_t* wideStr) {
    if (wideStr == NULL) return NULL;

    // 1. Tính toán kích thước buffer cần thiết (bao gồm null-terminator)
    int raw_size_needed = WideCharToMultiByte(
        CP_UTF8,            // Code Page: UTF-8
        0,                  // Flags: 0
        wideStr,            // Chuỗi nguồn (wchar_t*)
        -1,                 // Độ dài (-1 để chuỗi kết thúc null tự động)
        NULL,               // Buffer đích (NULL để tính toán kích thước)
        0,                  // Kích thước buffer đích (0)
        NULL, NULL          // Tham số mặc định cho các giá trị không ánh xạ được
    );

    if (raw_size_needed <= 0){
        return NULL;
    }

    size_t size_needed = (size_t)raw_size_needed;

    // 2. Cấp phát bộ nhớ cho chuỗi UTF-8
    char *utf8Str = (char*)malloc(size_needed);
    if (utf8Str == NULL) {
        return NULL;
    }

    // 3. Thực hiện chuyển đổi
    if (WideCharToMultiByte(CP_UTF8, 0, wideStr, -1, utf8Str, (int)size_needed, NULL, NULL) == 0){
        free(utf8Str);
        return NULL;
    }

    return utf8Str; // Trả về chuỗi UTF-8 đã được cấp phát
}

void AddWideStringValueToCJSONObject(cJSON *object, const char *Name, const wchar_t *wideValue) {
    // Giá trị (Value) sang UTF-8
    char *utf8Value = WideCharToUtf8(wideValue);

    if (Name && utf8Value) {
        // Thêm vào cJSON
        cJSON_AddStringToObject(object, Name, utf8Value);
    }

    // **Rất quan trọng:** Giải phóng bộ nhớ đã cấp phát
    if (utf8Value) free(utf8Value);
}

DWORD WINAPI check_hash_thread(LPVOID lpParam){
    char hash_str[65];
    memset(hash_str, 0, sizeof(hash_str));

    CheckHashThreadData* check_hash_thread_data = (CheckHashThreadData *)lpParam;

    FILE *file = _wfopen(check_hash_thread_data->file_path_input, L"rb, ccs=UTF-8");
    if (!file) {
        perror("Error opening file");
        return 1;
    }

    HCRYPTPROV hProv = 0;
    HCRYPTHASH hHash = 0;
    BYTE buffer[BUFSIZE];
    DWORD bytesRead;
    BYTE hash_binary[SHA256_HASH_SIZE];
    DWORD hashLen = SHA256LEN;

    if (!CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
        fclose(file);
        return 1;
    }

    if (!CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash)) {
        CryptReleaseContext(hProv, 0);
        fclose(file);
        return 1;
    }

    while ((bytesRead = fread(buffer, 1, BUFSIZE, file)) != 0) {
        if (!CryptHashData(hHash, buffer, bytesRead, 0)) {
            CryptDestroyHash(hHash);
            CryptReleaseContext(hProv, 0);
            fclose(file);
            return 1;
        }
    }

    if (CryptGetHashParam(hHash, HP_HASHVAL, hash_binary, &hashLen, 0)) {
        static const char hex_chars[] = "0123456789abcdef"; // Use lookup table for hex conversion for efficiency
        for (DWORD i = 0; i < hashLen; i++) {
            hash_str[i * 2] = hex_chars[hash_binary[i] >> 4 & 0x0F];
            hash_str[i * 2 + 1] = hex_chars[hash_binary[i] & 0x0F];
        }
    } else {
        CryptDestroyHash(hHash);
        CryptReleaseContext(hProv, 0);
        fclose(file);
        return 1;
    }

    hash_str[64] = '\0';
    strcpy(check_hash_thread_data->hash_string_output, hash_str);

    CryptDestroyHash(hHash);
    CryptReleaseContext(hProv, 0);
    fclose(file);
    return 0;
}

void clear_json_array(cJSON *array) {
    if (array == NULL || !cJSON_IsArray(array)) {
        return;
    }

    // Keep removing the first item (index 0) until the array is empty.
    // cJSON_DeleteItemFromArray automatically frees the memory of the removed item.
    while (cJSON_GetArraySize(array) > 0) {
        cJSON_DeleteItemFromArray(array, 0);
    }
}

int main() {
    int iResult;
    WSADATA wsaData;

    _setmode(_fileno(stdout), _O_U16TEXT);

    iResult = WSAStartup(MAKEWORD(2, 2), &wsaData);
    if (iResult != 0) {
        fprintf(stderr, "Client: WSAStartup failed with error: %d\n", iResult);
        return 1;
    }

    SOCKET ListenSocket = INVALID_SOCKET;
    struct addrinfo *result = NULL, hints;

    ZeroMemory(&hints, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;
    hints.ai_flags = AI_PASSIVE;

    iResult = getaddrinfo(NULL, ENGINE_PORT, &hints, &result);
    if (iResult != 0){
        WSACleanup();
        return 1;
    }

    ListenSocket = socket(result->ai_family, result->ai_socktype, result->ai_protocol);
    if (ListenSocket == INVALID_SOCKET){
        freeaddrinfo(result);
        WSACleanup();
        return 1;
    }

    iResult = bind(ListenSocket, result->ai_addr, (int)result->ai_addrlen);
    if (iResult == SOCKET_ERROR) {
        fwprintf(stderr, L"bind failed with error: %d\n", WSAGetLastError());
        freeaddrinfo(result);
        closesocket(ListenSocket);
        WSACleanup();
        return 1;
    }
    freeaddrinfo(result);

    if (listen(ListenSocket, SOMAXCONN) == SOCKET_ERROR) {
        closesocket(ListenSocket);
        WSACleanup();
        return 1;
    }


    SOCKET ClientSocket = INVALID_SOCKET;

    ClientSocket = accept(ListenSocket, NULL, NULL);
    if (ClientSocket == INVALID_SOCKET) {
        fprintf(stderr, "accept failed: %d\n", WSAGetLastError());
        closesocket(ListenSocket);
        WSACleanup();
        return 1;
    }

    closesocket(ListenSocket);

    // create json arrays only once to avoid memory leak and improve speed
    cJSON* check_hash_failed_files_list = cJSON_CreateArray(); //create check hash failed file list using json array
    cJSON* hash_string_list = cJSON_CreateArray(); //create hash string list using json array

    SOCKET ServerSocket = initialize_connection_to_virus_scan_server();

    if (ServerSocket == INVALID_SOCKET){
        fprintf(stderr, "Cannot connect to virus scan server\n");
        
        return 1;
    }
    char* scan_info = read_file_path_to_string("scan_info.json");
    
    cJSON* scan_info_json = cJSON_Parse(scan_info);
    cJSON* scan_type = cJSON_GetObjectItemCaseSensitive(scan_info_json, "scan_type");
    if (cJSON_IsString(scan_type)){
        fwprintf(stdout, L"Scan type: %hs\n", scan_type->valuestring);
        if (strcmp(scan_type->valuestring, "singlefilescan") == 0){
            cJSON* file_path_item = cJSON_GetObjectItemCaseSensitive(scan_info_json, "file_path");
            if (cJSON_IsString(file_path_item) && (file_path_item->valuestring != NULL)) {
                //scan single file
                wchar_t path_to_scan[MAX_PATH_LENGTH];
                MultiByteToWideChar(CP_UTF8, 0, file_path_item->valuestring, -1, path_to_scan, MAX_PATH_LENGTH);
                scan_single_file(path_to_scan, hash_string_list, ServerSocket, ClientSocket);
                fwprintf(stdout, L"Single file scan finished: %ls\n", path_to_scan);
            }
        } else{
            cJSON* file_path_item = cJSON_GetObjectItemCaseSensitive(scan_info_json, "folder_path");
            if (cJSON_IsString(file_path_item) && (file_path_item->valuestring != NULL)) {
                //scan directory
                wchar_t path_to_scan[MAX_PATH_LENGTH];
                MultiByteToWideChar(CP_UTF8, 0, file_path_item->valuestring, -1, path_to_scan, MAX_PATH_LENGTH);
                scan_file_in_directory(path_to_scan, check_hash_failed_files_list, hash_string_list, ServerSocket, ClientSocket);
            }
        }
    }
    iResult = send(ClientSocket, "2", 1, 0); // send code 2 mean scan process finished
    if (iResult == SOCKET_ERROR) {
        fprintf(stderr, "Client: send failed with error: %d\n", WSAGetLastError());
        return 1;
    }

    iResult = shutdown(ServerSocket, SD_SEND);
    if (iResult == SOCKET_ERROR) {
        printf("shutdown failed: %d\n", WSAGetLastError());
    }

    closesocket(ServerSocket);
    closesocket(ClientSocket);
    WSACleanup();

    fwprintf(stdout, L"scan finished\n");
    return 0;
}

int scan_file_batch(wchar_t file_path_queue[MAX_FILE_PATH_IN_QUEUE][MAX_PATH_LENGTH], 
    cJSON* check_hash_failed_files_list, 
    cJSON* hash_string_list, 
    SOCKET ServerSocket, 
    SOCKET ClientSocket, 
    int total_file_path_in_queue,
    int *IsStopScanning,
    int *total_scanned_files,
    int *total_viruses_found,
    cJSON* virus_found_file_paths,
    cJSON* current_scan_progress){

    HANDLE hThreads[MAX_FILE_PATH_IN_QUEUE];
    DWORD ThreadIds[MAX_FILE_PATH_IN_QUEUE];
    DWORD exit_code;
    CheckHashThreadData check_hash_thread_data[MAX_FILE_PATH_IN_QUEUE];
    int iResult;
    cJSON* server_scan_result = NULL;
    int IsAnyHashFailed = 0;
    int IsAllHashFailed = 0; // to prevent sending empty json array to server
    int IsSendOrReceiveHashFailed = 0;
    int IsVirusFoundInThisBatch = 0;
    wchar_t success_file_scanned[MAX_FILE_PATH_IN_QUEUE][MAX_PATH_LENGTH];
    char file_scan_error_action_respone_code; // 1: rescan, 2: skip, 3: cancel
    char *current_scan_progress_string = NULL;
    size_t current_scan_progress_string_length = 0;
    char *json_string_to_send = NULL;
    size_t json_string_length = 0;

    AddWideStringValueToCJSONObject(current_scan_progress, "current_scanning_file", file_path_queue[total_file_path_in_queue - 1]);
    cJSON_AddNumberToObject(current_scan_progress, "total_scanned_files", *total_scanned_files);
    cJSON_AddNumberToObject(current_scan_progress, "total_viruses_found", *total_viruses_found);

    current_scan_progress_string = cJSON_PrintUnformatted(current_scan_progress);
    current_scan_progress_string_length = strlen(current_scan_progress_string);
    if (current_scan_progress_string_length <= INT_MAX){
        iResult = send(ClientSocket, "0", 1, 0); // send code 0 mean send current scan progress to GUI client
        if (iResult == SOCKET_ERROR) {
            fprintf(stderr, "Client: send failed with error: %d\n", WSAGetLastError());
        }
    
        iResult = send(ClientSocket, (const char*)&current_scan_progress_string_length, sizeof(int), 0);
        if (iResult == SOCKET_ERROR) {
            fprintf(stderr, "Client: send failed with error: %d\n", WSAGetLastError());
        }

        iResult = send(ClientSocket, current_scan_progress_string, (int)current_scan_progress_string_length, 0);
        if (iResult == SOCKET_ERROR) {
            fprintf(stderr, "Client: send failed with error: %d\n", WSAGetLastError());
        }
    } else{
        fwprintf(stderr, L"Current scan progress string is too long to send.\n");
    }

    cJSON_free(current_scan_progress_string);
    cJSON_DeleteItemFromObject(current_scan_progress, "current_scanning_file");
    cJSON_DeleteItemFromObject(current_scan_progress, "total_scanned_files");
    cJSON_DeleteItemFromObject(current_scan_progress, "total_viruses_found");

    // prepare for scanning
    clear_json_array(hash_string_list);
    clear_json_array(check_hash_failed_files_list);
    clear_json_array(virus_found_file_paths);

    // prepared done, start scanning
    for (int i = 0; i < total_file_path_in_queue; i++){
        wcscpy(check_hash_thread_data[i].file_path_input, file_path_queue[i]);
        hThreads[i] = CreateThread(
            NULL,
            0,
            check_hash_thread,
            &check_hash_thread_data[i],
            0,
            &ThreadIds[i]
        );
    }

    WaitForMultipleObjects((DWORD)total_file_path_in_queue, hThreads, TRUE, INFINITE);

    for (int i = 0; i < total_file_path_in_queue; i++){
        GetExitCodeThread(hThreads[i], &exit_code);
        if ((int)exit_code == 1){ // add file to check_hash_failed_files_list if check hash failed
            cJSON* check_hash_failed_file_object = cJSON_CreateObject();
            AddWideStringValueToCJSONObject(check_hash_failed_file_object, "file_path", check_hash_thread_data[i].file_path_input);
            cJSON_AddItemToArray(check_hash_failed_files_list, check_hash_failed_file_object);
            IsAnyHashFailed = 1;
        }else{ // if not, add to hash string list to send to server for analysis
            if (strlen(check_hash_thread_data[i].hash_string_output) == SHA256_HASH_STRING_LEN){ // make sure each hash in array are exactly 64 characters long before send
                cJSON* hash_string_object = cJSON_CreateObject();
                cJSON_AddStringToObject(hash_string_object, "hash_str", check_hash_thread_data[i].hash_string_output);
                cJSON_AddItemToArray(hash_string_list, hash_string_object);
                wcscpy(success_file_scanned[i], check_hash_thread_data[i].file_path_input); //FIX ME: Some elements in success_file_scanned can be empty, need to fix it
                *total_scanned_files += 1;
            } else{
                cJSON* check_hash_failed_file_object = cJSON_CreateObject();
                AddWideStringValueToCJSONObject(check_hash_failed_file_object, "file_path", check_hash_thread_data[i].file_path_input);
                cJSON_AddItemToArray(check_hash_failed_files_list, check_hash_failed_file_object);
                IsAnyHashFailed = 1;
            }
        CloseHandle(hThreads[i]);
        }
    }

    if(cJSON_GetArraySize(hash_string_list) == 0){ // if hash_string_list is empty, scan next batch of files immediately to prevent sending empty json array to server (send empty json array will waste server resource)
        iResult = send(ClientSocket, "6", 1, 0); // send code 6 mean entire file batch failed to scan
        if (iResult == SOCKET_ERROR) {
            fprintf(stderr, "Client: send failed with error: %d\n", WSAGetLastError());
        }

        iResult = recv(ClientSocket, &file_scan_error_action_respone_code, 1, 0);
        if (iResult == SOCKET_ERROR) {
                fprintf(stderr, "Client: send failed with error: %d\n", WSAGetLastError());
        }

        if (file_scan_error_action_respone_code == '1'){
            scan_file_batch(file_path_queue, 
                check_hash_failed_files_list, 
                hash_string_list, 
                ServerSocket, 
                ClientSocket, 
                total_file_path_in_queue,
                IsStopScanning,
                total_scanned_files,
                total_viruses_found,
                virus_found_file_paths,
                current_scan_progress);

        } else if (file_scan_error_action_respone_code == '3'){
            *IsStopScanning = 1;
            return 0;
        }

        IsAllHashFailed = 1;
    }

    json_string_to_send = cJSON_PrintUnformatted(hash_string_list);
    json_string_length = strlen(json_string_to_send);

    IsSendOrReceiveHashFailed = 0;
    while (IsAllHashFailed == 0){
        if (json_string_length <= INT_MAX){
            iResult = send(ServerSocket, (const char*)&json_string_length, sizeof(json_string_length), 0);
            if (iResult == SOCKET_ERROR) {
                fprintf(stderr, "Client: send failed with error: %d\n", WSAGetLastError());
                IsSendOrReceiveHashFailed = 1;
                goto finish_send_hash;
            }

            iResult = send(ServerSocket, json_string_to_send, (int)json_string_length, 0); // Sử dụng độ dài được truyền vào
            if (iResult == SOCKET_ERROR) {
                fprintf(stderr, "Client: send failed with error: %d\n", WSAGetLastError());
                IsSendOrReceiveHashFailed = 1;
                goto finish_send_hash;
            }
        }else{
            IsSendOrReceiveHashFailed = 1;
            goto finish_send_hash;
        }
        
        {
            size_t array_len = 0;
            iResult = recv(ServerSocket, (char*)&array_len, sizeof(array_len), 0);
            if (iResult == SOCKET_ERROR) {
                fprintf(stderr, "Client: recv failed with error: %d\n", WSAGetLastError());
                IsSendOrReceiveHashFailed = 1;
                goto finish_send_hash;
            } else if (array_len > INT_MAX){
                fprintf(stderr, "Client: Received array length is too long.\n");
                IsSendOrReceiveHashFailed = 1;
                goto finish_send_hash;
            }

            char recvbuf[array_len];
            iResult = recv(ServerSocket, recvbuf, (int)array_len, 0);

            if (iResult > 0) {
                // PHÂN TÍCH JSON PHẢN HỒI
                server_scan_result = cJSON_Parse(recvbuf);
                if (!server_scan_result) {
                    const char* error_ptr = cJSON_GetErrorPtr();
                    if (error_ptr != NULL) {
                        fprintf(stderr, "Client: Failed to parse JSON response: %s\n", error_ptr);
                    } else {
                        fprintf(stderr, "Client: Failed to parse JSON response (unknown error).\n");
                    }
                    IsSendOrReceiveHashFailed = 1;
                }
            } else{
                IsSendOrReceiveHashFailed = 1;
            }
        }

        finish_send_hash:
        if (IsSendOrReceiveHashFailed == 0){
            break;
        } else{
            // send code 3 mean failed to send or receive hash to/from server
            iResult = send(ClientSocket, "3", 1, 0);
            if (iResult == SOCKET_ERROR) {
                fprintf(stderr, "Client: send failed with error: %d\n", WSAGetLastError());
                break;
            }
            char response_code; // response code from GUI client, 0: continue, 1: skip, 2: stop scanning
            iResult = recv(ClientSocket, &response_code, 1, 0);
            if (iResult == SOCKET_ERROR) {
                fprintf(stderr, "Client: recv failed with error: %d\n", WSAGetLastError());
                break;
            }

            if (response_code == '1'){
                IsSendOrReceiveHashFailed = 0; // reset flag and try to send/receive hash again
            } else if (response_code == '2'){
                // skip this batch of files
                break;
            } else if (response_code == '3'){
                // stop scanning
                *IsStopScanning = 1;
                break;
            }
        }
        
    }
    cJSON_free(json_string_to_send);

    if(*IsStopScanning){
        return 0;
    }

    if (!IsSendOrReceiveHashFailed && !IsAllHashFailed && server_scan_result){
        // process server scan result
        int server_scan_result_element_array_element_index = 0;
        cJSON* server_scan_result_element = NULL;
        cJSON_ArrayForEach(server_scan_result_element, server_scan_result){
            cJSON* server_scan_result_file_status_item = cJSON_GetObjectItemCaseSensitive(server_scan_result_element, "status");
            if (strcmp(server_scan_result_file_status_item->valuestring, "infected") == 0){
                cJSON* server_scan_result_virus_name_item = cJSON_GetObjectItemCaseSensitive(server_scan_result_element, "virus_id");
                cJSON* virus_found_file_object = cJSON_CreateObject();
                AddWideStringValueToCJSONObject(virus_found_file_object, "file_path", success_file_scanned[server_scan_result_element_array_element_index]);
                cJSON_AddStringToObject(virus_found_file_object, "virus_name", server_scan_result_virus_name_item->valuestring);
                cJSON_AddItemToArray(virus_found_file_paths, virus_found_file_object);
                *total_viruses_found += 1;
                IsVirusFoundInThisBatch = 1;
            }
            server_scan_result_element_array_element_index += 1;
        }

        cJSON_Delete(server_scan_result);

        if (IsVirusFoundInThisBatch){
            // send code 4 mean found virus in this batch
            iResult = send(ClientSocket, "4", 1, 0);
            if (iResult == SOCKET_ERROR) {
                fprintf(stderr, "Client: send failed with error: %d\n", WSAGetLastError());
            }

            char *virus_found_file_paths_string = cJSON_PrintUnformatted(virus_found_file_paths);
            size_t virus_found_file_paths_string_length = strlen(virus_found_file_paths_string);

            if(virus_found_file_paths_string_length <= INT_MAX){
                iResult = send(ClientSocket, (const char*)&virus_found_file_paths_string_length, sizeof(int), 0);
                if (iResult == SOCKET_ERROR) {
                    fprintf(stderr, "Client: send failed with error: %d\n", WSAGetLastError());
                }

                iResult = send(ClientSocket, virus_found_file_paths_string, (int)virus_found_file_paths_string_length, 0);
                if (iResult == SOCKET_ERROR) {
                    fprintf(stderr, "Client: send failed with error: %d\n", WSAGetLastError());
                }
            }else{
                fwprintf(stderr, L"Virus found file paths string is too long to send.\n");
            }

            cJSON_free(virus_found_file_paths_string);
        }
    }
    
    if (IsAnyHashFailed){
        cJSON *check_hash_failed_file_element = check_hash_failed_files_list->child;
        while (check_hash_failed_file_element != NULL) {
            cJSON *check_hash_failed_file_item = cJSON_GetObjectItemCaseSensitive(check_hash_failed_file_element, "file_path");
            if (cJSON_IsString(check_hash_failed_file_item) && (check_hash_failed_file_item->valuestring != NULL)){
                cJSON_AddStringToObject(current_scan_progress, "current_scanning_file", check_hash_failed_file_item->valuestring);
                cJSON_AddNumberToObject(current_scan_progress, "total_scanned_files", *total_scanned_files);
                cJSON_AddNumberToObject(current_scan_progress, "total_viruses_found", *total_viruses_found);

                current_scan_progress_string = cJSON_PrintUnformatted(current_scan_progress);
                current_scan_progress_string_length = strlen(current_scan_progress_string);

                if (current_scan_progress_string_length <= INT_MAX){
                    iResult = send(ClientSocket, "0", 1, 0); // send code 0 mean send current scan progress to GUI client
                    if (iResult == SOCKET_ERROR) {
                        fprintf(stderr, "Client: send failed with error: %d\n", WSAGetLastError());
                        *IsStopScanning = 1;
                        cJSON_free(current_scan_progress_string);
                        break;
                    }
                
                    iResult = send(ClientSocket, (const char*)&current_scan_progress_string_length, sizeof(int), 0);
                    if (iResult == SOCKET_ERROR) {
                        fprintf(stderr, "Client: send failed with error: %d\n", WSAGetLastError());
                    }

                    iResult = send(ClientSocket, current_scan_progress_string, (int)current_scan_progress_string_length, 0);
                    if (iResult == SOCKET_ERROR) {
                        fprintf(stderr, "Client: send failed with error: %d\n", WSAGetLastError());
                    }
                } else{
                    fwprintf(stderr, L"Current scan progress string is too long to send.\n");
                }

                cJSON_free(current_scan_progress_string);
                cJSON_DeleteItemFromObject(current_scan_progress, "current_scanning_file");
                cJSON_DeleteItemFromObject(current_scan_progress, "total_scanned_files");
                cJSON_DeleteItemFromObject(current_scan_progress, "total_viruses_found");
            
                int IsScanHashFailed = 0;
                IsVirusFoundInThisBatch = 0;

                wchar_t check_hash_failed_file_item_widechar_string[MAX_PATH_LENGTH];
                MultiByteToWideChar(CP_UTF8, 0, check_hash_failed_file_item->valuestring, -1, check_hash_failed_file_item_widechar_string, MAX_PATH_LENGTH);

                // start scanning
                wcscpy(check_hash_thread_data[0].file_path_input, check_hash_failed_file_item_widechar_string);
                hThreads[0] = CreateThread(
                    NULL,
                    0,
                    check_hash_thread,
                    &check_hash_thread_data,
                    0,
                    &ThreadIds[0]
                );

                WaitForSingleObject(hThreads[0], INFINITE);

                GetExitCodeThread(hThreads[0], &exit_code);
                
                if ((int)exit_code == 1){ // add file to check_hash_failed_files_list if check hash failed
                    IsScanHashFailed = 1;
                    goto send_scan_result_to_gui;
                }else{ // if not add to hash string list to send to server for analysis
                    if (strlen(check_hash_thread_data[0].hash_string_output) == SHA256_HASH_STRING_LEN){ // make sure each hash in array are exactly 64 characters long before send
                        cJSON* hash_string_object = cJSON_CreateObject();
                        cJSON_AddStringToObject(hash_string_object, "hash_str",check_hash_thread_data[0].hash_string_output);
                        cJSON_AddItemToArray(hash_string_list, hash_string_object);
                    } else{
                        IsScanHashFailed = 1;
                        goto send_scan_result_to_gui;
                    }

                }

                CloseHandle(hThreads[0]);

                json_string_to_send = cJSON_PrintUnformatted(hash_string_list);
                json_string_length = strlen(json_string_to_send);

                while (1){
                    if (json_string_length <= INT_MAX){
                        iResult = send(ServerSocket, (const char*)&json_string_length, sizeof(int), 0);
                        if (iResult == SOCKET_ERROR) {
                            fprintf(stderr, "Client: send failed with error: %d\n", WSAGetLastError());
                            IsSendOrReceiveHashFailed = 1;
                            goto finish_send_hash;
                        }

                        iResult = send(ServerSocket, json_string_to_send, (int)json_string_length, 0); // Sử dụng độ dài được truyền vào
                        if (iResult == SOCKET_ERROR) {
                            fprintf(stderr, "Client: send failed with error: %d\n", WSAGetLastError());
                            IsSendOrReceiveHashFailed = 1;
                            goto finish_send_hash;
                        }
                    }else{
                        IsSendOrReceiveHashFailed = 1;
                        goto finish_send_hash;
                    }

                    size_t array_len;
                    iResult = recv(ServerSocket, (char*)&array_len, sizeof(array_len), 0);
                    if (iResult == SOCKET_ERROR) {
                        fprintf(stderr, "Client: recv failed with error: %d\n", WSAGetLastError());
                        IsSendOrReceiveHashFailed = 1;
                        goto finish_send_hash;
                    } else if (array_len > INT_MAX){
                        fprintf(stderr, "Client: Received array length is too long.\n");
                        IsSendOrReceiveHashFailed = 1;
                        goto finish_send_hash;
                    }
                    
                    char recvbuf[array_len];
                    iResult = recv(ServerSocket, recvbuf, (int)array_len, 0);

                    if (iResult > 0) {
                        // PHÂN TÍCH JSON PHẢN HỒI
                        server_scan_result = cJSON_Parse(recvbuf);
                        if (!server_scan_result) {
                            const char* error_ptr = cJSON_GetErrorPtr();
                            if (error_ptr != NULL) {
                                fprintf(stderr, "Client: Failed to parse JSON response: %s\n", error_ptr);
                            } else {
                                fprintf(stderr, "Client: Failed to parse JSON response (unknown error).\n");
                            }
                            IsScanHashFailed = 1;
                        }
                    } else{
                        IsScanHashFailed = 1;
                    }

                    break;
                }

                cJSON_free(json_string_to_send);

                // process server scan result
                int server_scan_result_array_element_index = 0;
                cJSON* server_scan_result_element = NULL;
                cJSON_ArrayForEach(server_scan_result_element, server_scan_result){
                    cJSON* server_scan_result_file_status_item = cJSON_GetObjectItemCaseSensitive(server_scan_result_element, "status");
                    if (strcmp(server_scan_result_file_status_item->valuestring, "infected") == 0){
                        cJSON* server_scan_result_virus_name_item = cJSON_GetObjectItemCaseSensitive(server_scan_result_element, "virus_id");
                        cJSON* virus_found_file_object = cJSON_CreateObject();
                        AddWideStringValueToCJSONObject(virus_found_file_object, "file_path", success_file_scanned[server_scan_result_array_element_index]);
                        cJSON_AddStringToObject(virus_found_file_object, "virus_name", server_scan_result_virus_name_item->valuestring);
                        cJSON_AddItemToArray(virus_found_file_paths, virus_found_file_object);
                        *total_viruses_found += 1;
                        IsVirusFoundInThisBatch = 1;
                    }
                    server_scan_result_array_element_index += 1;
                }

                cJSON_Delete(server_scan_result);

                if (IsVirusFoundInThisBatch){
                    // send code 4 mean found virus in this batch
                    iResult = send(ClientSocket, "4", 1, 0);
                    if (iResult == SOCKET_ERROR) {
                        fprintf(stderr, "Client: send failed with error: %d\n", WSAGetLastError());
                    }

                    char *virus_found_file_paths_string = cJSON_PrintUnformatted(virus_found_file_paths);
                    size_t virus_found_file_paths_string_length = strlen(virus_found_file_paths_string);

                    if(virus_found_file_paths_string_length <= INT_MAX){
                        iResult = send(ClientSocket, (const char*)&virus_found_file_paths_string_length, sizeof(int), 0);
                        if (iResult == SOCKET_ERROR) {
                            fprintf(stderr, "Client: send failed with error: %d\n", WSAGetLastError());
                        }

                        iResult = send(ClientSocket, virus_found_file_paths_string, (int)virus_found_file_paths_string_length, 0);
                        if (iResult == SOCKET_ERROR) {
                            fprintf(stderr, "Client: send failed with error: %d\n", WSAGetLastError());
                        }
                    }else{
                        fwprintf(stderr, L"Virus found file paths string is too long to send.\n");
                    }

                    cJSON_free(virus_found_file_paths_string);
                }

                send_scan_result_to_gui:
                if (IsScanHashFailed == 1){
                    char *check_hash_failed_file_element_string = cJSON_PrintUnformatted(check_hash_failed_file_element);
                    size_t check_hash_failed_file_element_string_length = strlen(check_hash_failed_file_element_string);
                    if (check_hash_failed_file_element_string_length <= INT_MAX){
                        // send code 5 mean file failed to scan
                        iResult = send(ClientSocket, "5", 1, 0);
                        if (iResult == SOCKET_ERROR) {
                            fprintf(stderr, "Client: send failed with error: %d\n", WSAGetLastError());
                        }

                        iResult = send(ClientSocket, check_hash_failed_file_element_string, (int)check_hash_failed_file_element_string_length, 0);
                        if (iResult == SOCKET_ERROR) {
                            fprintf(stderr, "Client: send failed with error: %d\n", WSAGetLastError());
                        }

                        iResult = recv(ClientSocket, &file_scan_error_action_respone_code, 1, 0);
                        if (iResult == SOCKET_ERROR) {
                            fprintf(stderr, "Client: send failed with error: %d\n", WSAGetLastError());
                        }
                        
                        if (file_scan_error_action_respone_code == '1'){
                            cJSON_free(check_hash_failed_file_element_string);
                            continue;
                        }else if (file_scan_error_action_respone_code == '3'){
                            cJSON_free(check_hash_failed_file_element_string);
                            *IsStopScanning = 1;
                            break;
                        }else{
                            cJSON_free(check_hash_failed_file_element_string);
                        }
                    } else{
                        fwprintf(stderr, L"Check hash failed file element string is too long to send.\n");
                    }

                }else{
                    *total_scanned_files++;
                }
            }
            check_hash_failed_file_element = check_hash_failed_file_element->next;
        }
    }

    // Send current scan progress to GUI client after finish scanning this batch of files (mostly to update total scanned files and total viruses found)
    AddWideStringValueToCJSONObject(current_scan_progress, "current_scanning_file", file_path_queue[total_file_path_in_queue - 1]);
    cJSON_AddNumberToObject(current_scan_progress, "total_scanned_files", *total_scanned_files);
    cJSON_AddNumberToObject(current_scan_progress, "total_viruses_found", *total_viruses_found);

    current_scan_progress_string = cJSON_PrintUnformatted(current_scan_progress);
    current_scan_progress_string_length = strlen(current_scan_progress_string);
    if (current_scan_progress_string_length <= INT_MAX){
        iResult = send(ClientSocket, "0", 1, 0); // send code 0 mean send current scan progress to GUI client
        if (iResult == SOCKET_ERROR) {
            fprintf(stderr, "Client: send failed with error: %d\n", WSAGetLastError());
        }
    
        iResult = send(ClientSocket, (const char*)&current_scan_progress_string_length, sizeof(int), 0);
        if (iResult == SOCKET_ERROR) {
            fprintf(stderr, "Client: send failed with error: %d\n", WSAGetLastError());
        }

        iResult = send(ClientSocket, current_scan_progress_string, (int)current_scan_progress_string_length, 0);
        if (iResult == SOCKET_ERROR) {
            fprintf(stderr, "Client: send failed with error: %d\n", WSAGetLastError());
        }
    } else{
        fwprintf(stderr, L"Current scan progress string is too long to send.\n");
    }

    cJSON_free(current_scan_progress_string);
    cJSON_DeleteItemFromObject(current_scan_progress, "current_scanning_file");
    cJSON_DeleteItemFromObject(current_scan_progress, "total_scanned_files");
    cJSON_DeleteItemFromObject(current_scan_progress, "total_viruses_found");

    return 0;
}

int scan_file_in_directory(const wchar_t* path, cJSON* check_hash_failed_files_list, cJSON* hash_string_list, SOCKET ServerSocket, SOCKET ClientSocket) {
    static int IsStopScanning = 0; // flag to stop scanning when receive stop signal from GUI client, should be static to keep its value between function calls and placed at the beginning of the function to check before doing anything

    if (IsStopScanning){
        return 0;
    }

    wchar_t searchPath[MAX_PATH_LENGTH];
    WIN32_FIND_DATAW findData;
    HANDLE hFind = INVALID_HANDLE_VALUE;

    static int current_recursion_depth = 0;

    // Tạo đường dẫn tìm kiếm dạng: "C:\Folder\*"
    // swprintf_s an toàn hơn để nối chuỗi Unicode
    if (swprintf_s(searchPath, MAX_PATH_LENGTH, L"%ls\\*", path) < 0) {
        // Xử lý lỗi nếu việc tạo chuỗi thất bại
        fwprintf(stderr, L"Lỗi: Không đủ bộ nhớ hoặc lỗi định dạng đường dẫn.\n");
        return 1;
    }

    // Bắt đầu tìm kiếm file đầu tiên
    hFind = FindFirstFileW(searchPath, &findData);

    if (hFind == INVALID_HANDLE_VALUE) {
        // wprintf(L"Khong the mo thu muc: %ls\n", path);
        return 1;
    }

    // use static variable because this function is recursive
    static wchar_t file_path_queue[MAX_FILE_PATH_IN_QUEUE][MAX_PATH_LENGTH];
    static int total_file_path_in_queue = 0;
    static int total_scanned_files = 0;
    static int total_viruses_found = 0;

    int iResult;
    cJSON* virus_found_file_paths = cJSON_CreateArray(); // to store file paths with its virus name (if file is virus) that found virus in this batch to send to GUI client
    cJSON* current_scan_progress = cJSON_CreateObject(); // to store current scan progress info to send to GUI client (including current scanning file, total scanned files, total viruses found)
    char should_continue_scanning_respone_code; // 0: continue scanning, 1: stop scanning

    do {
        // Bỏ qua thư mục hiện tại "." và thư mục cha ".."
        if (wcscmp(findData.cFileName, L".") == 0 || wcscmp(findData.cFileName, L"..") == 0) {
            continue;
        }

        // Tạo đường dẫn đầy đủ của file/thư mục tìm thấy
        wchar_t fullPath[MAX_PATH_LENGTH];
        // DÙNG %ls cho wide-strings; tránh truyền chuỗi trực tiếp làm format string
        if (swprintf_s(fullPath, MAX_PATH_LENGTH, L"%ls\\%ls", path, findData.cFileName) < 0) {
            fwprintf(stderr, L"Lỗi: Không đủ bộ nhớ hoặc lỗi định dạng đường dẫn đầy đủ.\n");
            continue; // Bỏ qua file/thư mục này và tiếp tục
        }

        if (findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            // Nếu là thư mục -> Gọi đệ quy
            current_recursion_depth++;
            scan_file_in_directory(fullPath, check_hash_failed_files_list, hash_string_list, ServerSocket, ClientSocket);
            current_recursion_depth--;
        } else {
            wcscpy(file_path_queue[total_file_path_in_queue], fullPath);
            total_file_path_in_queue += 1;

            if (total_file_path_in_queue == MAX_FILE_PATH_IN_QUEUE){
                scan_file_batch(file_path_queue, 
                                check_hash_failed_files_list, 
                                hash_string_list, 
                                ServerSocket, 
                                ClientSocket, 
                                total_file_path_in_queue,
                                &IsStopScanning,
                                &total_scanned_files,
                                &total_viruses_found,
                                virus_found_file_paths,
                                current_scan_progress);

                memset(file_path_queue, 0, sizeof(file_path_queue));
                total_file_path_in_queue = 0;

                // send code 1 mean should continue scanning or stop scanning from GUI client
                iResult = send(ClientSocket, "1", 1, 0);
                if (iResult == SOCKET_ERROR) {
                    fprintf(stderr, "Client: send failed with error: %d\n", WSAGetLastError()); 
                    break;
                }

                iResult = recv(ClientSocket, &should_continue_scanning_respone_code, 1, 0);
                if (iResult == SOCKET_ERROR) {
                    fprintf(stderr, "Client: recv failed with error: %d\n", WSAGetLastError());
                    break;
                }

                if (should_continue_scanning_respone_code == '1'){
                    IsStopScanning = 1;
                }
            }
        }

    } while (FindNextFileW(hFind, &findData) != 0 && !IsStopScanning);

    if (total_file_path_in_queue > 0 && current_recursion_depth == 0 && !IsStopScanning){ // only scan leftover files when current recursion depth is 0
        scan_file_batch(file_path_queue, 
                        check_hash_failed_files_list, 
                        hash_string_list, 
                        ServerSocket, 
                        ClientSocket, 
                        total_file_path_in_queue,
                        &IsStopScanning,
                        &total_scanned_files,
                        &total_viruses_found,
                        virus_found_file_paths,
                        current_scan_progress);
    }

    // Xử lý lỗi nếu việc duyệt kết thúc không phải do hết file
    DWORD dwError = GetLastError();
    if (dwError != ERROR_NO_MORE_FILES && dwError != ERROR_SUCCESS) {
        wprintf(L"Loi khi duyet file: %lu\n", dwError);
    }

    FindClose(hFind);

    cJSON_Delete(current_scan_progress);
    cJSON_Delete(virus_found_file_paths);

    return 0;
}

int scan_single_file(const wchar_t* path, cJSON* hash_string_list, SOCKET ServerSocket, SOCKET ClientSocket){
    HANDLE hThread;
    DWORD ThreadId;
    DWORD exit_code;
    CheckHashThreadData check_hash_thread_data;
    int iResult;
    char* server_scan_result;
    int IsScanHashFailed = 0;

    // start scanning
    wcscpy(check_hash_thread_data.file_path_input, path);
    hThread = CreateThread(
        NULL,
        0,
        check_hash_thread,
        &check_hash_thread_data,
        0,
        &ThreadId
    );

    WaitForSingleObject(hThread, INFINITE);

    GetExitCodeThread(hThread, &exit_code);
    
    if ((int)exit_code == 1){ // add file to check_hash_failed_files_list if check hash failed
        IsScanHashFailed = 1;
        goto send_scan_result_to_gui;
    }else{ // if not add to hash string list to send to server for analysis
        if (strlen(check_hash_thread_data.hash_string_output) == SHA256_HASH_STRING_LEN){ // make sure each hash in array are exactly 64 characters long before send
            cJSON* hash_string_object = cJSON_CreateObject();
            cJSON_AddStringToObject(hash_string_object, "hash_str",check_hash_thread_data.hash_string_output);
            cJSON_AddItemToArray(hash_string_list, hash_string_object);
        } else{
            IsScanHashFailed = 1;
            goto send_scan_result_to_gui;
        }

    }

    char* json_string_to_send = cJSON_PrintUnformatted(hash_string_list);
    size_t length = strlen(json_string_to_send);

    if (length > INT_MAX){
        fprintf(stderr, "Client: JSON string to send is too long.\n");
        IsScanHashFailed = 1;
        goto send_scan_result_to_gui;
    }

    while (1){
        iResult = send(ServerSocket, (const char*)&length, sizeof(long long), 0);
        if (iResult == SOCKET_ERROR) {
            fprintf(stderr, "Client: send failed with error: %d\n", WSAGetLastError());
            IsScanHashFailed = 1;
            break;
        }

        iResult = send(ServerSocket, json_string_to_send, (int)length, 0); // Sử dụng độ dài được truyền vào
        if (iResult == SOCKET_ERROR) {
            fprintf(stderr, "Client: send failed with error: %d\n", WSAGetLastError());
            IsScanHashFailed = 1;
            break;
        }

        size_t array_len;
        iResult = recv(ServerSocket, (char*)&array_len, sizeof(array_len), 0);
        if (iResult == SOCKET_ERROR) {
            fprintf(stderr, "Client: recv failed with error: %d\n", WSAGetLastError());
            IsScanHashFailed = 1;
            break;
        } else if (array_len > INT_MAX){
            fprintf(stderr, "Client: Received array length is too long.\n");
            IsScanHashFailed = 1;
            break;
        }

        char recvbuf[array_len];
        iResult = recv(ServerSocket, recvbuf, (int)array_len, 0);
        if (iResult > 0) {
            // PHÂN TÍCH JSON PHẢN HỒI
            cJSON* root = cJSON_Parse(recvbuf);
            if (root) {
                server_scan_result = cJSON_PrintUnformatted(root);
            } else {
                const char* error_ptr = cJSON_GetErrorPtr();
                if (error_ptr != NULL) {
                    fprintf(stderr, "Client: Failed to parse JSON response: %s\n", error_ptr);
                } else {
                    fprintf(stderr, "Client: Failed to parse JSON response (unknown error).\n");
                }
                IsScanHashFailed = 1;
            }
            cJSON_Delete(root);
        } else {
            IsScanHashFailed = 1;
        }
        break;
    }

    // send code in single file scan is different with directory scan

    send_scan_result_to_gui:
    // send code 0 mean scan process finished
    iResult = send(ClientSocket, "0", 1, 0);
    if (iResult == SOCKET_ERROR) {
        fprintf(stderr, "Client: send failed with error: %d\n", WSAGetLastError());
        return 1;
    }

    // send scan status back to GUI client
    if (IsScanHashFailed == 1){
        iResult = send(ClientSocket, "1", 1, 0);
        if (iResult == SOCKET_ERROR) {
            fprintf(stderr, "Client: send failed with error: %d\n", WSAGetLastError());
        }
        return 1;
    }

    iResult = send(ClientSocket, "0", 1, 0);
    if (iResult == SOCKET_ERROR) {
        fprintf(stderr, "Client: send failed with error: %d\n", WSAGetLastError());
    }

    // send scan result to GUI client
    iResult = send(ClientSocket, server_scan_result, (int)strlen(server_scan_result), 0);
    if (iResult == SOCKET_ERROR) {
        fprintf(stderr, "Client: send failed with error: %d\n", WSAGetLastError());
    }

    cJSON_free(server_scan_result);
    cJSON_free(json_string_to_send);
    CloseHandle(hThread);
    
    return 0;
}

SOCKET initialize_connection_to_virus_scan_server(){
    int iResult;
    SOCKET ConnectSocket = INVALID_SOCKET;
    struct addrinfo *result = NULL, *ptr = NULL, hints;

    // 1. Cấu hình địa chỉ server
    ZeroMemory(&hints, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;

    iResult = getaddrinfo(VIRUS_SCAN_SERVER_IP, DEFAULT_VIRUS_SCAN_SERVER_PORT, &hints, &result);
    if (iResult != 0) {
        fprintf(stderr, "Client: getaddrinfo failed with error: %d\n", iResult);
        WSACleanup();
        return ConnectSocket;
    }

    // 2. Lặp qua các địa chỉ và thử kết nối
    for (ptr = result; ptr != NULL; ptr = ptr->ai_next) {
        ConnectSocket = socket(ptr->ai_family, ptr->ai_socktype, ptr->ai_protocol);
        if (ConnectSocket == INVALID_SOCKET) {
            fprintf(stderr, "Client: socket failed with error: %d\n", WSAGetLastError());
            WSACleanup();
            return ConnectSocket;
        }

        iResult = connect(ConnectSocket, ptr->ai_addr, (int)ptr->ai_addrlen);
        if (iResult == SOCKET_ERROR) {
            closesocket(ConnectSocket);
            ConnectSocket = INVALID_SOCKET;
            continue; // Thử địa chỉ tiếp theo
        }
        break; // Kết nối thành công
    }

    freeaddrinfo(result); // Giải phóng bộ nhớ của getaddrinfo

    return ConnectSocket;
}
