#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <windows.h> // Cần thiết cho Winsock
#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "cJSON.h"
#include <unistd.h>
#include "sqlite3.h"

#define DEFAULT_PORT "27015"
#define SHA256_HASH_STRING_LEN 64


// Đảm bảo liên kết với thư viện Ws2_32.lib
#pragma comment (lib, "Ws2_32.lib")

typedef struct{
    char hash_string_in[SHA256_HASH_STRING_LEN + 1];
    char virus_id_result_out[100];
    int virus_detected_out;
    sqlite3 *db;
} CheckHashInDatabaseThreadData;

typedef struct{
    SOCKET clientsocket;
    sqlite3 *db;
} HandleClientConnectionThreadData;

typedef struct{
    int *total_virus_in_database;
    sqlite3 *db;
} CountTotalVirusInDatabaseThreadData;

// Khai báo hàm để xử lý mỗi client
// client_socket: Socket đã được accept từ client
// Trả về 0 nếu xử lý thành công, khác 0 nếu có lỗi
int handle_client_connection(SOCKET client_socket, sqlite3 *db);

//Khai báo thread để xử lý nhiều client
unsigned __stdcall handle_client_thread(LPVOID lpParam);

//Khai báo Thread để xử lý các mã hash trong array
DWORD WINAPI check_hash_in_database_thread(LPVOID lpParam);

int connection_current_count = 0;
int total_connection_count = 0;

int check_hash_in_table(sqlite3 *db, const char *table, const char *sha256_hash, char *virus_id_output) {
    sqlite3_stmt *stmt;
    char *sql_select_dynamic = NULL; // Dùng để xây dựng câu lệnh SQL động
    // 1. Xây dựng câu lệnh SQL động
    // Ước tính kích thước đủ lớn cho chuỗi SQL: "SELECT sha256_hash, virus_id FROM " + table_name + " WHERE sha256_hash = ?;" + null terminator
    size_t sql_len = strlen("SELECT sha256_hash, virus_id FROM  WHERE sha256_hash = ?;") + strlen(table) + 1;
    sql_select_dynamic = (char*)malloc(sql_len);
    if (!sql_select_dynamic) {
        fprintf(stderr, "Lỗi cấp phát bộ nhớ cho câu lệnh SQL.\n");
        return SQLITE_NOMEM; // Trả về lỗi hết bộ nhớ của SQLite
    }

    // Sử dụng snprintf để xây dựng chuỗi SQL an toàn
    snprintf(sql_select_dynamic, sql_len, "SELECT sha256_hash, virus_id FROM %s WHERE sha256_hash = ?;", table);

    if (sqlite3_prepare_v2(db, sql_select_dynamic, -1, &stmt, NULL) != SQLITE_OK) {
        fprintf(stderr, "Lỗi prepare: %s\n", sqlite3_errmsg(db));
        free(sql_select_dynamic);
        return -1;
    }
    if (sqlite3_bind_text(stmt, 1, sha256_hash, -1, SQLITE_STATIC)) {
        fprintf(stderr, "Lỗi khi gắn hash_to_find: %s\n", sqlite3_errmsg(db));
        sqlite3_finalize(stmt); // Đảm bảo giải phóng statement nếu có lỗi
        free(sql_select_dynamic);
        return -1;
    }

    if (sqlite3_step(stmt) == SQLITE_ROW) {
        strcpy(virus_id_output, sqlite3_column_text(stmt, 1));
        free(sql_select_dynamic);
        sqlite3_finalize(stmt);
        return 1;
    } else {
        free(sql_select_dynamic);
        sqlite3_finalize(stmt);
        return 0;
    }
}

int count_rows(sqlite3 *db, const char *table_name) {
    sqlite3_stmt *stmt;
    char sql[128];
    int count = 0;

    snprintf(sql, sizeof(sql), "SELECT COUNT(*) FROM %s;", table_name);

    if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) != SQLITE_OK) {
        sqlite3_finalize(stmt);
        return -1;
    }

    if (sqlite3_step(stmt) == SQLITE_ROW) {
        count = sqlite3_column_int(stmt, 0);
    }

    sqlite3_finalize(stmt);
    return count;
}

DWORD WINAPI count_total_virus_in_database_thread(LPVOID lpParam) {
    CountTotalVirusInDatabaseThreadData* count_total_virus_in_database_thread_data = (CountTotalVirusInDatabaseThreadData *)lpParam;

    int total_virus_in_database_temp = 0;

    while (TRUE){
        int total_virus_in_database_temp = 0;
        // total_virus_in_database_temp += count_rows(count_total_virus_in_database_thread_data->db, "Malware_hashes");
        total_virus_in_database_temp += count_rows(count_total_virus_in_database_thread_data->db, "EICAR");

        total_virus_in_database_temp += count_rows(count_total_virus_in_database_thread_data->db, "EICAR");
        total_virus_in_database_temp += count_rows(count_total_virus_in_database_thread_data->db, "Ransomware");
        total_virus_in_database_temp += count_rows(count_total_virus_in_database_thread_data->db, "Trojan");
        total_virus_in_database_temp += count_rows(count_total_virus_in_database_thread_data->db, "Backdoor");
        total_virus_in_database_temp += count_rows(count_total_virus_in_database_thread_data->db, "Spyware");
        total_virus_in_database_temp += count_rows(count_total_virus_in_database_thread_data->db, "JS");
        total_virus_in_database_temp += count_rows(count_total_virus_in_database_thread_data->db, "Miscellaneous");
        total_virus_in_database_temp += count_rows(count_total_virus_in_database_thread_data->db, "Miner");
        total_virus_in_database_temp += count_rows(count_total_virus_in_database_thread_data->db, "Jokeware");
        total_virus_in_database_temp += count_rows(count_total_virus_in_database_thread_data->db, "Worm");

        *count_total_virus_in_database_thread_data->total_virus_in_database += total_virus_in_database_temp - *count_total_virus_in_database_thread_data->total_virus_in_database;

        Sleep(60000); //wait 60 secs before count again
    }
}

int main() {
    WSADATA wsaData;
    int iResult;
    SOCKET ListenSocket = INVALID_SOCKET;
    struct addrinfo *result = NULL, hints;

    // 1. Khởi tạo Winsock (CHỈ MỘT LẦN KHI SERVER BẮT ĐẦU)
    iResult = WSAStartup(MAKEWORD(2, 2), &wsaData);
    if (iResult != 0) {
        fprintf(stderr, "Server: WSAStartup failed with error: %d\n", iResult);
        return 1;
    }
    // printf("Server: Winsock initialized.\n");

    // 2. Cấu hình địa chỉ server
    ZeroMemory(&hints, sizeof(hints));
    hints.ai_family = AF_INET; // IPv4
    hints.ai_socktype = SOCK_STREAM; // Stream socket (TCP)
    hints.ai_protocol = IPPROTO_TCP; // TCP protocol
    hints.ai_flags = AI_PASSIVE; // Server lắng nghe trên tất cả các interface

    iResult = getaddrinfo(NULL, DEFAULT_PORT, &hints, &result);
    if (iResult != 0) {
        fprintf(stderr, "Server: getaddrinfo failed with error: %d\n", iResult);
        WSACleanup();
        return 1;
    }
    // printf("Server: Address info obtained for port %s.\n", DEFAULT_PORT);

    // 3. Tạo Socket để lắng nghe kết nối
    ListenSocket = socket(result->ai_family, result->ai_socktype, result->ai_protocol);
    if (ListenSocket == INVALID_SOCKET) {
        fprintf(stderr, "Server: socket failed with error: %ld\n", WSAGetLastError());
        freeaddrinfo(result);
        WSACleanup();
        return 1;
    }
    // printf("Server: Listen socket created.\n");

    // 4. Gán socket vào địa chỉ và cổng
    iResult = bind(ListenSocket, result->ai_addr, (int)result->ai_addrlen);
    if (iResult == SOCKET_ERROR) {
        fprintf(stderr, "Server: bind failed with error: %d\n", WSAGetLastError());
        freeaddrinfo(result);
        closesocket(ListenSocket);
        WSACleanup();
        return 1;
    }
    // printf("Server: Socket bound to port %s.\n", DEFAULT_PORT);

    freeaddrinfo(result); // Giải phóng bộ nhớ của getaddrinfo

    // 5. Chuyển socket sang trạng thái lắng nghe
    iResult = listen(ListenSocket, SOMAXCONN); // SOMAXCONN là số lượng kết nối tối đa
    if (iResult == SOCKET_ERROR) {
        fprintf(stderr, "Server: listen failed with error: %d\n", WSAGetLastError());
        closesocket(ListenSocket);
        WSACleanup();
        return 1;
    }
    // printf("Server: Listening for incoming connections on port %s...\n", DEFAULT_PORT);

    sqlite3 *db; //open database only once to reduce overhead of opening / closing database every time
    sqlite3_open_v2("file:qsecurity_database.db?nolock=1", &db, SQLITE_OPEN_READONLY | SQLITE_OPEN_URI, NULL);

    HandleClientConnectionThreadData handle_client_connection_thread_data;
    CountTotalVirusInDatabaseThreadData count_total_virus_in_database_thread_data;

    //create a thread for counting total virus in database
    int total_virus_in_database = 0;
    count_total_virus_in_database_thread_data.db = db;
    count_total_virus_in_database_thread_data.total_virus_in_database = &total_virus_in_database;

    HANDLE hThread;
    hThread = CreateThread(
        NULL,
        0,
        count_total_virus_in_database_thread,
        &count_total_virus_in_database_thread_data,
        0,
        NULL
    );

    CloseHandle(hThread); // we don't need to manage the thread anymore (fire and forget)

    // *******************************************************************
    // VÒNG LẶP CHÍNH CỦA SERVER: LUÔN CHẠY ĐỂ CHẤP NHẬN KẾT NỐI MỚI
    // *******************************************************************
    while (TRUE) { // Vòng lặp vô hạn

        printf("                                                  Server console\n");
        printf("/*Infomation:                                                                                                         */");
        // printf("Server ip: 192.168.100.7\n");
        printf("Server port: %s\n", DEFAULT_PORT);
        printf("connection(s) current count: %d\n", connection_current_count);
        printf("total connection(s) count: %d\n", total_connection_count);
        printf("total virus in database count: %d\n", total_virus_in_database);
        printf("/*                                                                                                                    */");
        printf("                       QSecurity server console. A part of QSecurity project. Since 2025\n");
        // printf("\nServer: Waiting for a new client connection...\n");

        SOCKET ClientSocket = INVALID_SOCKET;
        // Chấp nhận kết nối từ client
        ClientSocket = accept(ListenSocket, NULL, NULL); // Hàm này sẽ chặn cho đến khi có kết nối
        if (ClientSocket == INVALID_SOCKET) {
            fprintf(stderr, "Server: accept failed with error: %d\n", WSAGetLastError());
            // Có thể thêm kiểm tra lỗi cụ thể ở đây nếu muốn thoát server.
            // Ví dụ: if (WSAGetLastError() == WSAEINTR) break; // Nếu server bị ngắt
            Sleep(100); // Đợi một chút để tránh lặp quá nhanh nếu lỗi liên tục
            continue; // Bỏ qua lỗi hiện tại và thử chấp nhận kết nối tiếp theo
        }
        total_connection_count++;

        // printf("Server: Client connected! ClientSocket ID: %d\n", (int)ClientSocket);

        // Gọi hàm để xử lý giao tiếp với client này
        // *** TẠI ĐÂY LÀ NƠI BẠN CÓ THỂ TRIỂN KHAI MULTITHREADING ***
        // Nếu bạn muốn server xử lý nhiều client đồng thời, bạn sẽ tạo một thread mới
        // và truyền ClientSocket vào thread đó để hàm handle_client_connection được gọi trong thread mới.
        // Ví dụ: _beginthreadex(NULL, 0, handle_client_thread, (void*)ClientSocket, 0, NULL);
        handle_client_connection_thread_data.clientsocket = ClientSocket;
        handle_client_connection_thread_data.db = db;

        uintptr_t hThread;

        hThread = _beginthreadex(NULL, 0, handle_client_thread, &handle_client_connection_thread_data, 0, NULL);
        
        CloseHandle((HANDLE)hThread);

        // Sau khi handle_client_connection hoàn thành, ClientSocket đã được đóng bên trong hàm đó.
        // Server quay lại đầu vòng lặp để chờ kết nối mới.
        system("cls");
    }

    // *******************************************************************
    // KẾT THÚC VÒNG LẶP CHÍNH (Chỉ chạy khi server tắt hoàn toàn, ví dụ Ctrl+C)
    // *******************************************************************
    closesocket(ListenSocket); // Đóng ListenSocket khi server tắt
    WSACleanup(); // Giải phóng Winsock (CHỈ MỘT LẦN KHI KẾT THÚC CHƯƠNG TRÌNH)
    sqlite3_close_v2(db); //Close database
    // printf("Server: Winsock cleaned up. Server shutting down.\n");

    system("pause"); // Giữ console mở để xem log cuối cùng (nếu server tắt)
    return 0;
}

unsigned __stdcall handle_client_thread(LPVOID lpParam) {
    // Ép kiểu tham số truyền vào (nếu có)
    HandleClientConnectionThreadData* handle_client_thread_data = (HandleClientConnectionThreadData *)lpParam;
    connection_current_count++;
    handle_client_connection(handle_client_thread_data->clientsocket, handle_client_thread_data->db);
    connection_current_count--;
    return 0;
}

// Hàm xử lý giao tiếp với MỘT client cụ thể
// client_socket: Socket đã được accept từ client đó
int handle_client_connection(SOCKET client_socket, sqlite3 *db) {
    cJSON* received_hash_array; // Buffer để lưu array chứa mã hash nhận được từ client này
    long long array_len;
    int bytesReceived;
    int iResult;

    // printf("Server %d: Ready to receive hash from client.\n", (int)client_socket);

    while (1){
        // 1. Nhận kích thước của array chứa mã hash từ client
        bytesReceived = recv(client_socket, (char*)&array_len, sizeof(array_len), 0);
        if (bytesReceived > 0){

        }else if (bytesReceived == 0)
        {
            // printf("Server %d: Client closed connection gracefully.\n", (int)client_socket);
            break;
        }else{
            fprintf(stderr, "Server %d: recv failed with error: %d\n", (int)client_socket, WSAGetLastError());
            break;
        }

        // 2. Nhận array chứa mã hash từ client
        char recvbuf[array_len]; // Buffer tạm thời cho recv
        bytesReceived = recv(client_socket, recvbuf, array_len, 0);

        if (bytesReceived > 0) {
            if (received_hash_array = cJSON_Parse(recvbuf)) {
                if (cJSON_IsArray(received_hash_array)){
                    // printf("Server %d: Bytes received: %d\n", (int)client_socket, bytesReceived);
                    // printf("Server %d: Received hash: '%s'\n", (int)client_socket, recvbuf);

                    // printf("Server %d: Hash stored in variable: '%s'\n", (int)client_socket, received_hash);

                    // *****************************************************************
                    // TẠI ĐÂY: received_hash_array ĐÃ CHỨA ARRAY CHỨA MÃ HASH TỪ CLIENT NÀY
                    // BẠN CÓ THỂ TẠO CÁC LUỒNG KIỂM TRA MALWARE CỦA MÌNH VỚI received_hash_array
                    // VÍ DỤ: check_malware_database(received_hash_array);
                    // *****************************************************************
                    
                    cJSON* check_hash_in_database_result_array = cJSON_CreateArray();
                    int total_hash_received = cJSON_GetArraySize(received_hash_array);

                    // prepare to create threads to compare hash with database
                    HANDLE hThreads[total_hash_received];
                    CheckHashInDatabaseThreadData check_hash_in_database_thread_data[total_hash_received];
                    DWORD ThreadIds[total_hash_received];
                    int index = 0;

                    // create threads to compare hash with database
                    cJSON* received_hash_element = NULL;
                    cJSON_ArrayForEach(received_hash_element, received_hash_array){
                        cJSON* received_hash_item = cJSON_GetObjectItemCaseSensitive(received_hash_element, "hash_str");
                        if (cJSON_IsString(received_hash_item) && (received_hash_item->valuestring != NULL)){
                            strcpy(check_hash_in_database_thread_data[index].hash_string_in, received_hash_item->valuestring);
                            check_hash_in_database_thread_data[index].db = db;
                            hThreads[index] = CreateThread(
                                NULL,
                                0,
                                check_hash_in_database_thread,
                                &check_hash_in_database_thread_data[index],
                                0,
                                &ThreadIds[index]
                            );
                            index += 1;
                        }
                    }

                    WaitForMultipleObjects(total_hash_received, hThreads, TRUE, INFINITE);

                    //finished comparing hash with database
                    for (int i = 0; i < total_hash_received; i++){
                        cJSON* check_hash_in_database_result_object = cJSON_CreateObject();
                        if (check_hash_in_database_thread_data[i].virus_detected_out == 0){
                            cJSON_AddStringToObject(check_hash_in_database_result_object, "status", "clean");
                            cJSON_AddStringToObject(check_hash_in_database_result_object, "virus_id", "none");
                        }else{
                            received_hash_element = cJSON_GetArrayItem(received_hash_array, i);
                            cJSON* received_hash_item = cJSON_GetObjectItemCaseSensitive(received_hash_element, "hash_str");
                            
                            cJSON_AddStringToObject(check_hash_in_database_result_object, "hash_str", received_hash_item->valuestring);
                            cJSON_AddStringToObject(check_hash_in_database_result_object, "status", "infected");
                            cJSON_AddStringToObject(check_hash_in_database_result_object, "virus_id", check_hash_in_database_thread_data[i].virus_id_result_out);
                        }
                        cJSON_AddItemToArray(check_hash_in_database_result_array, check_hash_in_database_result_object);
                        CloseHandle(hThreads[i]); // close thread handle
                    }
                    
                    char* json_string = cJSON_PrintUnformatted(check_hash_in_database_result_array);
                    size_t json_string_len = strlen(json_string);

                    iResult = send(client_socket, (const char*)&json_string_len, sizeof(size_t), 0);
                    if (iResult == SOCKET_ERROR) {
                        fprintf(stderr, "Server %d: send failed with error: %d\n", (int)client_socket, WSAGetLastError());
                    } else {
                        // printf("Server %d: Sent %d bytes response: %s\n", (int)client_socket, iResult, response_json);
                    }

                    if (json_string) {
                        iResult = send(client_socket, json_string, strlen(json_string), 0);
                        if (iResult == SOCKET_ERROR) {
                            fprintf(stderr, "Server %d: send failed with error: %d\n", (int)client_socket, WSAGetLastError());
                        } else {
                            // printf("Server %d: Sent %d bytes response: %s\n", (int)client_socket, iResult, response_json);
                        }
                    } else {
                        // Xử lý lỗi nếu không thể tạo chuỗi JSON
                        fprintf(stderr, "Server %d: Failed to create length of json response to send.\n", (int)client_socket);
                        // sprintf(response_json, "{\"status\":\"error\", \"message\":\"Failed to create JSON response\"}");
                        iResult = send(client_socket, "[{\"status\":\"error\", \"message\":\"Failed to create JSON response\"}]", 65, 0);
                        if (iResult == SOCKET_ERROR) {
                            fprintf(stderr, "Server %d: send failed with error: %d\n", (int)client_socket, WSAGetLastError());
                        } else {
                            // printf("Server %d: Sent %d bytes response: %s\n", (int)client_socket, iResult, response_json);
                        }
                    }
                    cJSON_Delete(check_hash_in_database_result_array); // Giải phóng đối tượng cJSON gốc
                    cJSON_free(json_string); // free memory allocated for json_string
                    cJSON_Delete(received_hash_array); //free memory allocated for received_hash_array
                } else{
                    const char* error_response = "{\"status\":\"error\", \"message\":\"String is not an array\"}";
                    send(client_socket, error_response, (int)strlen(error_response), 0);
                }

            } else {
                cJSON_Delete(received_hash_array);
                fprintf(stderr, "Server %d: Cannot parse json string\n",
                        (int)client_socket);
            }
        } else if (bytesReceived == 0) {
            cJSON_Delete(received_hash_array);
            // printf("Server %d: Client closed connection gracefully.\n", (int)client_socket);
            break;
        } else {
            cJSON_Delete(received_hash_array);
            fprintf(stderr, "Server %d: recv failed with error: %d\n", (int)client_socket, WSAGetLastError());
            break;
        }
    }

    // 4. Đóng socket của client sau khi xử lý xong
    iResult = shutdown(client_socket, SD_SEND); // Ngừng gửi dữ liệu
    if (iResult == SOCKET_ERROR) {
        fprintf(stderr, "Server %d: shutdown failed with error: %d\n", (int)client_socket, WSAGetLastError());
    }
    closesocket(client_socket); // Đóng socket client
    // printf("Server %d: Client socket closed.\n", (int)client_socket);
    return 0; // Xử lý client hoàn tất
}

DWORD WINAPI check_hash_in_database_thread(LPVOID lpParam){
    CheckHashInDatabaseThreadData* check_hash_in_database_thread_data = (CheckHashInDatabaseThreadData* )lpParam;
    char virus_id_result[100];
    int check_hash_with_database_result[9];
    // int check_hash_with_database_result[2];
    check_hash_in_database_thread_data->virus_detected_out = 0;

    check_hash_with_database_result[0] = check_hash_in_table(check_hash_in_database_thread_data->db, "EICAR", check_hash_in_database_thread_data->hash_string_in, virus_id_result);
    check_hash_with_database_result[1] = check_hash_in_table(check_hash_in_database_thread_data->db, "Ransomware", check_hash_in_database_thread_data->hash_string_in, virus_id_result);
    check_hash_with_database_result[2] = check_hash_in_table(check_hash_in_database_thread_data->db, "Spyware", check_hash_in_database_thread_data->hash_string_in, virus_id_result);
    check_hash_with_database_result[3] = check_hash_in_table(check_hash_in_database_thread_data->db, "Backdoor", check_hash_in_database_thread_data->hash_string_in, virus_id_result);
    check_hash_with_database_result[4] = check_hash_in_table(check_hash_in_database_thread_data->db, "JS", check_hash_in_database_thread_data->hash_string_in, virus_id_result);
    check_hash_with_database_result[5] = check_hash_in_table(check_hash_in_database_thread_data->db, "Trojan", check_hash_in_database_thread_data->hash_string_in, virus_id_result);
    check_hash_with_database_result[6] = check_hash_in_table(check_hash_in_database_thread_data->db, "Worm", check_hash_in_database_thread_data->hash_string_in, virus_id_result);
    check_hash_with_database_result[7] = check_hash_in_table(check_hash_in_database_thread_data->db, "Miner", check_hash_in_database_thread_data->hash_string_in, virus_id_result);
    check_hash_with_database_result[8] = check_hash_in_table(check_hash_in_database_thread_data->db, "Jokeware", check_hash_in_database_thread_data->hash_string_in, virus_id_result);
    // check_hash_with_database_result[0] = check_hash_in_table(check_hash_in_database_thread_data->db, "Malware_hashes", check_hash_in_database_thread_data->hash_string_in, virus_id_result);
    // check_hash_with_database_result[1] = check_hash_in_table(check_hash_in_database_thread_data->db, "EICAR", check_hash_in_database_thread_data->hash_string_in, virus_id_result);

    for (int i = 0; i < 8; i++){
        if (check_hash_with_database_result[i] == 1){
            check_hash_in_database_thread_data->virus_detected_out = 1;
            strcpy(check_hash_in_database_thread_data->virus_id_result_out, virus_id_result);
            break;
        }
    }
    return 0;
}