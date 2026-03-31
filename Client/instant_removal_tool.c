#include <stdio.h>
#include <wchar.h>
#include <windows.h>
#include "cJSON.h"
#include <string.h>
void write_json_data(char* key, char* value) {
       // create a cJSON object
   cJSON *json = cJSON_CreateObject();
   cJSON_AddStringToObject(json, key, value);

   // convert the cJSON object to a JSON string
   char *json_str = cJSON_Print(json);

   // write the JSON string to a file
   FILE *fp = fopen("removal_info.json", "w");
   fputs(json_str, fp);
   // free the JSON string and cJSON object
   cJSON_free(json_str);
   cJSON_Delete(json);
}
// Hàm để đọc nội dung file vào một chuỗi động
char* read_file_to_string(const char* filename) {
    FILE* fp = NULL;
    long file_size = 0;
    char* buffer = NULL;

    fp = fopen(filename, "rb"); // Mở ở chế độ nhị phân
    if (!fp) {
        fprintf(stderr, "Error: Could not open file %s\n", filename);
        return NULL;
    }

    fseek(fp, 0, SEEK_END);
    file_size = ftell(fp);
    fseek(fp, 0, SEEK_SET);

    if (file_size <= 0) {
        fprintf(stderr, "Error: Empty or invalid file %s\n", filename);
        fclose(fp);
        return NULL;
    }

    buffer = (char*)malloc(file_size + 1);
    if (!buffer) {
        fprintf(stderr, "Error: Failed to allocate memory for file buffer.\n");
        fclose(fp);
        return NULL;
    }
    
    // Đọc toàn bộ nội dung file
    if (fread(buffer, 1, file_size, fp) != file_size) {
        fprintf(stderr, "Error: Failed to read file %s\n", filename);
        free(buffer);
        fclose(fp);
        return NULL;
    }
    buffer[file_size] = '\0'; // Đảm bảo null-terminator

    fclose(fp);
    return buffer;
}
int main(){
    // read json file
    char file_path[1024];
    char* json_string = read_file_to_string("removal_info.json");
    if (!json_string) {
        return 1;
    }

    cJSON* root = cJSON_Parse(json_string);
    free(json_string); // Giải phóng bộ nhớ chuỗi JSON sau khi parse

    if (!root) {
        const char* error_ptr = cJSON_GetErrorPtr();
        if (error_ptr != NULL) {
            fprintf(stderr, "Error: JSON parsing error: %s\n", error_ptr);
        }
        return 1;
    }
    cJSON* key = cJSON_GetObjectItemCaseSensitive(root, "file_path");
    if (cJSON_IsString(key) && (key->valuestring != NULL)) {
        strcpy(file_path, key->valuestring);
    } else {
        return 1;
    }
    // process delete file
    int wide_path_len = MultiByteToWideChar(CP_UTF8, 0, file_path, -1, NULL, 0);
    if (wide_path_len == 0) { 
        return 1; 
    }
    wchar_t* wide_file_path = (wchar_t*)malloc(wide_path_len * sizeof(wchar_t));
    if (!wide_file_path) { 
        return 1; 
    }
    if (MultiByteToWideChar(CP_UTF8, 0, file_path, -1, wide_file_path, wide_path_len) == 0) {
        free(wide_file_path);
        return 1;
    }
    
    if (DeleteFileW(wide_file_path)) {
        
    } else {
        DWORD error_code = GetLastError();
        if (error_code == ERROR_SHARING_VIOLATION || error_code == ERROR_ACCESS_DENIED) {
            return 2;            
        } else {
            // wprintf(L"Không thể xóa file '%ls'. Mã lỗi: %lu\n", wide_file_path, error_code);
            return 1;
        }
    }

    free(wide_file_path);
    return 0;
}