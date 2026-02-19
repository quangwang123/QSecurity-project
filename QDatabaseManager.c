#include <stdio.h>
#include "sqlite3.h"
#include <stdlib.h>
#include <time.h>
#include <string.h>

int check_virus_id_in_database(sqlite3 *db, const char *table, const char *virus_id)
{
    sqlite3_stmt *stmt;
    char *sql_select_dynamic = NULL; // Dùng để xây dựng câu lệnh SQL động
    // 1. Xây dựng câu lệnh SQL động
    // Ước tính kích thước đủ lớn cho chuỗi SQL: "SELECT virus_id FROM " + table_name + " WHERE virus_id = ?;" + null terminator
    size_t sql_len = strlen("SELECT virus_id FROM  WHERE virus_id = ?;") + strlen(table) + 1;
    sql_select_dynamic = (char *)malloc(sql_len);
    if (!sql_select_dynamic)
    {
        fprintf(stderr, "Error allocating memory for SQL statement.\n");
        return SQLITE_NOMEM; // Trả về lỗi hết bộ nhớ của SQLite
    }

    // Sử dụng snprintf để xây dựng chuỗi SQL an toàn
    snprintf(sql_select_dynamic, sql_len, "SELECT virus_id FROM %s WHERE virus_id = ?;", table);

    if (sqlite3_prepare_v2(db, sql_select_dynamic, -1, &stmt, NULL) != SQLITE_OK)
    {
        fprintf(stderr, "Error prepare: %s\n", sqlite3_errmsg(db));
        return -1;
    }
    if (sqlite3_bind_text(stmt, 1, virus_id, -1, SQLITE_STATIC))
    {
        fprintf(stderr, "Error when binding virus_id_to_find: %s\n", sqlite3_errmsg(db));
        sqlite3_finalize(stmt); // Đảm bảo giải phóng statement nếu có lỗi
        return -1;
    }

    if (sqlite3_step(stmt) == SQLITE_ROW)
    {
        return 1;
    }
    else
    {
        return 0;
    }

    free(sql_select_dynamic);
    sqlite3_finalize(stmt);
}

void generate_random_string(char *output, int length)
{
    // Tập hợp các ký tự có thể sử dụng
    const char charset[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                           "abcdefghijklmnopqrstuvwxyz"
                           "0123456789";
    int charset_size = sizeof(charset) - 1; // Kích thước thực của charset (bỏ qua null terminator)

    // Kiểm tra đầu vào hợp lệ
    if (output == NULL || length <= 0)
    {
        if (output != NULL)
        {
            output[0] = '\0'; // Đảm bảo chuỗi rỗng nếu đầu vào không hợp lệ
        }
        return;
    }

    for (int i = 0; i < length; i++)
    {
        // Lấy một số ngẫu nhiên trong khoảng từ 0 đến (charset_size - 1)
        int index = rand() % charset_size;
        output[i] = charset[index];
    }
    output[length] = '\0'; // Kết thúc chuỗi bằng ký tự null terminator
}

static int table_name_callback(void *data, int argc, char **argv, char **azColName)
{
    // data: Con trỏ tùy chỉnh được truyền từ sqlite3_exec (không dùng ở đây)
    // argc: Số lượng cột trong hàng kết quả
    // argv: Mảng các chuỗi chứa giá trị của các cột
    // azColName: Mảng các chuỗi chứa tên của các cột

    // Chúng ta chỉ quan tâm đến cột đầu tiên (tên bảng)
    if (argc > 0 && argv[0])
    {
        printf("  - %s\n", argv[0]); // argv[0] sẽ là tên bảng
    }
    return 0; // Trả về 0 để tiếp tục duyệt các hàng khác
}

// Hàm để hiển thị tất cả tên bảng trong một database SQLite
// Tham số:
//   db: Con trỏ đến kết nối database SQLite đã mở.
// Trả về: SQLITE_OK nếu thành công, mã lỗi SQLite nếu có lỗi.
int display_all_table_names(sqlite3 *db)
{
    const char *sql = "SELECT name FROM sqlite_master WHERE type='table';";
    char *zErrMsg = 0; // Con trỏ để lưu thông báo lỗi từ SQLite
    int rc;

    printf("Các bảng trong cơ sở dữ liệu:\n");

    // sqlite3_exec thực thi câu lệnh SQL và gọi callback cho mỗi hàng kết quả
    rc = sqlite3_exec(db, sql, table_name_callback, 0, &zErrMsg);

    if (rc != SQLITE_OK)
    {
        fprintf(stderr, "Lỗi khi truy vấn tên bảng: %s\n", zErrMsg);
        sqlite3_free(zErrMsg); // Giải phóng bộ nhớ của thông báo lỗi
    }
    else
    {
        printf("Truy vấn tên bảng thành công.\n");
    }

    return rc;
}

int create_virus_signature_table(sqlite3 *db, const char *table_name)
{
    char sql[128];
    snprintf(sql, sizeof(sql),
             "CREATE TABLE IF NOT EXISTS %s ("
             "sha256_hash TEXT NOT NULL UNIQUE,"
             "virus_id TEXT NOT NULL UNIQUE);",
             table_name);

    if (sqlite3_exec(db, sql, NULL, NULL, NULL) != SQLITE_OK)
    {
        fprintf(stderr, "Error creating table: %s\n", sqlite3_errmsg(db));
        printf("%s\n", sql);
        return -1;
    }
    printf("Table '%s' created successfully.\n", table_name);
    return 0;
}

int create_temporary_table(sqlite3 *db, const char *table_name)
{
    char sql[128];
    snprintf(sql, sizeof(sql),
             "CREATE TABLE IF NOT EXISTS %s ("
             "sha256_hash TEXT NOT NULL UNIQUE,"
             "virus_id TEXT UNIQUE);",
             table_name);

    if (sqlite3_exec(db, sql, NULL, NULL, NULL) != SQLITE_OK)
    {
        fprintf(stderr, "Error creating table: %s\n", sqlite3_errmsg(db));
        return -1;
    }
    printf("Table '%s' created successfully.\n", table_name);
    return 0;
}

// Hàm gộp tất cả dữ liệu hash từ bảng table_name trong file source_db_path vào database đang mở (target_db)

int merge_all_data_from_table_from_db(sqlite3 *target_db, const char *source_db_path, const char *table_name)
{
    char sql[512];
    char *err_msg = NULL;

    // ATTACH source.db dưới tên alias là 'src'
    snprintf(sql, sizeof(sql), "ATTACH DATABASE '%s' AS src;", source_db_path);
    if (sqlite3_exec(target_db, sql, NULL, NULL, &err_msg) != SQLITE_OK)
    {
        fprintf(stderr, "Error ATTACH: %s\n", err_msg);
        sqlite3_free(err_msg);
        return -1;
    }

    // Gộp dữ liệu từ bảng src.table_name → main.table_name
    snprintf(sql, sizeof(sql),
             "INSERT OR IGNORE INTO main.%s SELECT * FROM src.%s;", table_name, table_name); // avoid conflict with "OR IGNORE"
    if (sqlite3_exec(target_db, sql, NULL, NULL, &err_msg) != SQLITE_OK)
    {
        fprintf(stderr, "Error when merge data: %s\n", err_msg);
        sqlite3_free(err_msg);
        sqlite3_exec(target_db, "DETACH DATABASE src;", NULL, NULL, NULL); // detach nếu lỗi
        return -1;
    }

    // DETACH source database sau khi xong
    if (sqlite3_exec(target_db, "DETACH DATABASE src;", NULL, NULL, &err_msg) != SQLITE_OK)
    {
        fprintf(stderr, "Error DETACH: %s\n", err_msg);
        sqlite3_free(err_msg);
        return -1;
    }

    printf("Table '%s' from '%s' merged successfully.\n", table_name, source_db_path);
    return 0;
}

int merge_sha256_hash_from_src_table_to_temp_table(sqlite3 *target_db, const char *source_db_path, const char *table_name)
{
    char sql[512];
    char *err_msg = NULL;

    // ATTACH source.db dưới tên alias là 'src'
    snprintf(sql, sizeof(sql), "ATTACH DATABASE '%s' AS src;", source_db_path);
    if (sqlite3_exec(target_db, sql, NULL, NULL, &err_msg) != SQLITE_OK)
    {
        fprintf(stderr, "Error ATTACH: %s\n", err_msg);
        sqlite3_free(err_msg);
        return -1;
    }

    // Gộp dữ liệu từ bảng src.table_name → main.temp
    snprintf(sql, sizeof(sql),
             "INSERT INTO main.temp (sha256_hash) SELECT sha256_hash FROM src.%s;", table_name);
    if (sqlite3_exec(target_db, sql, NULL, NULL, &err_msg) != SQLITE_OK)
    {
        fprintf(stderr, "Error when merge data: %s\n", err_msg);
        sqlite3_free(err_msg);
        sqlite3_exec(target_db, "DETACH DATABASE src;", NULL, NULL, NULL); // detach nếu lỗi
        return -1;
    }

    // DETACH source database sau khi xong
    if (sqlite3_exec(target_db, "DETACH DATABASE src;", NULL, NULL, &err_msg) != SQLITE_OK)
    {
        fprintf(stderr, "Error DETACH: %s\n", err_msg);
        sqlite3_free(err_msg);
        return -1;
    }

    return 0;
}

int merge_sha256_hash_from_temp_table_to_target_table(sqlite3 *target_db, const char *table_name)
{
    char sql[512];
    char *err_msg = NULL;

    // Gộp dữ liệu từ bảng temp → table_name
    snprintf(sql, sizeof(sql),
             "INSERT OR IGNORE INTO %s SELECT * FROM temp;", table_name); // avoid conflict with "OR IGNORE"
    if (sqlite3_exec(target_db, sql, NULL, NULL, &err_msg) != SQLITE_OK)
    {
        fprintf(stderr, "Error when merge data: %s\n", err_msg);
        sqlite3_free(err_msg);
        sqlite3_exec(target_db, "DETACH DATABASE src;", NULL, NULL, NULL); // detach nếu lỗi
        return -1;
    }

    return 0;
}

int merge_data_from_src_table_to_target_table(sqlite3 *target_db, const char *source_db_path, const char *table_name){
    char sql[512];
    char *err_msg = NULL;

    // ATTACH source.db dưới tên alias là 'src'
    snprintf(sql, sizeof(sql), "ATTACH DATABASE '%s' AS src;", source_db_path);
    if (sqlite3_exec(target_db, sql, NULL, NULL, &err_msg) != SQLITE_OK)
    {
        fprintf(stderr, "Error ATTACH: %s\n", err_msg);
        sqlite3_free(err_msg);
        return -1;
    }

    // Gộp dữ liệu từ bảng src.table_name → main.table_name
    snprintf(sql, sizeof(sql),
             "INSERT OR IGNORE INTO main.%s SELECT * FROM src.%s;", table_name, table_name); // avoid conflict with "OR IGNORE"
    if (sqlite3_exec(target_db, sql, NULL, NULL, &err_msg) != SQLITE_OK)
    {
        fprintf(stderr, "Error when merge data: %s\n", err_msg);
        sqlite3_free(err_msg);
        sqlite3_exec(target_db, "DETACH DATABASE src;", NULL, NULL, NULL); // detach nếu lỗi
        return -1;
    }

    // DETACH source database sau khi xong
    if (sqlite3_exec(target_db, "DETACH DATABASE src;", NULL, NULL, &err_msg) != SQLITE_OK)
    {
        fprintf(stderr, "Error DETACH: %s\n", err_msg);
        sqlite3_free(err_msg);
        return -1;
    }

    return 0;

    // Gộp dữ liệu từ bảng src.table_name → main.table_name
}

// Hàm đếm số dòng dữ liệu trong một bảng cụ thể
// db: Con trỏ đến đối tượng database đã mở.
// table_name: Tên của bảng cần đếm số dòng.
// Trả về số dòng nếu thành công, hoặc -1 nếu có lỗi.
long double count_rows_in_table(sqlite3 *db, const char *table_name)
{
    sqlite3_stmt *stmt = NULL;  // Đối tượng prepared statement
    long double row_count = -1; // Biến lưu trữ số dòng
    char *sql_query = NULL;     // Chuỗi SQL động

    // Xây dựng câu lệnh SQL: SELECT COUNT(*) FROM <table_name>;
    size_t sql_len = strlen("SELECT COUNT(*) FROM ;") + strlen(table_name) + 1;
    sql_query = (char *)malloc(sql_len);
    if (!sql_query)
    {
        fprintf(stderr, "Error allocating memory for SQL query\n");
        return -1;
    }
    snprintf(sql_query, sql_len, "SELECT COUNT(*) FROM %s;", table_name);

    // Chuẩn bị câu lệnh SQL
    int rc = sqlite3_prepare_v2(db, sql_query, -1, &stmt, NULL);
    if (rc != SQLITE_OK)
    {
        fprintf(stderr, "Error when prepare statement: %s\n", sqlite3_errmsg(db));
        goto cleanup;
    }

    // Thực thi câu lệnh và lấy kết quả
    // sqlite3_step() sẽ trả về SQLITE_ROW nếu có kết quả (COUNT(*) luôn trả về 1 hàng)
    // hoặc SQLITE_DONE nếu không có hàng nào (không xảy ra với COUNT(*))
    if (sqlite3_step(stmt) == SQLITE_ROW)
    {
        // COUNT(*) luôn trả về một giá trị duy nhất ở cột đầu tiên (chỉ mục 0)
        row_count = sqlite3_column_int64(stmt, 0);
    }
    else
    {
        // Trường hợp không mong muốn, COUNT(*) luôn trả về một hàng
        fprintf(stderr, "No data returned from COUNT(*): %s\n", sqlite3_errmsg(db));
    }

cleanup:
    // Giải phóng tài nguyên
    if (stmt)
    {
        sqlite3_finalize(stmt); // Giải phóng prepared statement
    }
    if (sql_query)
    {
        free(sql_query); // Giải phóng chuỗi SQL đã cấp phát
    }

    return row_count;
}

int update_virus_id_into_temporary_table(sqlite3 *db, const char *virus_id)
{
    sqlite3_stmt *stmt; // Con trỏ đến prepared statement
    char *sql = malloc(64);
    snprintf(sql, 256, "UPDATE main.temp SET virus_id = ? WHERE virus_id = NULL;");

    int rc;

    // 1. Chuẩn bị câu lệnh SQL
    // sqlite3_prepare_v2 biên dịch câu lệnh SQL thành một prepared statement.
    // Tham số cuối cùng (&tail) thường là NULL nếu toàn bộ câu lệnh được sử dụng.
    rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK)
    {
        fprintf(stderr, "Error when prepare statement: %s\n", sqlite3_errmsg(db));
        return rc;
    }

    // 2. Gắn các giá trị vào placeholder (?)
    // Placeholder được đánh số từ 1.
    // sqlite3_bind_text: Gắn một giá trị chuỗi (text) vào placeholder.
    // Tham số 1: prepared statement
    // Tham số 2: Vị trí placeholder (bắt đầu từ 1)
    // Tham số 3: Giá trị chuỗi
    // Tham số 4: Độ dài chuỗi (-1 để tự động tính độ dài đến ký tự null)
    // Tham số 5: Destructor cho chuỗi. SQLITE_STATIC nghĩa là SQLite không giải phóng chuỗi này.

    // Gắn virus_id vào placeholder thứ nất
    rc = sqlite3_bind_text(stmt, 1, virus_id, -1, SQLITE_STATIC);
    if (rc != SQLITE_OK)
    {
        fprintf(stderr, "Error when bind text: %s\n", sqlite3_errmsg(db));
        sqlite3_finalize(stmt);
        return rc;
    }

    // 3. Thực thi câu lệnh
    // sqlite3_step thực thi câu lệnh đã được chuẩn bị.
    // Đối với INSERT, UPDATE, DELETE, nó sẽ trả về SQLITE_DONE khi thành công.
    // Đối với SELECT, nó sẽ trả về SQLITE_ROW cho mỗi hàng kết quả.
    rc = sqlite3_step(stmt);

    // 4. Giải phóng prepared statement
    // Luôn gọi sqlite3_finalize để giải phóng tài nguyên sau khi sử dụng statement.

    free(sql);
    sqlite3_finalize(stmt);

    return rc;
}

// Hàm lấy tên cột từ chỉ số (index)
char *get_virus_id_by_row(sqlite3 *db, const char *table, int row_index)
{
    sqlite3_stmt *stmt;
    char query[256];
    snprintf(query, sizeof(query), "SELECT sha256_hash FROM %s ORDER BY virus_id LIMIT 1 OFFSET %d;", table, row_index);

    int rc = sqlite3_prepare_v2(db, query, -1, &stmt, NULL);

    if (rc != SQLITE_OK)
    {
        printf("Error prepare: %s\n", sqlite3_errmsg(db));
        return NULL;
    }

    rc = sqlite3_step(stmt);
    if (rc == SQLITE_ROW)
    {
        const unsigned char *text = sqlite3_column_text(stmt, 0);
        if (text)
        {
            // Sao chép dữ liệu trả về
            char *result = strdup((const char *)text);
            sqlite3_finalize(stmt);
            return result;
        }
    }

    sqlite3_finalize(stmt);
    return NULL;
}

// Cập nhật cột "Name" khi cột index xác định có giá trị cụ thể
int update_virus_id_by_column_index(sqlite3 *db, const char *table, int col_index, const char *new_virus_id)
{
    const char *col_name = get_virus_id_by_row(db, table, col_index);
    if (!col_name)
    {
        printf("Cannot find column name at index %d\n", col_index);
        return -1;
    }

    char sql[256];
    snprintf(sql, sizeof(sql),
             "UPDATE %s SET virus_id = ? WHERE sha256_hash = '%s';", table, col_name);

    sqlite3_stmt *stmt;
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) != SQLITE_OK)
    {
        printf("Error prepare: %s\n", sqlite3_errmsg(db));
        return -1;
    }

    sqlite3_bind_text(stmt, 1, new_virus_id, -1, SQLITE_STATIC); // SET virus_id = ?

    int rc = sqlite3_step(stmt);
    if (rc != SQLITE_DONE)
    {
        printf("Error step: %s\n", sqlite3_errmsg(db));
    }

    sqlite3_finalize(stmt);
    return rc;
}

// Hàm để xóa một bảng trong cơ sở dữ liệu SQLite3
// db: Con trỏ đến đối tượng database đã mở.
// table_name: Tên của bảng cần xóa.
// Trả về SQLITE_OK nếu thành công, hoặc mã lỗi SQLite khác nếu thất bại.
int drop_table(sqlite3 *db, const char *table_name) {
    char *sql_drop_table = NULL;
    char *zErrMsg = 0; // Con trỏ để lưu thông báo lỗi từ SQLite
    int rc;

    // Xây dựng câu lệnh SQL: DROP TABLE IF EXISTS <table_name>;
    // IF EXISTS đảm bảo rằng lệnh không báo lỗi nếu bảng không tồn tại.
    size_t sql_len = strlen("DROP TABLE IF EXISTS ;") + strlen(table_name) + 1;
    sql_drop_table = (char *)malloc(sql_len);
    if (!sql_drop_table) {
        fprintf(stderr, "Error allocating memory for SQL statement\n");
        return SQLITE_NOMEM; // Mã lỗi cho thiếu bộ nhớ
    }
    snprintf(sql_drop_table, sql_len, "DROP TABLE IF EXISTS %s;", table_name);

    // Thực thi câu lệnh SQL
    rc = sqlite3_exec(db, sql_drop_table, NULL, 0, &zErrMsg);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "Error dropping table: '%s': %s\n", table_name, zErrMsg);
        sqlite3_free(zErrMsg); // Giải phóng bộ nhớ của thông báo lỗi
    }

    // Giải phóng bộ nhớ đã cấp phát cho chuỗi SQL
    free(sql_drop_table);

    return rc;
}

int delete_virus_signature_by_virus_id(sqlite3 *db, const char *virus_id, const char *table_name) {
    char sql[256];
    snprintf(sql, sizeof(sql),
             "DELETE FROM %s WHERE virus_id = '%s';", table_name, virus_id);
    int rc = sqlite3_exec(db, sql, NULL, NULL, NULL);
    if (rc != SQLITE_OK)
    {
        printf("Error when delete: %s\n", sqlite3_errmsg(db));
    }
    return rc;
    
}
int delete_virus_signature_by_sha256_hash(sqlite3 *db, const char *sha256_hash, const char *table_name) {
    char sql[256];
    snprintf(sql, sizeof(sql),
             "DELETE FROM %s WHERE sha256_hash = '%s';", table_name, sha256_hash);
    int rc = sqlite3_exec(db, sql, NULL, NULL, NULL);
    if (rc != SQLITE_OK)
    {
        printf("Error when delete: %s\n", sqlite3_errmsg(db));
    }
    return rc;
    
}

int main()
{
    srand((unsigned int)time(NULL)); // khởi tạo seed ngẫu nhiên
    sqlite3 *db;
    sqlite3_open_v2("file:qsecurity_database.db?nolock=1", &db, SQLITE_READONLY | SQLITE_OPEN_URI, NULL);
    int rc;
    char table_name[256];
    char source_db_path[256];
    while (1)
    {
        int total_virus_in_database = 0;
        total_virus_in_database += count_rows_in_table(db, "EICAR");
        total_virus_in_database += count_rows_in_table(db, "Ransomware");
        total_virus_in_database += count_rows_in_table(db, "Trojan");
        total_virus_in_database += count_rows_in_table(db, "Backdoor");
        total_virus_in_database += count_rows_in_table(db, "Spyware");
        total_virus_in_database += count_rows_in_table(db, "JS");
        total_virus_in_database += count_rows_in_table(db, "Miner");
        total_virus_in_database += count_rows_in_table(db, "Jokeware");
        total_virus_in_database += count_rows_in_table(db, "Worm");
    A:
        printf("                                                  Database Manager\n");
        printf("Total virus in database: %d\n", total_virus_in_database);
        printf("\n");
        printf("(1) Merge virus signature from source table database to target table database (slower because auto generate virus id and rewrite virus id in table, but recomended to avoid conflict)\n");
        printf("(2) Merge all from source table database to target table database (faster because no auto generate virus id, but not recomended due possible conflict)\n");
        printf("(3) Create a virus signature table\n");
        printf("(4) Delete virus signature by virus id\n");
        printf("(5) Delete virus signature by sha256 hash\n");
        printf("(6) Exit\n");
        printf("                    QSecurity Database Manager. A part of QSecurity project. Since 2025\n");
        printf("Your choice: ");

        int choice;
        scanf("%d", &choice);

        if (choice == 1)
        {
            system("cls");
            goto merge_sha256_hash_auto_generate_virus_id;
        }
        else if (choice == 2)
        {
            system("cls");
            goto merge_sha256_hash_no_auto_generate_virus_id;
        }
        else if (choice == 3)
        {
            system("cls");
            goto create_virus_signature_table;
        }
        else if (choice == 4)
        {
            system("cls");
            goto delete_virus_signature_by_virus_id;
        }
        else if (choice == 5)
        {
            system("cls");
            goto delete_virus_signature_by_sha256_hash;
        }
        else if (choice == 6)
        {
            system("pause");
            break;
        }
        else
        {
            printf("invalid choice\n");
            system("pause");
            system("cls");
            goto A;
        }

    // Start merge sha256 hash auto generate virus id
    merge_sha256_hash_auto_generate_virus_id:
        printf("Enter source database path: ");
        scanf("%s", source_db_path);

        printf("Enter table name: ");
        scanf("%s", table_name);

        printf("Creating temporary table...\n");
        int rc;
        rc = create_temporary_table(db, "temp");
        if (rc != 0)
        {
            printf("Error while creating temporary table\n");
            system("pause");
            system("cls");
            goto A;
        }

        printf("Merging sha256 hash to temporary table...\n");
        rc = merge_sha256_hash_from_src_table_to_temp_table(db, source_db_path, table_name);
        if (rc != 0)
        {
            printf("Error while merging data\n");
            printf("Dropping temporary table...\n");
            rc = drop_table(db, "temp");
            if (rc != SQLITE_OK)
            {
                printf("Error while dropping temporary table\n");
                system("pause");
                system("cls");
                goto A;
            }
            system("pause");
            system("cls");
            goto A;
        }

        int total_virus = count_rows_in_table(db, "temp");

        printf("Generating virus id and update it to temporary table...\n");

        for (int i = 0; i < total_virus; i++)
        {

        generate_virus_id:
            char random_string[13]; // 12 ký tự + 1 cho null terminator
            generate_random_string(random_string, 12);

            char virus_id[64]; // 63 ký tự + 1 cho null terminator
            snprintf(virus_id, sizeof(virus_id), "Virus.%s.%s", table_name, random_string);

            if (check_virus_id_in_database(db, table_name, virus_id) == 1)
            {
                goto generate_virus_id;
            }

            rc = update_virus_id_by_column_index(db, "temp", 0, virus_id); // if the data is not null, it's no longer is virus_id field to use with "ORDER BY" anymore so we use 0 instand of i
            if (rc == SQLITE_CONSTRAINT)
            {
                goto generate_virus_id;
            }
            else if (rc != SQLITE_DONE)
            {
                printf("Error while inserting virus signature into temporary table\n");
                printf("Dropping temporary table...\n");
                rc = drop_table(db, "temp");
                if (rc != SQLITE_OK)
                {
                    printf("Error while dropping temporary table\n");
                    system("pause");
                    system("cls");
                    goto A;
                }
                system("pause");
                system("cls");
                goto A;
            }
        }

        printf("Merging data from temporary table to target table...\n");
        rc = merge_sha256_hash_from_temp_table_to_target_table(db, table_name);
        if (rc != 0)
        {
            printf("Error while merging data\n");
            printf("Dropping temporary table...\n");
            rc = drop_table(db, "temp");
            if (rc != SQLITE_OK)
            {
                printf("Error while dropping temporary table\n");
                system("pause");
                system("cls");
                goto A;
            }
            system("pause");
            system("cls");
            goto A;
        }

        printf("Dropping temporary table...\n");
        rc = drop_table(db, "temp");
        if (rc != SQLITE_OK)
        {
            printf("Error while dropping temporary table\n");
            system("pause");
            system("cls");
            goto A;
        }

        printf("Virus signature inserted successfully\n");
        system("pause");
        system("cls");
        goto A;
    // End merge sha256 hash auto generate virus id

    // Start merge sha256 hash no auto generate virus id
    merge_sha256_hash_no_auto_generate_virus_id:
        printf("Enter source database path: ");
        scanf("%s", source_db_path);

        printf("Enter table name: ");
        scanf("%s", table_name);

        printf("Merging data to target table...\n");
        rc = merge_data_from_src_table_to_target_table(db, source_db_path, table_name);
        if (rc != 0)
        {
            printf("Error while merging data\n");
            printf("Dropping temporary table...\n");
            rc = drop_table(db, "temp");
            if (rc != SQLITE_OK)
            {
                printf("Error while dropping temporary table\n");
                system("pause");
                system("cls");
                goto A;
            }
            system("pause");
            system("cls");
            goto A;
        }

        printf("Virus signature inserted successfully\n");
        system("pause");
        system("cls");
        goto A;
    // End merge sha256 hash no auto generate virus id

    // Start create a virus signature table
    create_virus_signature_table:
        printf("Enter table name: ");
        scanf("%s", table_name);

        printf("Creating virus signature table...\n");
        rc = create_virus_signature_table(db, table_name);
        if (rc != 0)
        {
            printf("Error while creating virus signature table\n");
            system("pause");
            system("cls");
            goto A;
        }

        printf("Virus signature table created successfully\n");
        system("pause");
        system("cls");
        goto A;
        // End create a virus signature table

    // Start delete virus signature by virus id
    delete_virus_signature_by_virus_id:
        char virus_id[128];
        printf("Enter table name: ");
        scanf("%s", table_name);

        printf("Enter virus id: ");
        scanf("%s", virus_id);

        printf("Deleting virus signature...\n");
        rc = delete_virus_signature_by_virus_id(db, virus_id, table_name);
        if (rc != 0)
        {
            printf("Error while deleting virus signature\n");
            system("pause");
            system("cls");
            goto A;
        }

        printf("Virus signature deleted successfully\n");
        system("pause");
        system("cls");
        goto A;
    // End delete virus signature by virus id

    // Start virus signature by sha256 hash
    delete_virus_signature_by_sha256_hash:
        char sha256_hash[128];
        printf("Enter table name: ");
        scanf("%s", table_name);

        printf("Enter sha256 hash: ");
        scanf("%s", sha256_hash);

        printf("Deleting virus signature...\n");
        rc = delete_virus_signature_by_sha256_hash(db, sha256_hash, table_name);
        if (rc != 0)
        {
            printf("Error while deleting virus signature\n");
            system("pause");
            system("cls");
            goto A;
        }

        printf("Virus signature deleted successfully\n");
        system("pause");
        system("cls");
        goto A;
    // End virus signature by sha256 hash
    }

    sqlite3_close(db);

    return 0;
}