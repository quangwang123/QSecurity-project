import subprocess
from PyQt6.QtCore import QObject, pyqtSignal, pyqtSlot,QThread
import json
import subprocess
import os
import socket
import struct

SERVER_IP = "127.0.0.1"
SERVER_PORT = 3549
WORKER_STATUS_SUCCESS_SCAN = 0
WORKER_INTERNAL_ERROR_SCAN = 1
WORKER_STATUS_STOPPED_SCAN = 2

# def get_files_in_directory_recursive(directory_path):
#     """
#     Duyệt qua tất cả các file trong thư mục chỉ định và các thư mục con
#     và trả về một list các đường dẫn tuyệt đối của file.
#     """
#     file_paths = []
#     try:
#         # os.walk trả về một iterator, mỗi lần lặp là một tuple (dirpath, dirnames, filenames)
#         for root, dirs, files in os.walk(directory_path):
#             for file_name in files:
#                 full_path = os.path.join(root, file_name) # Kết hợp đường dẫn thư mục hiện tại và tên file
#                 file_paths.append(full_path)
#     except FileNotFoundError:
#         print(f"Lỗi: Thư mục '{directory_path}' không tồn tại.")
#     except PermissionError:
#         print(f"Lỗi: Không có quyền truy cập vào thư mục '{directory_path}'.")
#     except Exception as e:
#         print(f"Đã xảy ra lỗi: {e}")
#     return file_paths

def clear_json_file(filepath):
    with open(filepath, 'w') as f:
        f.write('')

def load_json_file(filename):
    with open(filename, 'r', encoding='utf-8') as f:
        return json.load(f)

def write_scan_info_data(json_data, IsSingleFileScan=False):
    # If caller passed a simple path string, convert it into a dict so we can
    # set items like `scan_type` safely. Also wrap lists into a dict so the
    # output file is always a JSON object (consistent with readers).
    if isinstance(json_data, str):
        if IsSingleFileScan:
            json_data = {"file_path": json_data}
        else:
            json_data = {"folder_path": json_data}
    elif isinstance(json_data, list):
        json_data = {"file_list": json_data}
    elif not isinstance(json_data, dict):
        # Fallback: wrap whatever was passed into a dict to avoid TypeError
        json_data = {"data": json_data}

    # Mở file với encoding='utf-8' và đảm bảo non-ASCII được hiển thị đúng
    with open("scan_info.json", "w", encoding='utf-8') as file:
        json_data["scan_type"] = "singlefilescan" if IsSingleFileScan else "folderscan"
        json.dump(json_data, file, ensure_ascii=False, indent=4) # indent=4 để dễ đọc hơn
        
def write_virus_detected_data(new_data): #for removal process
    # Nếu file tồn tại → đọc dữ liệu cũ
    if os.path.exists("virus_detected_list.json"):
        with open("virus_detected_list.json", 'r', encoding='utf-8') as f:
            try:
                data = json.load(f)
                # Nếu không phải list → biến thành list
                if not isinstance(data, list):
                    data = [data]
            except json.JSONDecodeError:
                data = []
    else:
        data = []

    # Thêm dữ liệu mới
    data.append(new_data)

    # Ghi lại toàn bộ dữ liệu
    with open(f"virus_detected_list.json", 'w', encoding='utf-8') as f:
        json.dump(data, f, indent=4, ensure_ascii=False)

def write_log_data(json_data):
    try:
        with open("activity_log_file.json", "r+", encoding='utf-8') as file:
            existing_data = json.load(file)
            existing_data.append(json_data)
            file.seek(0)
            json.dump(existing_data, file, ensure_ascii=False, indent=4)
            file.truncate()
    except json.JSONDecodeError:
        with open("activity_log_file.json", "w", encoding='utf-8') as file:
            json.dump([json_data], file, ensure_ascii=False, indent=4)
    except FileNotFoundError:
        with open("activity_log_file.json", "w", encoding='utf-8') as file:
            json.dump([json_data], file, ensure_ascii=False, indent=4)

class ScanEngineWorker(QObject):
    finished = pyqtSignal(int, str, str)
    current_scanning_path = pyqtSignal(str)
    total_file_scanned = pyqtSignal(int)
    total_virus_detected = pyqtSignal(int)
    virus_detected_info = pyqtSignal(str)
    scan_failed = pyqtSignal() # scan_failed means scan failed entire file path list or scan failed single file (if user use scan single file) 
    failed_to_scan_file = pyqtSignal(str) # file_error_request_rescan_or_skip_or_cancel means one or some file failed to scan
    failed_to_send_hash_to_server = pyqtSignal()
    def __init__(self, file_path, parent=None):
        super().__init__(parent)
        self.file_path = file_path # Also can be folder path if user choose specified folder scan
        self.scan_stop = False
        self.action_needed = False # if scan result is infected, action needed will be set to true and it will be used to display "Action needed" in GUI and also used to determine whether we need to display virus detected info in scan result or not because if action_needed == False, we will not display virus detected info because it means no virus found
        self.rescan_or_skip_or_cancel = 0 # 1: rescan, 2: skip, 3: cancel
        self.resend_hash_or_skip_or_cancel = 0 # 1: resend, 2: skip, 3: cancel
        self.default_skip = 0 # 0: not skip, 1: skip. Default skip when use choose don't ask again for rescan or skip or cancel (scan failed)
    def run_single_scan_process(self):
        # try:
        #     write_scan_info_data([{"file_path": self.file_path}])
        #     engine_executable="./engine.exe"
        #     engine = subprocess.run([engine_executable, self.file_path], 
        #                         check=False,
        #                         capture_output=True,
        #                         text=True
        #                         )
        #     if engine.returncode == 0:
        #         scan_result = load_json_file("scan_result.json")
        #         status = scan_result[0]["status"]
        #         virus_name = scan_result[0]["virus_id"]
        #         self.finished.emit(WORKER_STATUS_SUCCESS_SCAN, status, virus_name)
        #     else:
        #         self.finished.emit(WORKER_INTERNAL_ERROR_SCAN,"", "")
                
        # except FileNotFoundError:
        #     self.finished.emit(WORKER_INTERNAL_ERROR_SCAN, "", "")
        write_scan_info_data({"file_path": self.file_path}, IsSingleFileScan=True)
        
        # self.finished.emit(WORKER_STATUS_SUCCESS_SCAN, "clean", "none")

        try:
            engine_executable="./engine.exe"
            engine = subprocess.Popen([engine_executable])

            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                
                s.connect((SERVER_IP, SERVER_PORT))
                    
                recieve_code = int(s.recv(1).decode('ascii'))

                if recieve_code == 0:
                    scan_status = int(s.recv(1).decode('ascii'))
                    if scan_status == 1:
                        self.finished.emit(WORKER_INTERNAL_ERROR_SCAN,"", "")
                    else:
                        scan_result = json.loads(s.recv(1024).decode('ascii'))
                        status = scan_result[0]["status"]
                        virus_name = scan_result[0]["virus_id"]
                        self.finished.emit(WORKER_STATUS_SUCCESS_SCAN, status, virus_name)
                else:
                    self.finished.emit(WORKER_INTERNAL_ERROR_SCAN,"", "")
        except ConnectionRefusedError:
            print(f"Lỗi: Không thể kết nối. Đảm bảo Server đang chạy trên {SERVER_IP}:{SERVER_PORT}.")
            self.finished.emit(WORKER_INTERNAL_ERROR_SCAN,"", "")
        except TimeoutError:
            print("Lỗi: Kết nối bị hết thời gian (Timeout).")
            self.finished.emit(WORKER_INTERNAL_ERROR_SCAN,"", "")
        except FileNotFoundError:
            print("Lỗi: Không tìm thấy file engine.exe.")
            self.finished.emit(WORKER_INTERNAL_ERROR_SCAN,"", "")
        except Exception as e:
            print(f"Đã xảy ra lỗi: {e}")
            self.finished.emit(WORKER_INTERNAL_ERROR_SCAN,"", "")
    def run_quick_scan_process(self):
        if self.scan_stop == False:
            self.scan_folder("C:\\Users", IsSpecifiedFolderScan=False)
        if self.scan_stop == False:
            self.scan_folder("C:\\Program Files", IsSpecifiedFolderScan=False)
        if self.scan_stop == False:
            self.scan_folder("C:\\Program Files (x86)", IsSpecifiedFolderScan=False)
        if self.scan_stop == False:
            self.scan_folder("C:\\ProgramData", IsSpecifiedFolderScan=False)
        
        self.finished.emit(WORKER_STATUS_SUCCESS_SCAN, "", str(self.action_needed))
    def run_specified_folder_scan_process(self): # also used for full scan
        self.scan_folder(self.file_path, IsSpecifiedFolderScan=True)
        self.finished.emit(WORKER_STATUS_SUCCESS_SCAN, "", str(self.action_needed))
    def full_scan_process(self):
        total_drives = len(self.file_path)
        for i in range (total_drives):
            if self.scan_stop == False:
                self.scan_folder(self.file_path[i], IsSpecifiedFolderScan=False)
        self.finished.emit(WORKER_STATUS_SUCCESS_SCAN, "", str(self.action_needed))
    @pyqtSlot()
    def file_error_request_rescan(self):
        self.rescan_or_skip_or_cancel = 1 # rescan
    @pyqtSlot()
    def file_error_request_skip(self):
        self.rescan_or_skip_or_cancel = 2 # skip
    @pyqtSlot()
    def file_error_request_cancel(self):
        self.rescan_or_skip_or_cancel = 3 # cancel
    @pyqtSlot()
    def user_request_default_skip_file_error(self):
        self.default_skip = 1 # 0: not skip 1: skip
    @pyqtSlot()
    def send_hash_failed_request_retry(self):
        self.resend_hash_or_skip_or_cancel = 1 # resend
    @pyqtSlot()
    def send_hash_failed_request_skip(self):
        self.resend_hash_or_skip_or_cancel = 2 # skip
    @pyqtSlot()
    def send_hash_failed_cancel(self):
        self.resend_hash_or_skip_or_cancel = 3 # cancel

    def scan_folder(self, folder_path, IsSpecifiedFolderScan): #In this version, all scanning logic is in engine instead GUI to improve performance and scanning speed. GUI now just for displaying scan progress and scan result only
        write_scan_info_data(folder_path, IsSingleFileScan=False)
        clear_json_file("virus_detected_list.json")
        
        try:
            engine_executable="./engine.exe"
            engine = subprocess.Popen([engine_executable])

            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                
                s.connect((SERVER_IP, SERVER_PORT))
                while 1:
                    if QThread.currentThread().isInterruptionRequested():
                        self.scan_stop = True
                    
                    recieve_code = s.recv(1).decode('ascii')
                    print(f"Recieve code: {recieve_code}")

                    if not recieve_code:
                        break

                    if recieve_code == '0':
                        current_scan_progress_length_in_hex = s.recv(4)
                        current_scan_progress_length = struct.unpack('<i', current_scan_progress_length_in_hex)[0]
                        current_scan_progress = json.loads(s.recv(current_scan_progress_length).decode('utf-8'))
                        self.current_scanning_path.emit(current_scan_progress["current_scanning_file"])
                        self.total_file_scanned.emit(current_scan_progress["total_scanned_files"])
                        self.total_virus_detected.emit(current_scan_progress["total_viruses_found"])
                    elif recieve_code == '1':
                        if self.scan_stop == False:
                            s.send("0".encode('ascii'))
                        else:
                            s.send("1".encode('ascii'))
                    elif recieve_code == '2':
                        if IsSpecifiedFolderScan == True:
                            self.finished.emit(WORKER_STATUS_STOPPED_SCAN, "", str(self.action_needed))
                        break
                    elif recieve_code == '3':
                        self.failed_to_send_hash_to_server.emit()

                        self.resend_hash_or_skip_or_cancel = 0
                        while self.resend_hash_or_skip_or_cancel == 0:
                            continue

                        if self.resend_hash_or_skip_or_cancel == 1:
                            s.send("1".encode('ascii'))
                        elif self.resend_hash_or_skip_or_cancel == 2:
                            s.send("2".encode('ascii'))
                        elif self.resend_hash_or_skip_or_cancel == 3:
                            s.send("3".encode('ascii'))

                    elif recieve_code == '4':
                        virus_found_file_paths_length_in_hex = s.recv(4)
                        virus_found_file_paths_length = struct.unpack('<i', virus_found_file_paths_length_in_hex)[0]
                        virus_found_file_paths = json.loads(s.recv(virus_found_file_paths_length).decode('utf-8'))
                        # print(virus_found_file_paths)
                        # print(virus_found_file_paths_length)
                        for virus_found_file_path in virus_found_file_paths:
                            virus_name = virus_found_file_path["virus_name"]
                            self.virus_detected_info.emit(f"File path: {virus_found_file_path["file_path"]} - Virus name: {virus_name}")
                            self.action_needed = True
                            write_log_data({"file_path": virus_found_file_path["file_path"], "virus_name": virus_name})
                            write_virus_detected_data({"file_path": virus_found_file_path["file_path"]})
                    elif recieve_code == '5':
                        check_hash_failed_file = json.loads(s.recv(1041).decode('ascii'))
                        if self.default_skip == 0:
                            self.current_scanning_path.emit(check_hash_failed_file["file_path"])
                            self.failed_to_scan_file.emit(check_hash_failed_file["file_path"])
                            self.rescan_or_skip_or_cancel = 0
                            while self.rescan_or_skip_or_cancel == 0:
                                continue
                            
                            if self.default_skip == 0:
                                print(f"User choice for file scan error: {self.rescan_or_skip_or_cancel}")
                                if self.rescan_or_skip_or_cancel == 1:
                                    s.send("1".encode('ascii'))
                                elif self.rescan_or_skip_or_cancel == 2:
                                    s.send("2".encode('ascii'))
                                elif self.rescan_or_skip_or_cancel == 3:
                                    s.send("3".encode('ascii'))
                            else:
                                s.send("2".encode('ascii'))
                        else:
                            s.send("2".encode('ascii'))
                    elif recieve_code == '6':
                        self.scan_failed.emit()
                        
                        self.rescan_or_skip_or_cancel = 0
                        while self.rescan_or_skip_or_cancel == 0:
                            continue
                            
                        if self.rescan_or_skip_or_cancel == 1:
                            s.send("1".encode('ascii'))
                        elif self.rescan_or_skip_or_cancel == 2:
                            s.send("2".encode('ascii'))
                        elif self.rescan_or_skip_or_cancel == 3:
                            s.send("3".encode('ascii'))

        except ConnectionRefusedError:
            print(f"Lỗi: Không thể kết nối. Đảm bảo Server đang chạy trên {SERVER_IP}:{SERVER_PORT}.")
        except TimeoutError:
            print("Lỗi: Kết nối bị hết thời gian (Timeout).")
        except ConnectionResetError:
            print("Lỗi: Không thể thiết lập kết nối đến engine.")
        except json.decoder.JSONDecodeError:
            self.finished.emit(WORKER_STATUS_STOPPED_SCAN, "", str(self.action_needed))
        except FileNotFoundError:
            print("Lỗi: Không tìm thấy file engine.exe.")
    def scan_folder1(self, folder_path):
        # prepare for scanning
        total_file_added_to_queue = 0
        file_path_list = []
        if self.scan_stop == False: #dont clear json file and dont set total_file_scanned and total_virus_detected to 0 after self.scan_stop == True
            clear_json_file("virus_detected_list.json") #clear virus_detected_list.json before scan
            self.total_file_scanned_temporary = 0 #temporary variable
            self.total_virus_detected_temporary = 0 #temporary variable

        # prepared done, start scanning
        # os.walk trả về một iterator, mỗi lần lặp là một tuple (dirpath, dirnames, filenames)
        for root, dirs, files in os.walk(folder_path):
            for file_name in files:
                file_path = os.path.join(root, file_name) # Kết hợp đường dẫn thư mục hiện tại và tên file
                file_path_list.append({"file_path": file_path})
                total_file_added_to_queue += 1
                if total_file_added_to_queue == 20:
                    total_file_added_to_queue = 0
                    while True:
                        self.current_scanning_path.emit(file_path_list[len(file_path_list)-1]["file_path"])
                        self.rescan_or_skip_or_cancel = 0
                        if QThread.currentThread().isInterruptionRequested():
                            self.scan_stop = True
                        if self.scan_stop == True:
                            self.finished.emit(WORKER_STATUS_STOPPED_SCAN, "", str(self.action_needed))
                            return 
                        write_scan_info_data(file_path_list)
                        engine_executable="./engine.exe"
                        engine = subprocess.run([engine_executable], 
                                                check=False,
                                                capture_output=True,
                                                text=True
                                                )

                        if engine.returncode == 0 or engine.returncode == 2:
                            scan_result_list = load_json_file("scan_result.json")
                            self.total_file_scanned_temporary += len(scan_result_list)
                            self.total_file_scanned.emit(self.total_file_scanned_temporary)
                            for file_path in load_json_file("scan_failed_files.json"):
                                if file_path in file_path_list:
                                    file_path_list.remove(file_path)
                            for i in range(len(scan_result_list)):
                                status = scan_result_list[i]["status"]
                                if status == "infected":
                                    self.total_virus_detected_temporary += 1
                                    self.total_virus_detected.emit(self.total_virus_detected_temporary)
                                    virus_name = scan_result_list[i]["virus_id"]
                                    self.virus_detected_info.emit(f"File path: {file_path_list[i]["file_path"]} - Virus name: {virus_name}")
                                    self.action_needed = True
                                    write_log_data({"file_path": file_path_list[i]["file_path"], "virus_name": virus_name})
                                    write_virus_detected_data({"file_path": file_path_list[i]["file_path"]})
                            if engine.returncode == 2 and self.default_skip == 0:
                                scan_failed_files = load_json_file("scan_failed_files.json")
                                for i in range(len(scan_failed_files)):
                                    if self.default_skip == 1:
                                        break
                                    self.rescan_or_skip_or_cancel = 0
                                    self.current_scanning_path.emit(scan_failed_files[i]["file_path"])
                                    self.file_error_request_rescan_or_skip_or_cancel.emit(scan_failed_files[i]["file_path"])
                                    while self.rescan_or_skip_or_cancel == 0:
                                        continue
                                    if self.rescan_or_skip_or_cancel == 2:
                                        pass #stop scan current file if user choose skip and scan next file, use pass instead break because break will break out of for loop
                                    elif self.rescan_or_skip_or_cancel == 3:
                                        self.scan_stop = True
                                        self.finished.emit(WORKER_STATUS_STOPPED_SCAN, "", str(self.action_needed))
                                        return
                                    elif self.rescan_or_skip_or_cancel == 1:                                  
                                        while True:
                                            self.rescan_or_skip_or_cancel = 0 #reset because it already has value from the last loop
                                            if QThread.currentThread().isInterruptionRequested():
                                                self.scan_stop = True
                                            if self.scan_stop == True:
                                                self.finished.emit(WORKER_STATUS_STOPPED_SCAN, "", str(self.action_needed))
                                                return 
                                            write_scan_info_data([{"file_path": scan_failed_files[i]["file_path"]}])
                                            engine_executable="./engine.exe"
                                            engine = subprocess.run([engine_executable], 
                                                                    check=False,
                                                                    capture_output=True,
                                                                    text=True
                                                                    )
                                            if engine.returncode == 0:
                                                scan_result_list = load_json_file("scan_result.json")
                                                self.total_file_scanned_temporary += len(scan_result_list)
                                                self.total_file_scanned.emit(self.total_file_scanned_temporary)
                                                status = scan_result_list[0]["status"] #set to 0 because we only have 1 file to scan
                                                if status == "infected":
                                                    self.total_virus_detected_temporary += 1
                                                    self.total_virus_detected.emit(self.total_virus_detected_temporary)
                                                    virus_name = scan_result_list[0]["virus_id"]
                                                    self.virus_detected_info.emit(f"File path: {scan_failed_files[0]["file_path"]} - Virus name: {virus_name}")
                                                    self.action_needed = True
                                                    write_log_data({"file_path": scan_failed_files[0]["file_path"], "virus_name": virus_name})
                                                    write_virus_detected_data({"file_path": scan_failed_files[0]["file_path"]})
                                            
                                            else:
                                                self.file_error_request_rescan_or_skip_or_cancel.emit(scan_failed_files[i]["file_path"])
                                                while self.rescan_or_skip_or_cancel == 0:
                                                    continue
                                                if self.rescan_or_skip_or_cancel == 2:
                                                    break #stop scan current file if user choose skip and scan next file
                                                continue #rescan the file or stop the scan if user choose cancel because QThread.currentThread().isInterruptionRequested() will set self.scan_stop = True
                                            break
                        elif engine.returncode == 1:
                            self.scan_failed.emit()
                            while self.rescan_or_skip_or_cancel == 0:
                                continue
                            if self.rescan_or_skip_or_cancel == 2:
                                    break #stop scan current file if user choose skip and scan next file
                            continue #rescan the file or stop the scan if user choose cancel because QThread.currentThread().isInterruptionRequested() will set self.scan_stop = True
                        file_path_list.clear() #clear file_path_list
                        break
                            #self.finished.emit(WORKER_INTERNAL_ERROR_SCAN, "during_scan", file_path)
        #check for leftover files in file_path_list
        if len(file_path_list) > 0:
            self.current_scanning_path.emit(file_path_list[len(file_path_list)-1]["file_path"])
            while True:
                self.rescan_or_skip_or_cancel = 0
                if QThread.currentThread().isInterruptionRequested():
                    self.scan_stop = True
                if self.scan_stop == True:
                    self.finished.emit(WORKER_STATUS_STOPPED_SCAN, "", str(self.action_needed))
                    return 
                write_scan_info_data(file_path_list)
                engine_executable="./engine.exe"
                engine = subprocess.run([engine_executable], 
                                        check=False,
                                        capture_output=True,
                                        text=True
                                        )
                if engine.returncode == 0 or engine.returncode == 2:
                    scan_result_list = load_json_file("scan_result.json")
                    self.total_file_scanned_temporary += len(scan_result_list)
                    self.total_file_scanned.emit(self.total_file_scanned_temporary)
                    for file_path in load_json_file("scan_failed_files.json"):
                        if file_path in file_path_list:
                            file_path_list.remove(file_path)
                    for i in range(len(scan_result_list)):
                        status = scan_result_list[i]["status"]
                        if status == "infected":
                            self.total_virus_detected_temporary += 1
                            self.total_virus_detected.emit(self.total_virus_detected_temporary)
                            virus_name = scan_result_list[i]["virus_id"]
                            self.virus_detected_info.emit(f"File path: {file_path_list[i]["file_path"]} - Virus name: {virus_name}")
                            self.action_needed = True
                            write_log_data({"file_path": file_path_list[i]["file_path"], "virus_name": virus_name})
                            write_virus_detected_data({"file_path": file_path_list[i]["file_path"]})
                    if engine.returncode == 2 and self.default_skip == 0:
                        scan_failed_files = load_json_file("scan_failed_files.json")
                        for i in range(len(scan_failed_files)):
                            if self.default_skip == 1:
                                break
                            self.rescan_or_skip_or_cancel = 0
                            self.current_scanning_path.emit(scan_failed_files[i]["file_path"])
                            self.file_error_request_rescan_or_skip_or_cancel.emit(scan_failed_files[i]["file_path"])
                            while self.rescan_or_skip_or_cancel == 0:
                                continue
                            if self.rescan_or_skip_or_cancel == 2:
                                pass #stop scan current file if user choose skip and scan next file, use pass instead break because break will break out of for loop
                            elif self.rescan_or_skip_or_cancel == 3:
                                self.scan_stop = True
                                self.finished.emit(WORKER_STATUS_STOPPED_SCAN, "", str(self.action_needed))
                                return
                            elif self.rescan_or_skip_or_cancel == 1:                                     
                                while True:
                                    self.rescan_or_skip_or_cancel = 0 #reset
                                    if QThread.currentThread().isInterruptionRequested():
                                        self.scan_stop = True
                                    if self.scan_stop == True:
                                        self.finished.emit(WORKER_STATUS_STOPPED_SCAN, "", str(self.action_needed))
                                        return 
                                    write_scan_info_data([{"file_path": scan_failed_files[i]["file_path"]}])
                                    engine_executable="./engine.exe"
                                    engine = subprocess.run([engine_executable], 
                                                            check=False,
                                                            capture_output=True,
                                                            text=True
                                                            )
                                    if engine.returncode == 0:
                                        scan_result_list = load_json_file("scan_result.json")
                                        self.total_file_scanned_temporary += len(scan_result_list)
                                        self.total_file_scanned.emit(self.total_file_scanned_temporary)
                                        status = scan_result_list[0]["status"] #set to 0 because we only have 1 file to scan
                                        if status == "infected":
                                            self.total_virus_detected_temporary += 1
                                            self.total_virus_detected.emit(self.total_virus_detected_temporary)
                                            virus_name = scan_result_list[0]["virus_id"]
                                            self.virus_detected_info.emit(f"File path: {scan_failed_files[0]["file_path"]} - Virus name: {virus_name}")
                                            self.action_needed = True
                                            write_log_data({"file_path": scan_failed_files[0]["file_path"], "virus_name": virus_name})
                                            write_virus_detected_data({"file_path": scan_failed_files[0]["file_path"]})
                                                
                                    else:
                                        self.file_error_request_rescan_or_skip_or_cancel.emit(scan_failed_files[i]["file_path"])
                                        while self.rescan_or_skip_or_cancel == 0:
                                            continue
                                        if self.rescan_or_skip_or_cancel == 2:
                                            break #stop scan current file if user choose skip and scan next file
                                        continue #rescan the file or stop the scan if user choose cancel because QThread.currentThread().isInterruptionRequested() will set self.scan_stop = True
                                    break     
                elif engine.returncode == 1:
                    self.scan_failed.emit()
                    while self.rescan_or_skip_or_cancel == 0:
                        continue
                    if self.rescan_or_skip_or_cancel == 2:
                        break #stop scan current file if user choose skip and scan next file
                    continue #rescan the file or stop the scan if user choose cancel because QThread.currentThread().isInterruptionRequested() will set self.scan_stop = True
                file_path_list.clear()
                break