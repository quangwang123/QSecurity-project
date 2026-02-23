import subprocess
from PyQt6.QtCore import QObject, pyqtSignal, pyqtSlot,QThread
import json
import subprocess
import os
import socket
import struct
import asyncio
import aiofiles

SERVER_IP = "127.0.0.1"
SERVER_PORT = 3549
WORKER_STATUS_SUCCESS_SCAN = 0
WORKER_INTERNAL_ERROR_SCAN = 1
WORKER_STATUS_STOPPED_SCAN = 2

def clear_json_file(filepath):
    with open(filepath, 'w') as f:
        f.write('')

def load_json_file(filename):
    with open(filename, 'r', encoding='utf-8') as f:
        return json.load(f)

def write_scan_info_data(file_path, IsSingleFileScan=False):
    # If caller passed a simple path string, convert it into a dict so we can
    # set items like `scan_type` safely. Also wrap lists into a dict so the
    # output file is always a JSON object (consistent with readers).
    if isinstance(file_path, str):
        if IsSingleFileScan:
            file_path = {"file_path": file_path}
        else:
            file_path = {"folder_path_list": [file_path]}
    elif isinstance(file_path, list):
        file_path = {"folder_path_list": file_path}
    elif not isinstance(file_path, dict):
        # Fallback: wrap whatever was passed into a dict to avoid TypeError
        file_path = {"data": file_path}

    # Mở file với encoding='utf-8' và đảm bảo non-ASCII được hiển thị đúng
    with open("scan_info.json", "w", encoding='utf-8') as file:
        file_path["scan_type"] = "singlefilescan" if IsSingleFileScan else "folderscan"
        json.dump(file_path, file, ensure_ascii=False, indent=4) # indent=4 để dễ đọc hơn
        
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

async def write_log_data(json_data):
    try:
        file_path = "activity_log_file.json"

        async with aiofiles.open(file_path, mode="r+", encoding='utf-8') as file:
            content = await file.read()

            existing_data = json.loads(content) if content else []
            existing_data.append(json_data)

            await file.seek(0)
            new_content = json.dumps(existing_data, ensure_ascii=False, indent=4)
            await file.write(new_content)

            await file.truncate()
    except (json.JSONDecodeError, FileNotFoundError):
        async with aiofiles.open(file_path, mode="r+", encoding="utf-8") as file:
            new_content = json.dumps([json_data], ensure_ascii=False, indent=4)
            await file.write(new_content)

class ScanEngineWorker(QObject):
    finished = pyqtSignal(int, str, str)
    current_scanning_path = pyqtSignal(str)
    total_file_scanned = pyqtSignal(int)
    total_virus_detected = pyqtSignal(int)
    virus_detected_info = pyqtSignal(str)
    scan_failed = pyqtSignal() # scan_failed means scan failed entire file batch or scan failed single file (if user use scan single file) 
    failed_to_scan_file = pyqtSignal(str) # file_error_request_rescan_or_skip_or_cancel means one or some file failed to scan
    failed_to_send_hash_to_server = pyqtSignal()
    def __init__(self, file_path, parent=None):
        super().__init__(parent)
        self.file_path = file_path # Also can be folder path if user choose specified folder scan
        self.is_scan_stop = False
        self.action_needed = False # if scan result is infected, action needed will be set to true and it will be used to display "Action needed" in GUI and also used to determine whether we need to display virus detected info in scan result or not because if action_needed == False, we will not display virus detected info because it means no virus found
        self.failed_to_scan_file_action = 0 # 1: rescan, 2: skip, 3: cancel
        self.failed_to_send_hash_action = 0 # 1: resend, 2: skip, 3: cancel
        self.default_skip = 0 # 0: not skip, 1: skip. Default skip when use choose don't ask again for rescan or skip or cancel (scan failed)
    def run_single_scan_process(self):
        write_scan_info_data({"file_path": self.file_path}, IsSingleFileScan=True)

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
        self.scan_folder(["C:\\Users", "C:\\Program Files", "C:\\Program Files (x86)", "C:\\ProgramData"], IsSpecifiedFolderScan=False)
        self.finished.emit(WORKER_STATUS_SUCCESS_SCAN, "", str(self.action_needed))
    def run_specified_folder_scan_process(self): # also used for full scan
        self.scan_folder(self.file_path, IsSpecifiedFolderScan=True)
        self.finished.emit(WORKER_STATUS_SUCCESS_SCAN, "", str(self.action_needed))
    def full_scan_process(self):
        self.scan_folder(self.file_path, IsSpecifiedFolderScan=False)
        self.finished.emit(WORKER_STATUS_SUCCESS_SCAN, "", str(self.action_needed))
    @pyqtSlot()
    def file_error_request_rescan(self):
        self.failed_to_scan_file_action = 1 # rescan
    @pyqtSlot()
    def file_error_request_skip(self):
        self.failed_to_scan_file_action = 2 # skip
    @pyqtSlot()
    def file_error_request_cancel(self):
        self.failed_to_scan_file_action = 3 # cancel
    @pyqtSlot()
    def file_error_default_skip(self):
        self.default_skip = 1 # 0: not skip 1: skip
    @pyqtSlot()
    def send_hash_failed_request_retry(self):
        self.failed_to_send_hash_action = 1 # resend
    @pyqtSlot()
    def send_hash_failed_request_skip(self):
        self.failed_to_send_hash_action = 2 # skip
    @pyqtSlot()
    def send_hash_failed_cancel(self):
        self.failed_to_send_hash_action = 3 # cancel

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
                        self.is_scan_stop = True
                    
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
                        if self.is_scan_stop == False:
                            s.send("0".encode('ascii'))
                        else:
                            s.send("1".encode('ascii'))
                    elif recieve_code == '2':
                        if IsSpecifiedFolderScan == True:
                            self.finished.emit(WORKER_STATUS_STOPPED_SCAN, "", str(self.action_needed))
                        break
                    elif recieve_code == '3':
                        self.failed_to_send_hash_to_server.emit()

                        self.failed_to_send_hash_action = 0
                        while self.failed_to_send_hash_action == 0:
                            continue

                        if self.failed_to_send_hash_action == 1:
                            s.send("1".encode('ascii'))
                        elif self.failed_to_send_hash_action == 2:
                            s.send("2".encode('ascii'))
                        elif self.failed_to_send_hash_action == 3:
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
                            asyncio.run(write_log_data({"file_path": virus_found_file_path["file_path"], "virus_name": virus_name}))
                            write_virus_detected_data({"file_path": virus_found_file_path["file_path"]})
                    elif recieve_code == '5':
                        check_hash_failed_file = json.loads(s.recv(1041).decode('ascii'))
                        if self.default_skip == 0:
                            self.current_scanning_path.emit(check_hash_failed_file["file_path"])
                            self.failed_to_scan_file.emit(check_hash_failed_file["file_path"])
                            self.failed_to_scan_file_action = 0
                            while self.failed_to_scan_file_action == 0:
                                continue
                            
                            if self.default_skip == 0:
                                print(f"User choice for file scan error: {self.failed_to_scan_file_action}")
                                if self.failed_to_scan_file_action == 1:
                                    s.send("1".encode('ascii'))
                                elif self.failed_to_scan_file_action == 2:
                                    s.send("2".encode('ascii'))
                                elif self.failed_to_scan_file_action == 3:
                                    s.send("3".encode('ascii'))
                            else:
                                s.send("2".encode('ascii'))
                        else:
                            s.send("2".encode('ascii'))
                    elif recieve_code == '6':
                        self.scan_failed.emit()
                        
                        self.failed_to_scan_file_action = 0
                        while self.failed_to_scan_file_action == 0:
                            continue
                            
                        if self.failed_to_scan_file_action == 1:
                            s.send("1".encode('ascii'))
                        elif self.failed_to_scan_file_action == 2:
                            s.send("2".encode('ascii'))
                        elif self.failed_to_scan_file_action == 3:
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