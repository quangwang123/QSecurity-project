import subprocess
import sys
from PyQt6.QtCore import QObject, pyqtSignal, pyqtSlot
import json

# --- Mã thoát từ các module C ---
# instant_remover.c
C_INSTANT_SUCCESS = 0
C_INSTANT_GENERIC_ERROR = 1
C_INSTANT_BLOCKED = 2 # File bị khóa / quyền truy cập bị từ chối

# reboot_scheduler.c
C_SCHEDULE_SUCCESS = 0
C_SCHEDULE_FAIL = 1

# --- Mã thoát mà Worker sẽ gửi về GUI ---
WORKER_STATUS_SUCCESS_INSTANT_REMOVAL = 0         # Xóa tức thời thành công
WORKER_STATUS_FAILED_ENTIRELY_REMOVAL = 2         # Xóa thất bại hoàn toàn (không xóa được ngay và không lên lịch được)
WORKER_STATUS_INTERNAL_ERROR_REMOVAL = 3          # Lỗi nội bộ trong worker (ví dụ: không tìm thấy exe C)
WORKER_STATUS_SUCCESS_MULTIPLE_REMOVAL = 4        # Xóa đa (hoặc đơn) file thành công

def write_removal_info_data(json_data):
    # Mở file với encoding='utf-8' và đảm bảo non-ASCII được hiển thị đúng
    with open("removal_info.json", "w", encoding='utf-8') as file:
        json.dump(json_data, file, ensure_ascii=False, indent=4) # indent=4 để dễ đọc hơn

def read_multiple_removal_info_data():
    with open("virus_detected_list.json", "r", encoding='utf-8') as file:
        data = json.load(file)
    return data

class RemovalWorker(QObject):
    # Signals để giao tiếp với luồng GUI
    finished = pyqtSignal(int, str)          # Gửi mã kết quả cuối cùng
    # progress_update = pyqtSignal(str)   # Gửi cập nhật trạng thái
    # error_message = pyqtSignal(str)     # Gửi thông báo lỗi cụ thể
    
    # Signal mới để yêu cầu GUI hiển thị hộp thoại xác nhận khởi động lại
    request_reboot_confirmation = pyqtSignal() 

    def __init__(self, file_path, parent=None):
        super().__init__(parent)
        self.file_path = file_path
        self.instant_remover_exe = "instant_removal_tool.exe"
        self.reboot_scheduler_exe = "reboot_scheduler_removal_tool.exe"
        self.retry_or_skip = 0 # 1: retry, 2: skip

    def run_single_removal_process(self):
        """
        Phương thức chính để thực hiện quá trình xóa virus.
        Đây là phần sẽ chạy trong QThread.
        """
        # print(f"Worker: Bắt đầu quá trình xóa cho: {self.file_path}")
        # self.progress_update.emit(f"Đang cố gắng diệt virus tức thời: {self.file_path}...")
        
        try:
            write_removal_info_data({"file_path": self.file_path}) # Ghi thông tin file cần xóa cho công cụ xóa
            # --- Bước 1: Chạy module xóa tức thời ---
            instant_proc = subprocess.run(
                [self.instant_remover_exe],
                capture_output=True,
                text=True,
                encoding='utf-8',
                check=False # Quan trọng: để chúng ta tự kiểm tra return code
            )
            # print(f"Worker: instant_remover stdout:\n{instant_proc.stdout.strip()}")
            # if instant_proc.stderr:
            #     print(f"Worker: instant_remover stderr:\n{instant_proc.stderr.strip()}")

            if instant_proc.returncode == C_INSTANT_SUCCESS:
                # self.progress_update.emit(f"Đã diệt virus tức thời thành công: {self.file_path}")
                self.finished.emit(WORKER_STATUS_SUCCESS_INSTANT_REMOVAL, "")
                return

            elif instant_proc.returncode == C_INSTANT_BLOCKED:
                # self.progress_update.emit("Không thể xóa tức thời (file bị khóa/quyền truy cập bị từ chối). Đang cố gắng lên lịch xóa khi khởi động lại...")
                # print(f"Worker: File bị khóa hoặc quyền truy cập bị từ chối cho: {self.file_path}. Đang thử lên lịch.")
                
                # --- Bước 2: Nếu module tức thời thất bại do bị khóa/quyền, chạy module lên lịch ---
                reboot_proc = subprocess.run(
                    [self.reboot_scheduler_exe],
                    capture_output=True,
                    text=True,
                    encoding='utf-8',
                    check=False
                )
                # print(f"Worker: reboot_scheduler stdout:\n{reboot_proc.stdout.strip()}")
                # if reboot_proc.stderr:
                #     print(f"Worker: reboot_scheduler stderr:\n{reboot_proc.stderr.strip()}")

                if reboot_proc.returncode == C_SCHEDULE_SUCCESS:
                    # self.progress_update.emit(f"Diệt virus thành công (đã lên lịch xóa khi khởi động lại).")
                    self.request_reboot_confirmation.emit() # Yêu cầu GUI hỏi người dùng để khởi động lại
                else:
                    # self.error_message.emit(f"Không thể xóa ngay lập tức và không thể lên lịch xóa khi khởi động lại. Mã lỗi lên lịch: {reboot_proc.returncode}. Lỗi: {reboot_proc.stderr.strip()}")
                    self.finished.emit(WORKER_STATUS_FAILED_ENTIRELY_REMOVAL, "")

            else: # Các lỗi khác từ instant_remover
                # self.error_message.emit(f"Diệt virus tức thời thất bại với mã lỗi: {instant_proc.returncode}. Lỗi: {instant_proc.stderr.strip()}")
                self.finished.emit(WORKER_STATUS_FAILED_ENTIRELY_REMOVAL, "")

        except FileNotFoundError as e:
            # self.error_message.emit(f"Lỗi: Không tìm thấy công cụ diệt virus ({self.instant_remover_exe} hoặc {self.reboot_scheduler_exe}). Đảm bảo các file .exe nằm cùng thư mục với ứng dụng.")
            self.finished.emit(WORKER_STATUS_INTERNAL_ERROR_REMOVAL, "")
        except Exception as e:
            # self.error_message.emit(f"Đã xảy ra lỗi không mong muốn trong quá trình diệt virus: {e}")
            self.finished.emit(WORKER_STATUS_INTERNAL_ERROR_REMOVAL, "")
    @pyqtSlot()
    def retry_removal_process(self):
        self.retry_or_skip = 1
    @pyqtSlot()
    def skip_removal_process(self):
        self.retry_or_skip = 2
    def run_multiple_removal_process(self):
        """
        Phương thức chính để thực hiện quá trình xóa virus.
        Đây là phần sẽ chạy trong QThread.
        """
        # print(f"Worker: Bắt đầu quá trình xóa cho: {self.file_path}")
        # self.progress_update.emit(f"Đang cố gắng diệt virus tức thời: {self.file_path}...")
        total_removal_count = len(read_multiple_removal_info_data())
        #while True:
        i = 0
        while i < total_removal_count:
            file_path = read_multiple_removal_info_data()[i]["file_path"]
            self.retry_or_skip = 0
            try:
                write_removal_info_data({"file_path": file_path}) # Ghi thông tin file cần xóa cho công cụ xóa
                # --- Bước 1: Chạy module xóa tức thời ---
                instant_proc = subprocess.run(
                    [self.instant_remover_exe],
                    capture_output=True,
                    text=True,
                    encoding='utf-8',
                    check=False # Quan trọng: để chúng ta tự kiểm tra return code
                )
                # print(f"Worker: instant_remover stdout:\n{instant_proc.stdout.strip()}")
                # if instant_proc.stderr:
                #     print(f"Worker: instant_remover stderr:\n{instant_proc.stderr.strip()}")
                if instant_proc.returncode == C_INSTANT_SUCCESS:
                    pass
                elif instant_proc.returncode == C_INSTANT_BLOCKED:
                    # self.progress_update.emit("Không thể xóa tức thời (file bị khóa/quyền truy cập bị từ chối). Đang cố gắng lên lịch xóa khi khởi động lại...")
                    # print(f"Worker: File bị khóa hoặc quyền truy cập bị từ chối cho: {self.file_path}. Đang thử lên lịch.")
                    
                    # --- Bước 2: Nếu module tức thời thất bại do bị khóa/quyền, chạy module lên lịch ---
                    reboot_proc = subprocess.run(
                        [self.reboot_scheduler_exe],
                        capture_output=True,
                        text=True,
                        encoding='utf-8',
                        check=False
                    )
                    # print(f"Worker: reboot_scheduler stdout:\n{reboot_proc.stdout.strip()}")
                    # if reboot_proc.stderr:
                    #     print(f"Worker: reboot_scheduler stderr:\n{reboot_proc.stderr.strip()}")

                    if reboot_proc.returncode == C_SCHEDULE_SUCCESS:
                        # self.progress_update.emit(f"Diệt virus thành công (đã lên lịch xóa khi khởi động lại).")
                        self.request_reboot_confirmation.emit()
                    else:
                        # self.error_message.emit(f"Không thể xóa ngay lập tức và không thể lên lịch xóa khi khởi động lại. Mã lỗi lên lịch: {reboot_proc.returncode}. Lỗi: {reboot_proc.stderr.strip()}")
                        self.finished.emit(WORKER_STATUS_FAILED_ENTIRELY_REMOVAL, file_path)
                        while self.retry_or_skip == 0:
                            continue
                        if self.retry_or_skip == 1:
                            continue
                        elif self.retry_or_skip == 2:
                            pass
                else: # Các lỗi khác từ instant_remover
                    # self.error_message.emit(f"Diệt virus tức thời thất bại với mã lỗi: {instant_proc.returncode}. Lỗi: {instant_proc.stderr.strip()}")
                    self.finished.emit(WORKER_STATUS_FAILED_ENTIRELY_REMOVAL, file_path)
                    while self.retry_or_skip == 0:
                        continue
                    if self.retry_or_skip == 1:
                        continue
                    elif self.retry_or_skip == 2:
                        pass
            except FileNotFoundError as e:
                # self.error_message.emit(f"Lỗi: Không tìm thấy công cụ diệt virus ({self.instant_remover_exe} hoặc {self.reboot_scheduler_exe}). Đảm bảo các file .exe nằm cùng thư mục với ứng dụng.")
                self.finished.emit(WORKER_STATUS_INTERNAL_ERROR_REMOVAL, "engine not found")
                while self.retry_or_skip == 0:
                    continue
                if self.retry_or_skip == 1:
                    continue
            except Exception as e:
                # self.error_message.emit(f"Đã xảy ra lỗi không mong muốn trong quá trình diệt virus: {e}")
                self.finished.emit(WORKER_STATUS_INTERNAL_ERROR_REMOVAL, e)
                while self.retry_or_skip == 0:
                    continue
                if self.retry_or_skip == 1:
                    continue
            i += 1
        self.finished.emit(WORKER_STATUS_SUCCESS_MULTIPLE_REMOVAL, "")