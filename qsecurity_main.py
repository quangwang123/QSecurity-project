from PyQt6 import QtWidgets
from PyQt6.QtWidgets import QMessageBox, QWidget, QApplication, QLabel, QListWidget, QToolButton, QFileDialog, QCheckBox
from PyQt6 import uic
import sys
import json
from PyQt6.QtCore import Qt
import os
import ctypes
import string
from PyQt6.QtCore import QThread, pyqtSlot, pyqtSignal
from virus_removal_worker import (
    RemovalWorker,
    WORKER_STATUS_SUCCESS_INSTANT_REMOVAL,
    WORKER_STATUS_FAILED_ENTIRELY_REMOVAL,
    WORKER_STATUS_INTERNAL_ERROR_REMOVAL,
    WORKER_STATUS_SUCCESS_MULTIPLE_REMOVAL
)
from engine_scan_worker import (
    ScanEngineWorker,
    WORKER_STATUS_SUCCESS_SCAN,
    WORKER_INTERNAL_ERROR_SCAN,
    WORKER_STATUS_STOPPED_SCAN
)
from virus_detected_log_worker import VirusGetLogWorker

def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

if not is_admin():
    ctypes.windll.shell32.ShellExecuteW(
        None, "runas", sys.executable, ' '.join(sys.argv), None, 1)
    sys.exit()
else:
    pass

def clear_json_file(filepath):
    with open(filepath, 'w') as f:
        f.write('')

def get_all_active_drives():
    """
    Trả về danh sách các đường dẫn của các ổ đĩa logic (ví dụ: C:\\, D:\\)
    hiện đang có trên hệ thống Windows.
    """
    drives = []
    # Duyệt qua các chữ cái từ A đến Z
    for letter in string.ascii_uppercase:
        drive_path = f"{letter}:\\"
        # Kiểm tra xem đường dẫn ổ đĩa có tồn tại không
        if os.path.exists(drive_path):
            drives.append(drive_path)
    return drives

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

class MainWindow(QtWidgets.QMainWindow):
    def __init__(self):
        super().__init__()
        uic.loadUi('qsecurity_main_ui.ui',self)
        self.setWindowTitle("QSecurity")

        self.virus_get_log_thread = QThread()
        self.worker = VirusGetLogWorker()

        self.worker.moveToThread(self.virus_get_log_thread)

        self.worker.virus_detected_info.connect(self.show_virus_detected_info)

        self.virus_get_log_thread.started.connect(self.worker.get_virus_detected_log)

        self.worker.finished.connect(self.virus_get_log_thread.quit)
        self.worker.finished.connect(self.worker.deleteLater)
        self.virus_get_log_thread.finished.connect(self.virus_get_log_thread.deleteLater)

        self.virus_get_log_thread.start()

        self.select_file_scan.clicked.connect(self.browse_file_scan_command)
        self.select_folder_scan.clicked.connect(self.browse_folder_scan_command)
        self.quick_scan.clicked.connect(self.quick_scan_command)
        self.full_scan.clicked.connect(self.full_scan_command)
        
        self.clear_log.clicked.connect(self.clear_log_command)

        self.setWindowFlags(
            Qt.WindowType.Window | # Cửa sổ tiêu chuẩn
            Qt.WindowType.WindowCloseButtonHint | # Có nút đóng
            Qt.WindowType.WindowMinimizeButtonHint # Có nút thu nhỏ
        )
    
    @pyqtSlot(str)
    def show_virus_detected_info(self, virus_detected_info):
        self.log.addItem(virus_detected_info)
    
    def browse_file_scan_command(self):
        file_path, _ = QFileDialog.getOpenFileName(self, 
                                                   "Chọn tệp", 
                                                   "",
                                                   "All files (*)")
        
        if file_path:
            # self.path.setText(file_path)
            self.file_name = os.path.basename(file_path)
            self.scan(file_path)
        # else:
            # self.path.setText("Chưa có tệp nào được chọn...")
    def browse_folder_scan_command(self):
        folder_path = QFileDialog.getExistingDirectory(self, "Chọn thư mục")
        if folder_path:
            self.specifiedfolderscanwindow = SpecifiedFolderScanWindow(self, folder_path)
            self.specifiedfolderscanwindow.show()
            self.close()
    def scan(self, file_path):
        QMessageBox.information(self, "Đang quét", "Đang quét tệp, xin vui lòng đợi")
        self.file_path_scan = file_path
        self.single_scan_intialize(file_path)
    @pyqtSlot()
    def single_scan_intialize(self, file_path):
        self.select_file_scan.setEnabled(False) #Tránh bấm nhiều lần khi worker đang chạy
        self.select_folder_scan.setEnabled(False) #Tránh bấm các chức năng quét khác khi worker đang chạy
        self.quick_scan.setEnabled(False)
        self.full_scan.setEnabled(False)

        # 1. Tạo QThread và Worker
        self.thread = QThread()
        # 2. Truyền file_path vào Worker thông qua constructor
        self.worker = ScanEngineWorker(file_path)
            
        # 3. Di chuyển Worker object vào luồng mới
        self.worker.moveToThread(self.thread)

        # 4. Kết nối các tín hiệu (signals) từ worker đến các hàm (slots) trong MainWindow
        self.worker.finished.connect(self.on_scan_finished)

         # 5. Bắt đầu chạy worker khi thread được khởi động
        self.thread.started.connect(self.worker.run_single_scan_process)

        # 6. Dọn dẹp sau khi worker hoàn thành
        self.worker.finished.connect(self.thread.quit)
        self.worker.finished.connect(self.worker.deleteLater)
        self.thread.finished.connect(self.thread.deleteLater)

        # 7. Khởi động thread
        self.thread.start()
    @pyqtSlot(int, str, str)
    def on_scan_finished(self, result_code, status, virus_name):
        self.select_file_scan.setEnabled(True)
        self.select_folder_scan.setEnabled(True)
        self.quick_scan.setEnabled(True)
        self.full_scan.setEnabled(True)
        if result_code == WORKER_INTERNAL_ERROR_SCAN:
            QMessageBox.critical(self, "Lỗi", "Quét virus thất bại, vui lòng thử lại sau!")
        elif result_code == WORKER_STATUS_SUCCESS_SCAN:
            if status == "infected":
                write_log_data({"file_path": self.file_path_scan, "virus_name": virus_name})
                self.virus_detected_dialog = VirusDetectedDialog(self, virus_name, self.file_name, self.file_path_scan)
                self.virus_detected_dialog.show()
                log = f"File path: {self.file_path_scan} - Virus_name: {virus_name}"
                self.log.addItem(log)
            else:
                self.no_virus_detected_dialog = NoVirusDetectedDialog(self, self.file_name)
                self.no_virus_detected_dialog.show()
    def quick_scan_command(self):
        self.quick_scan_window = QuickScanWindow()
        self.quick_scan_window.show()
        self.close()
    def full_scan_command(self):
        self.full_scan_window = FullScanWindow(self)
        self.full_scan_window.show()
        self.close()
    def clear_log_command(self):
        reply = QMessageBox.warning(self,
                            "Xóa nhật ký",
                            f"Bạn có chắc chắn muốn xóa toàn bộ nhật ký không?",
                            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                            QMessageBox.StandardButton.Yes)
        if reply == QMessageBox.StandardButton.Yes:
            clear_json_file('activity_log_file.json')
            self.log.clear()
        elif reply == QMessageBox.StandardButton.No:
            pass

class ScanWindow(QtWidgets.QMainWindow):
    def __init__(self):
        super().__init__()
        uic.loadUi('scan.ui',self)

        self.total_scan_file = 0 # avoid error if scan failed and cancel or scan empty folder or etc

        self.setWindowFlags(
            Qt.WindowType.Window | # Cửa sổ tiêu chuẩn
            Qt.WindowType.WindowCloseButtonHint |# Có nút đóng
            Qt.WindowType.WindowMinimizeButtonHint
        )
    @pyqtSlot(str)
    def virus_detected_info_update(self, virus_name):
        self.virus_name = virus_name
        self.virus_name_list.append(self.virus_name)
        self.virus_detected_list.addItem(self.virus_name)
    @pyqtSlot(str)
    def current_scanning_path_update(self, current_scan_path):
        self.current_scan_path = current_scan_path
        self.current_file_scan.setText(self.current_scan_path)
    @pyqtSlot(int)
    def total_file_scanned_update(self, total_scan_file):
        self.total_scan_file = total_scan_file
        self.total_file_scan.setText(str(self.total_scan_file))
    @pyqtSlot(int)
    def total_virus_detected_update(self, total_virus_detected):
        self.total_detected_virus = total_virus_detected #tránh gây xung đột với total_virus_detected
        self.total_virus_detected.setText(str(self.total_detected_virus))
    @pyqtSlot(int, str, str)
    def on_scan_finished(self, result_code, type_error, action_needed):
        if result_code == WORKER_STATUS_STOPPED_SCAN:
            if action_needed == "True": 
                self.scan_finished_detected_dialog = ScanFinishedDetectedDialog(self, self.total_scan_file, self.total_detected_virus, self.virus_name_list)
                self.scan_finished_detected_dialog.show()
            if action_needed == "False":
                self.scan_finished_clean_dialog = ScanFinishedCleanDialog(self, self.total_scan_file)
                self.scan_finished_clean_dialog.show()
        elif result_code == WORKER_STATUS_SUCCESS_SCAN:
            if action_needed == "True":
                self.stop_scan.setEnabled(False)
                self.scan_finished_detected_dialog = ScanFinishedDetectedDialog(self, self.total_scan_file, self.total_detected_virus, self.virus_name_list)
                self.scan_finished_detected_dialog.show()
            if action_needed == "False":
                self.stop_scan.setEnabled(False)
                self.scan_finished_clean_dialog = ScanFinishedCleanDialog(self, self.total_scan_file)
                self.scan_finished_clean_dialog.show()
    def stop_scan_process(self):
        self.stop_scan.setEnabled(False)
        self.thread.requestInterruption()
    @pyqtSlot(str)
    def failed_to_scan_file(self, file_path):
        msg_box = QMessageBox()
        msg_box.setIcon(QMessageBox.Icon.Warning)
        msg_box.setWindowTitle("Lỗi trong khi quét file")
        msg_box.setText(f"Đã xảy ra lỗi trong khi quét file {file_path}, bạn có muốn thử lại không?")
        msg_box.setStandardButtons(QMessageBox.StandardButton.Retry | QMessageBox.StandardButton.Ignore | QMessageBox.StandardButton.Cancel)
        msg_box.setDefaultButton(QMessageBox.StandardButton.Retry)

        checkbox = QCheckBox("Không hiển thị lại thông báo này (mặc định bỏ qua).")
        msg_box.setCheckBox(checkbox)

        reply = msg_box.exec()

        if checkbox.isChecked():
            self.worker.user_request_default_skip_file_error()
        if reply == QMessageBox.StandardButton.Retry:
            self.worker.file_error_request_rescan()
        elif reply == QMessageBox.StandardButton.Ignore:
            self.worker.file_error_request_skip()
        elif reply == QMessageBox.StandardButton.Cancel:
            self.stop_scan.setEnabled(False)
            self.worker.file_error_request_cancel()
            self.thread.requestInterruption()
    @pyqtSlot()
    def failed_to_send_hash_to_server(self):
        reply = QMessageBox.warning(self,
                            "Lỗi trong khi quét file",
                            f"Đã xảy ra lỗi khi gửi chữ ký băm đến máy chủ, bạn có muốn thử lại không?",
                            QMessageBox.StandardButton.Retry | QMessageBox.StandardButton.Ignore | QMessageBox.StandardButton.Cancel,
                            QMessageBox.StandardButton.Retry)
        if reply == QMessageBox.StandardButton.Retry:
            self.worker.send_hash_failed_request_retry()
        elif reply == QMessageBox.StandardButton.Ignore:
            self.worker.send_hash_failed_request_skip()
        elif reply == QMessageBox.StandardButton.Cancel:
            self.stop_scan.setEnabled(False)
            self.worker.send_hash_failed_cancel()
            self.thread.requestInterruption()     

    @pyqtSlot()
    def scan_failed(self):
        reply = QMessageBox.warning(self,
                            "Lỗi trong khi quét file",
                            f"Đã xảy ra lỗi trong khi quét file , bạn có muốn thử lại không?",
                            QMessageBox.StandardButton.Retry | QMessageBox.StandardButton.Ignore | QMessageBox.StandardButton.Cancel,
                            QMessageBox.StandardButton.Retry)
        if reply == QMessageBox.StandardButton.Retry:
            self.worker.file_error_request_rescan()
        elif reply == QMessageBox.StandardButton.Ignore:
            self.worker.file_error_request_skip()
        elif reply == QMessageBox.StandardButton.Cancel:
            self.stop_scan.setEnabled(False)
            self.worker.file_error_request_cancel()
            self.thread.requestInterruption()

class QuickScanWindow(ScanWindow):
    def __init__(self):
        super().__init__()

        self.setWindowTitle("Quét nhanh")

        # 1. Tạo QThread và Worker
        self.thread = QThread()
        # 2. Truyền None vào Worker vì chỉ chạy quick scan
        self.worker = ScanEngineWorker(None)
            
        # 3. Di chuyển Worker object vào luồng mới
        self.worker.moveToThread(self.thread)

        # 4. Kết nối các tín hiệu (signals) từ worker đến các hàm (slots) trong MainWindow
        self.worker.finished.connect(self.on_scan_finished)
        self.worker.current_scanning_path.connect(self.current_scanning_path_update)
        self.worker.total_file_scanned.connect(self.total_file_scanned_update)
        self.worker.total_virus_detected.connect(self.total_virus_detected_update)
        self.worker.virus_detected_info.connect(self.virus_detected_info_update)
        self.worker.failed_to_scan_file.connect(self.failed_to_scan_file)
        self.worker.failed_to_send_hash_to_server.connect(self.failed_to_send_hash_to_server)
        self.worker.scan_failed.connect(self.scan_failed)

        # 5. Bắt đầu chạy worker khi thread được khởi động
        self.thread.started.connect(self.worker.run_quick_scan_process)

        # 6. Dọn dẹp sau khi worker hoàn thành
        self.worker.finished.connect(self.thread.quit)
        self.worker.finished.connect(self.worker.deleteLater)
        self.thread.finished.connect(self.thread.deleteLater)

        # 7. Khởi động thread
        self.thread.start()

        self.virus_name_list = [] #Truyền vào scan_finished_detected_dialog

        self.stop_scan.clicked.connect(self.stop_scan_process)

class SpecifiedFolderScanWindow(ScanWindow):
    def __init__(self, parent, folder_path):
        super().__init__()

        self.setWindowTitle("Quét thư mục được chỉ định")

        # 1. Tạo QThread và Worker
        self.thread = QThread()

        # 2. Truyền Folder path vào Worker

        self.worker = ScanEngineWorker(folder_path)
            
        # 3. Di chuyển Worker object vào luồng mới
        self.worker.moveToThread(self.thread)

        # 4. Kết nối các tín hiệu (signals) từ worker đến các hàm (slots) trong MainWindow
        self.worker.finished.connect(self.on_scan_finished)
        self.worker.current_scanning_path.connect(self.current_scanning_path_update)
        self.worker.total_file_scanned.connect(self.total_file_scanned_update)
        self.worker.total_virus_detected.connect(self.total_virus_detected_update)
        self.worker.virus_detected_info.connect(self.virus_detected_info_update)
        self.worker.failed_to_scan_file.connect(self.failed_to_scan_file)
        self.worker.failed_to_send_hash_to_server.connect(self.failed_to_send_hash_to_server)
        self.worker.scan_failed.connect(self.scan_failed)

         # 5. Bắt đầu chạy worker khi thread được khởi động
        self.thread.started.connect(self.worker.run_specified_folder_scan_process)

        # 6. Dọn dẹp sau khi worker hoàn thành
        self.worker.finished.connect(self.thread.quit)
        self.worker.finished.connect(self.worker.deleteLater)
        self.thread.finished.connect(self.thread.deleteLater)

        # 7. Khởi động thread
        self.thread.start()

        self.virus_name_list = [] #Truyền vào scan_finished_detected_dialog

        self.stop_scan.clicked.connect(self.stop_scan_process)

class FullScanWindow(ScanWindow):
    def __init__(self, parent):
        super().__init__()

        self.setWindowTitle("Quét toàn bộ")

        # 1. Tạo QThread và Worker
        self.thread = QThread()
        
        # 2. Truyền list drives vào Worker
        self.worker = ScanEngineWorker(get_all_active_drives())

        # 3. Di chuyển Worker object vào luồng mới
        self.worker.moveToThread(self.thread)

        # 4. Kết nối các tín hiệu (signals) từ worker đến các hàm (slots) trong MainWindow
        self.worker.finished.connect(self.on_scan_finished)
        self.worker.current_scanning_path.connect(self.current_scanning_path_update)
        self.worker.total_file_scanned.connect(self.total_file_scanned_update)
        self.worker.total_virus_detected.connect(self.total_virus_detected_update)
        self.worker.virus_detected_info.connect(self.virus_detected_info_update)
        self.worker.failed_to_scan_file.connect(self.failed_to_scan_file)
        self.worker.failed_to_send_hash_to_server.connect(self.failed_to_send_hash_to_server)
        self.worker.scan_failed.connect(self.scan_failed)

         # 5. Bắt đầu chạy worker khi thread được khởi động
        self.thread.started.connect(self.worker.full_scan_process)

        # 6. Dọn dẹp sau khi worker hoàn thành
        self.worker.finished.connect(self.thread.quit)
        self.worker.finished.connect(self.worker.deleteLater)
        self.thread.finished.connect(self.thread.deleteLater)

        # 7. Khởi động thread
        self.thread.start()

        self.virus_name_list = [] #Truyền vào scan_finished_detected_dialog

        self.stop_scan.clicked.connect(self.stop_scan_process)

class ScanFinishedDetectedDialog(QtWidgets.QDialog):
    def __init__(self, parent, total_scan_file, total_virus_detected, virus_name_list):
        super().__init__()
        uic.loadUi('scan_finished_detected.ui',self)
        self.setWindowTitle("Tiến trình quét đã hoàn tất, đã phát hiện virus !")
        self.parent_window = parent
        self.total_file_scanned.setText(str(total_scan_file))
        self.total_virus_detected.setText(str(total_virus_detected))
        for i in range(len(virus_name_list)):
            self.list_virus.addItem(virus_name_list[i])
        self.skip_button.clicked.connect(self.exit)
        self.delete_virus_button.clicked.connect(self.delete_virus)
        self.required_restart = False
        self.delete_virus_button.setEnabled(True)
        self.setWindowFlag(Qt.WindowType.WindowCloseButtonHint, False)
    def exit(self):
        self.mainwindow = MainWindow()
        self.mainwindow.show()
        self.parent_window.close()
        self.close()
    @pyqtSlot()
    def delete_virus(self):
        #Tránh bấm nhiều lần khi worker đang chạy
        self.delete_virus_button.setEnabled(False)
        self.skip_button.setEnabled(False)

        # 1. Tạo QThread và Worker
        self.thread = QThread()
        # 2. Truyền file_path vào Worker thông qua constructor
        self.worker = RemovalWorker(None)
        
        # 3. Di chuyển Worker object vào luồng mới
        self.worker.moveToThread(self.thread)

        # 4. Kết nối các tín hiệu (signals) từ worker đến các hàm (slots) trong MainWindow
        self.worker.finished.connect(self.on_removal_finished)
        self.worker.request_reboot_confirmation.connect(self.on_request_reboot_confirmation)

        # 5. Bắt đầu chạy worker khi thread được khởi động
        self.thread.started.connect(self.worker.run_multiple_removal_process)

        # 6. Dọn dẹp sau khi worker hoàn thành
        self.worker.finished.connect(self.thread.quit)
        self.worker.finished.connect(self.worker.deleteLater)
        self.thread.finished.connect(self.thread.deleteLater)

        # 7. Khởi động thread
        self.thread.start()
    @pyqtSlot(int, str)
    def on_removal_finished(self,result_code, message): #message can be error message or file path
        if result_code == WORKER_STATUS_SUCCESS_MULTIPLE_REMOVAL:
            if self.required_restart == False:
                QMessageBox.information(self,"Diệt virus hoàn tất", "Diệt virus thành công và hoàn tất")
                self.mainwindow = MainWindow()
                self.mainwindow.show()
                self.parent_window.close()
                self.close()
            else:
                reply = QMessageBox.warning(
                    self,
                    "Khởi động lại được yêu cầu",
                    "Một hoặc nhiều file không thể xóa được và đã lên lịch xóa trong lần khởi động tiếp theo. Điều này có thể là do đang có tiến trình khác đang sử dụng file hoặc bị khóa. Phần mềm sẽ cố gắng diệt sau khi máy tính khởi động lại (Lưu ý: hãy đảm bảo rằng các dữ liệu quan trọng được lưu trước khi khởi động lại máy tính). Bạn có muốn khởi động lại lúc này không? Nếu không muốn hoặc bạn muốn khởi động lại vào lúc khác thì bấm vào nút 'No' để bỏ qua.",
                    QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                    QMessageBox.StandardButton.Yes # Mặc định là Yes
                )
                if reply == QMessageBox.StandardButton.Yes:
                    os.system("shutdown /r /t 0")
                elif reply == QMessageBox.StandardButton.No:
                    self.mainwindow = MainWindow()
                    self.mainwindow.show()
                    self.parent_window.close()
                    self.close()
        elif result_code == WORKER_STATUS_INTERNAL_ERROR_REMOVAL:
            if message == "engine not found":
                reply = QMessageBox.critical(
                    self,
                    "Không tìm thấy công cụ diệt virus",
                    "Không tìm thấy công cụ diệt virus, bạn có thể thử lại. Nếu lỗi vẫn tiếp tục, hãy khởi động lại máy tính hoặc phần mềm hoặc cài đặt lại phần mềm!",
                    QMessageBox.StandardButton.Retry | QMessageBox.StandardButton.Cancel,
                    QMessageBox.StandardButton.Retry
                )
                if reply == QMessageBox.StandardButton.Retry:
                    self.worker.retry_removal_process()
                elif reply == QMessageBox.StandardButton.Cancel:
                    self.mainwindow = MainWindow()
                    self.mainwindow.show()
                    self.parent_window.close()
                    self.close()
            else:
                reply = QMessageBox.critical(self,
                                     "Đã xảy ra lỗi",
                                     f"Đã xảy ra lỗi không mong muốn: {message}, bạn có thể thử lại. Nếu lỗi vẫn tiếp tục, hãy khởi động lại máy tính hoặc phần mềm hoặc cài đặt lại phần mềm!",
                                     QMessageBox.StandardButton.Retry | QMessageBox.StandardButton.Cancel,
                                     QMessageBox.StandardButton.Retry)
                if reply == QMessageBox.StandardButton.Retry:
                    self.worker.retry_removal_process()
                elif reply == QMessageBox.StandardButton.Cancel:
                    self.mainwindow = MainWindow()
                    self.mainwindow.show()
                    self.parent_window.close()
                    self.close()
        elif result_code == WORKER_STATUS_FAILED_ENTIRELY_REMOVAL:
            reply = QMessageBox.critical(self,
                                "Đã xảy ra lỗi",
                                f"Đã xảy ra lỗi khi diệt virus của file {message}, bạn có muốn thử lại không?",
                                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                                QMessageBox.StandardButton.Yes)
            if reply == QMessageBox.StandardButton.Yes:
                self.worker.retry_removal_process()
            else:
                self.worker.skip_removal_process()
    @pyqtSlot()
    def on_request_reboot_confirmation(self):
        self.required_restart = True
class ScanFinishedCleanDialog(QtWidgets.QDialog):
    def __init__(self, parent, total_scan_file):
        super().__init__()
        uic.loadUi('scan_finished_clean.ui',self)
        self.setWindowTitle("Tiến trình quét đã hoàn tất, không phát hiện virus !")
        self.total_scan_file = total_scan_file
        self.total_file_scanned.setText(str(self.total_scan_file))
        self.total_virus_detected.setText("0")
        self.parent_window = parent
        self.setWindowFlag(Qt.WindowType.WindowCloseButtonHint, False)
        self.done_button.clicked.connect(self.done_command)
    def done_command(self):
        self.mainwindow = MainWindow()
        self.mainwindow.show()
        self.parent_window.close()
        self.close()
class VirusDetectedDialog(QtWidgets.QDialog):
    def __init__(self, parent, virus_name, file_name, file_path):
        super().__init__()
        uic.loadUi('virus_detected.ui',self)
        self.setWindowTitle("Không an toàn")
        self.virus_name.setText(virus_name)
        self.file_name.setText(file_name)
        self.skip.clicked.connect(self.skip_command)
        self.delete_virus.clicked.connect(self.delete_virus_command)
        self.thread = None  # QThread instance
        self.worker = None  # Virus Removal Worker instance
        self.file_path = file_path

        self.setWindowFlags(
            Qt.WindowType.Window | # Cửa sổ tiêu chuẩn
            Qt.WindowType.WindowCloseButtonHint # Có nút đóng
        )
    def skip_command(self):
        self.close()
    @pyqtSlot()
    def delete_virus_command(self):
        #Tránh bấm nhiều lần khi worker đang chạy
        self.delete_virus.setEnabled(False)

        # 1. Tạo QThread và Worker
        self.thread = QThread()
        # 2. Truyền file_path vào Worker thông qua constructor
        self.worker = RemovalWorker(self.file_path)
        
        # 3. Di chuyển Worker object vào luồng mới
        self.worker.moveToThread(self.thread)

        # 4. Kết nối các tín hiệu (signals) từ worker đến các hàm (slots) trong MainWindow
        self.worker.finished.connect(self.on_removal_finished)
        self.worker.request_reboot_confirmation.connect(self.on_request_reboot_confirmation)

        # 5. Bắt đầu chạy worker khi thread được khởi động
        self.thread.started.connect(self.worker.run_single_removal_process)

        # 6. Dọn dẹp sau khi worker hoàn thành
        self.worker.finished.connect(self.thread.quit)
        self.worker.finished.connect(self.worker.deleteLater)
        self.thread.finished.connect(self.thread.deleteLater)

        # 7. Khởi động thread
        self.thread.start()
    @pyqtSlot()
    def on_request_reboot_confirmation(self):
        """
        Slot này được gọi khi worker báo rằng cần khởi động lại máy tính.
        Hiển thị hộp thoại hỏi người dùng.
        """
        reply = QMessageBox.warning(
            self,
            "Khởi động lại được yêu cầu",
            "Diệt virus không thành công. Điều này có thể là do đang có tiến trình khác đang sử dụng file hoặc bị khóa. Phần mềm sẽ cố gắng diệt sau khi máy tính khởi động lại (Lưu ý: hãy đảm bảo rằng các dữ liệu quan trọng được lưu trước khi khởi động lại máy tính). Bạn có muốn khởi động lại lúc này không? Nếu không muốn hoặc bạn muốn khởi động lại vào lúc khác thì bấm vào nút 'No' để bỏ qua.",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.Yes # Mặc định là Yes
        )
        if reply == QMessageBox.StandardButton.Yes:
            os.system("shutdown /r /t 0")
        elif reply == QMessageBox.StandardButton.No:
            self.close()

    @pyqtSlot(int)
    def on_removal_finished(self, result_code):
        """Xử lý kết quả cuối cùng từ worker."""
        self.delete_virus.setEnabled(True) # Kích hoạt lại nút

        if result_code == WORKER_STATUS_SUCCESS_INSTANT_REMOVAL:
            QMessageBox.information(self, "Diệt Virus", "Diệt virus tức thời thành công!")
            self.close()
        elif result_code == WORKER_STATUS_FAILED_ENTIRELY_REMOVAL:
            QMessageBox.critical(self, "Lỗi", "Có lỗi trong quá trình tiến hành diệt virus, vui lòng thử lại sau!")
            self.close()
        elif result_code == WORKER_STATUS_INTERNAL_ERROR_REMOVAL:
            QMessageBox.critical(self, "Lỗi", "Có lỗi trong quá trình tiến hành diệt virus, vui lòng thử lại sau!")
            self.close()

class NoVirusDetectedDialog(QtWidgets.QDialog):
    def __init__(self, parent, file_name):
        super().__init__()
        uic.loadUi('no_virus_detected.ui',self)
        self.setWindowTitle("An toàn")
        self.file_name.setText(file_name)
        self.done_0.clicked.connect(self.done_command)
        self.setWindowFlags(
            Qt.WindowType.Window | # Cửa sổ tiêu chuẩn
            Qt.WindowType.WindowCloseButtonHint # Có nút đóng
        )
    def done_command(self):
        self.close()
if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec())