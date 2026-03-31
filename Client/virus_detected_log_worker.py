import sys
from PyQt6.QtCore import QObject, pyqtSignal, pyqtSlot,QThread
import json

def get_log():
    log_data = list()
    try:
        with open("activity_log_file.json", 'r', encoding='utf-8') as f:
            json_data = json.load(f)
    except json.JSONDecodeError:
        return []
    except FileNotFoundError:
        return []
    log_data.extend(json_data)
    return log_data

class VirusGetLogWorker(QObject):
    finished = pyqtSignal()
    virus_detected_info = pyqtSignal(str)
    
    def get_virus_detected_log(self):
        virus_detected_log = get_log()

        total_log = len(virus_detected_log)
        try:
            for i in range(total_log):
                if QThread.currentThread().isInterruptionRequested():
                    break
                file_path = virus_detected_log[i]["file_path"]
                virus_name = virus_detected_log[i]["virus_name"]
                log = f"File path: {file_path} - Virus_name: {virus_name}"
                self.virus_detected_info.emit(log)
            self.finished.emit()
        except IndexError:
            self.finished.emit()