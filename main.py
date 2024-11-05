import requests
import json
import sys
from PyQt5 import QtCore, QtGui, QtWidgets
from concurrent.futures import ThreadPoolExecutor

class SubdomainFinderWorker(QtCore.QThread):
    update_result = QtCore.pyqtSignal(str)
    alive_subdomains_found = QtCore.pyqtSignal(list)

    def __init__(self, domain, parent=None):
        super(SubdomainFinderWorker, self).__init__(parent)
        self.domain = domain
        self.api_key = "Your VirusTotal API"
        self.url = f"https://www.virustotal.com/vtapi/v2/domain/report?apikey={self.api_key}&domain={self.domain}"
    
    def is_alive(self, subdomain):
        try:
            response = requests.get(f"http://{subdomain}", timeout=5)
            if response.status_code == 200:
                return subdomain
        except requests.RequestException:
            pass
        return None

    def run(self):
        self.update_result.emit("[INFO] Fetching subdomains...")
        try:
            response = requests.get(self.url, timeout=10)
            response.raise_for_status()
            result = response.json()
        except requests.RequestException as e:
            self.update_result.emit(f"[ERROR] Failed to fetch subdomains: {e}")
            return

        if "subdomains" in result:
            subdomains = result["subdomains"]
            self.update_result.emit(f"[INFO] Found {len(subdomains)} subdomains. Checking which are alive...\n")
            
            with ThreadPoolExecutor(max_workers=10) as executor:
                alive_subdomains = list(filter(None, executor.map(self.is_alive, subdomains)))
            
            if alive_subdomains:
                self.update_result.emit("[+] Alive Subdomains:\n")
                for subdomain in alive_subdomains:
                    self.update_result.emit(f"- {subdomain}\n")
                self.alive_subdomains_found.emit(alive_subdomains)  # Emit list of alive subdomains
            else:
                self.update_result.emit("[-] No alive subdomains found.")
        else:
            self.update_result.emit("[-] No subdomains found.")

class SubdomainFinderApp(QtWidgets.QWidget):
    def __init__(self):
        super().__init__()
        self.initUI()
        self.alive_subdomains = []  # Store alive subdomains

    def initUI(self):
        # Set up main window properties
        self.setWindowTitle("Subdomain Finder - By Ali Ramzan")
        # self.setWindowIcon(QtGui.QIcon("favicon.png"))  # Path to your favicon file
        self.setGeometry(100, 100, 700, 800)
        self.setStyleSheet("background-color: #1e1e1e; color: #ffffff; font-family: Arial;")
        
        # Domain input
        self.domain_label = QtWidgets.QLabel("Enter Domain:")
        self.domain_label.setStyleSheet("color: #ffcc00; font-size: 14px;")
        self.domain_input = QtWidgets.QLineEdit()
        self.domain_input.setStyleSheet("background-color: #333333; color: #ffffff; padding: 5px; border-radius: 5px; font-size: 17px;")  # Increased font size
        
        # Scan button
        self.scan_button = QtWidgets.QPushButton("Find Alive Subdomains")
        self.scan_button.setStyleSheet("background-color: #ff3333; color: #ffffff; padding: 10px; border-radius: 5px; font-weight: bold;font-size: 18px")
        self.scan_button.clicked.connect(self.start_scan)

        # Copy and Save buttons (initially hidden)
        self.copy_button = QtWidgets.QPushButton("Copy to Clipboard")
        self.copy_button.setStyleSheet("background-color: #ff9933; color: #ffffff; padding: 10px; border-radius: 5px; font-weight: bold;")
        self.copy_button.clicked.connect(self.copy_to_clipboard)
        self.copy_button.setVisible(False)

        self.save_button = QtWidgets.QPushButton("Save to File")
        self.save_button.setStyleSheet("background-color: #3399ff; color: #ffffff; padding: 10px; border-radius: 5px; font-weight: bold;")
        self.save_button.clicked.connect(self.save_to_file)
        self.save_button.setVisible(False)

        # Result area
        self.result_area = QtWidgets.QTextEdit()
        self.result_area.setReadOnly(True)
        self.result_area.setStyleSheet("background-color: #333333; color: #00ff00; padding: 10px; border-radius: 5px; line-height: 1.5; font-size: 15px;")

        # Layout
        layout = QtWidgets.QVBoxLayout()
        layout.addWidget(self.domain_label)
        layout.addWidget(self.domain_input)
        layout.addWidget(self.scan_button)
        layout.addWidget(self.result_area)
        layout.addWidget(self.copy_button)
        layout.addWidget(self.save_button)
        self.setLayout(layout)

    def start_scan(self):
        domain = self.domain_input.text().strip()
        if not domain:
            QtWidgets.QMessageBox.warning(self, "Input Error", "Please enter a domain.")
            return

        self.result_area.clear()
        self.alive_subdomains = []
        self.copy_button.setVisible(False)
        self.save_button.setVisible(False)

        self.worker = SubdomainFinderWorker(domain)
        self.worker.update_result.connect(self.display_result)
        self.worker.alive_subdomains_found.connect(self.handle_alive_subdomains_found)
        self.worker.start()

    def display_result(self, message):
        self.result_area.append(message)

    def handle_alive_subdomains_found(self, alive_subdomains):
        self.alive_subdomains = alive_subdomains
        if alive_subdomains:
            self.copy_button.setVisible(True)
            self.save_button.setVisible(True)

    def copy_to_clipboard(self):
        clipboard = QtWidgets.QApplication.clipboard()
        clipboard.setText("\n".join(self.alive_subdomains))
        QtWidgets.QMessageBox.information(self, "Copied", "Alive subdomains copied to clipboard!")

    def save_to_file(self):
        domain = self.domain_input.text().strip()
        if not domain:
            QtWidgets.QMessageBox.warning(self, "Input Error", "Please enter a domain.")
            return

        filename = f"{domain}_alive_subdomains.txt"
        try:
            with open(filename, "w") as file:
                file.write("\n".join(self.alive_subdomains))
            QtWidgets.QMessageBox.information(self, "Saved", f"Alive subdomains saved to {filename}")
        except Exception as e:
            QtWidgets.QMessageBox.critical(self, "Save Error", f"Could not save file: {e}")

# Running the application
if __name__ == "__main__":
    app = QtWidgets.QApplication(sys.argv)
    mainWindow = SubdomainFinderApp()
    mainWindow.show()
    sys.exit(app.exec_())
