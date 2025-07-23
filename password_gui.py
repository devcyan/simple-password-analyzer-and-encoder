import sys
import hashlib
import re
from PyQt5.QtWidgets import (
    QApplication, QWidget, QLabel, QLineEdit, QPushButton,
    QVBoxLayout, QComboBox, QMessageBox, QTextEdit
)
from PyQt5.QtGui import QFont, QColor, QTextCursor
from PyQt5.QtCore import Qt

def is_strong_password(password):
    if len(password) < 8:
        return "❌ At least 8 characters"
    if not re.search(r"[A-Z]", password):
        return "❌ Must include uppercase"
    if not re.search(r"[a-z]", password):
        return "❌ Must include lowercase"
    if not re.search(r"[0-9]", password):
        return "❌ Must include digit"
    if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
        return "❌ Must include special char"
    return "✅ Strong password"

def hash_password(password, algo):
    if algo == 'MD5':
        return hashlib.md5(password.encode()).hexdigest()
    elif algo == 'SHA1':
        return hashlib.sha1(password.encode()).hexdigest()
    elif algo == 'SHA256':
        return hashlib.sha256(password.encode()).hexdigest()
    elif algo == 'SHA512':
        return hashlib.sha512(password.encode()).hexdigest()
    return None

class PasswordAnalyzer(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("🔐 Password Strength & Hashing Tool")
        self.setGeometry(200, 100, 500, 350)
        self.setStyleSheet("background-color: #1f1f1f; color: white; font-family: Consolas;")

        self.init_ui()

    def init_ui(self):
        layout = QVBoxLayout()

        self.label_title = QLabel("🔑 Enter Password:")
        self.label_title.setFont(QFont("Consolas", 12))
        self.label_title.setStyleSheet("color: #00BFFF;")

        self.input_password = QLineEdit()
        self.input_password.setEchoMode(QLineEdit.Password)
        self.input_password.setStyleSheet("background-color: #333; color: #0f0; padding: 5px; border-radius: 4px;")

        self.btn_check = QPushButton("Check Strength")
        self.btn_check.clicked.connect(self.analyze_password)
        self.btn_check.setStyleSheet("background-color: #008080; color: white; padding: 6px; border-radius: 5px;")

        self.result_label = QLabel("")
        self.result_label.setFont(QFont("Consolas", 11))
        self.result_label.setStyleSheet("padding: 5px;")

        self.label_algo = QLabel("Choose Hashing Algorithm:")
        self.label_algo.setFont(QFont("Consolas", 11))
        self.label_algo.setStyleSheet("color: #FFA500;")

        self.combo_algo = QComboBox()
        self.combo_algo.setStyleSheet("background-color: #444; color: white;")
        self.combo_algo.addItems(["MD5", "SHA1", "SHA256", "SHA512"])

        self.btn_hash = QPushButton("Hash Password")
        self.btn_hash.clicked.connect(self.hash_password_func)
        self.btn_hash.setStyleSheet("background-color: #5555aa; color: white; padding: 6px; border-radius: 5px;")
        self.btn_hash.setEnabled(False)

        self.hash_result = QTextEdit()
        self.hash_result.setReadOnly(True)
        self.hash_result.setTextInteractionFlags(Qt.TextSelectableByMouse)
        self.hash_result.setStyleSheet("background-color: #292929; color: #00FF7F; padding: 8px; border-radius: 5px;")
        self.hash_result.setFont(QFont("Consolas", 10))

        layout.addWidget(self.label_title)
        layout.addWidget(self.input_password)
        layout.addWidget(self.btn_check)
        layout.addWidget(self.result_label)
        layout.addWidget(self.label_algo)
        layout.addWidget(self.combo_algo)
        layout.addWidget(self.btn_hash)
        layout.addWidget(self.hash_result)

        self.setLayout(layout)

    def analyze_password(self):
        password = self.input_password.text()
        result = is_strong_password(password)
        self.result_label.setText(result)

        if result.startswith("✅"):
            self.result_label.setStyleSheet("color: #00FF00;")
            self.btn_hash.setEnabled(True)
        else:
            self.result_label.setStyleSheet("color: #FF4444;")
            self.btn_hash.setEnabled(False)
            self.hash_result.clear()

    def hash_password_func(self):
        password = self.input_password.text()
        algo = self.combo_algo.currentText()
        hashed = hash_password(password, algo)
        if hashed:
            self.hash_result.setText(f"🔒 {algo} Hash:\n{hashed}")
            self.hash_result.moveCursor(QTextCursor.Start)
        else:
            QMessageBox.warning(self, "Error", "Invalid hashing algorithm!")

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = PasswordAnalyzer()
    window.show()
    sys.exit(app.exec_())
