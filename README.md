# simple-password-analyzer-and-encoder

A simple, intuitive desktop GUI tool to check password strength and hash strong passwords using popular cryptographic algorithms (MD5, SHA1, SHA256, SHA512).
Built with Python and PyQt5.


🛠 Features
✅ Checks password strength based on:

Minimum 8 characters

At least one uppercase letter

At least one lowercase letter

At least one digit

At least one special character

🔐 Supports hashing algorithms:

MD5, SHA1, SHA256, SHA512

📋 Select and copy hashed output

🎨 Dark-themed, modern PyQt5 GUI

🚀 Installation
📦 1. Clone the repository
bash
Copy
Edit
git clone https://github.com/your-username/password-analyzer-gui.git
cd password-analyzer-gui
🐍 2. Create virtual environment (optional but recommended)
bash
Copy
Edit
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
📥 3. Install dependencies
bash
Copy
Edit
pip install -r requirements.txt
Or install manually:

bash
Copy
Edit
pip install PyQt5
▶️ Run the App
bash
Copy
Edit
python password_gui.py
📄 requirements.txt
txt
Copy
Edit
PyQt5>=5.15.0
Create it by running:

bash
Copy
Edit
pip freeze > requirements.txt

📂 File Structure
bash
Copy
Edit
password-analyzer-gui/
├── password_gui.py      # Main application code
├── requirements.txt     # Dependencies
└── README.md            # Project documentation

🛡️ License
MIT License. Free to use, modify, and distribute.

👨‍💻 Author
Devidas Zende
