# 🚫 BlockGuardApp

BlockGuardApp is a **productivity and privacy tool** built with **Python and CustomTkinter**.  
It helps you **block distracting websites and applications, disable incognito/private browsing modes, and enforce system-wide privacy protections**.  
On Windows, it also includes a **Volume Lock** feature that prevents muting or lowering the volume below a safe level.  
The build_guard02.py is the final file 
to run this app. Go to the CMD 
and type python build_guard02.p

---

## ✨ Features
- 🔒 **Website Blocker** – Redirects blocked domains in the system hosts file  
- 💻 **Application Blocker** – Detects and terminates specific applications  
- 🕵️ **Incognito/Private Mode Blocker** – Disables incognito in Chrome and Edge (requires admin)  
- 🔊 **Volume Lock (Windows only)** – Prevents mute and enforces minimum system volume  
- 📊 **Dashboard** – Clean UI with status cards and blocked items list  
- 💾 **Persistent Settings** – Saves configuration in `blocker_config.json`  

---

## 📸 Screenshots
<img width="963" height="867" alt="image" src="https://github.com/user-attachments/assets/d35f0e77-6413-48d0-a47e-0aa50ff26780" />


---

## ⚙️ Installation

### 1. Clone the Repository
```bash
git clone https://github.com/sayma-shaikh/BlockGuard_App.git
cd BlockGuard_App

2. Create Virtual Environment (recommended)
python -m venv .venv
# Activate it
.\.venv\Scripts\activate   # On Windows
source .venv/bin/activate  # On Linux/Mac

3. Install Dependencies
pip install -r requirements.txt


If requirements.txt is missing, install manually:

pip install customtkinter psutil pycaw comtypes

▶️ Usage

Run the app:

python build_guard02.py





