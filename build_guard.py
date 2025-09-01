import customtkinter as ctk
import json
import sys
import os
import ctypes
import threading
import time
import subprocess
import psutil
from datetime import datetime
from urllib.parse import urlparse

# --- Styling and Color Palette ---
class AppColors:
    BACKGROUND = "#F0F2F5"
    CARD = "#FFFFFF"
    BUTTON = "#3B82F6"
    BUTTON_HOVER = "#2563EB"
    TEXT_PRIMARY = "#1F2937"
    TEXT_SECONDARY = "#6B7280"
    DELETE_ICON = "#9CA3AF"
    DELETE_ICON_HOVER = "#EF4444"
    GREEN = "#10B981"
    BLUE_ACCENT = "#3B82F6"

# --- Configuration and Constants ---
CONFIG_FILE = "blocker_config.json"
HOSTS_PATH = r"C:\Windows\System32\drivers\etc\hosts" if sys.platform == "win32" else "/etc/hosts"
REDIRECT_IP = "127.0.0.1"
BLOCK_MARKER = "# Blocked by BlockGuard"

# --- Utility Function ---
def parse_domain(url_string):
    """Extracts the bare domain (e.g., 'youtube.com') from any URL format."""
    if not url_string.startswith(('http://', 'https://')):
        url_string = 'http://' + url_string
    try:
        parsed_uri = urlparse(url_string)
        domain = parsed_uri.netloc
        if domain.startswith('www.'):
            domain = domain[4:]
        return domain.lower()
    except Exception:
        # Fallback for invalid formats
        return url_string.lower()

# --- Main Application Class ---
class BlockGuardApp(ctk.CTk):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self.title("BlockGuard")
        self.geometry("850x800")
        self.configure(fg_color=AppColors.BACKGROUND)

        self.config = self.load_config()
        self.app_monitor_thread = None
        self.app_monitor_stop_event = threading.Event()

        self.setup_ui()
        self.update_all_ui()
        self.apply_all_blocks()

    # --- UI Setup ---
    def setup_ui(self):
        self.grid_columnconfigure(0, weight=1)
        
        title_frame = ctk.CTkFrame(self, fg_color="transparent")
        title_frame.grid(row=0, column=0, padx=40, pady=(20, 10), sticky="ew")
        ctk.CTkLabel(title_frame, text="BlockGuard", font=ctk.CTkFont(size=30, weight="bold"), text_color=AppColors.TEXT_PRIMARY).pack()
        ctk.CTkLabel(title_frame, text="Manage blocked websites, applications, and privacy settings", font=ctk.CTkFont(size=14), text_color=AppColors.TEXT_SECONDARY).pack()

        self.create_dashboard_frame()
        self.create_add_block_frame()
        self.create_blocked_list_frame()

    def create_dashboard_frame(self):
        dashboard_frame = ctk.CTkFrame(self, fg_color="transparent")
        dashboard_frame.grid(row=1, column=0, padx=40, pady=10, sticky="ew")
        dashboard_frame.grid_columnconfigure((0, 1, 2), weight=1)

        # Incognito Mode Card
        incognito_card = ctk.CTkFrame(dashboard_frame, fg_color=AppColors.CARD, corner_radius=12)
        incognito_card.grid(row=0, column=0, padx=(0, 10), sticky="nsew")
        incognito_card.pack_propagate(False); incognito_card.configure(height=120)
        ctk.CTkLabel(incognito_card, text="Incognito Mode", font=ctk.CTkFont(size=16, weight="bold"), text_color=AppColors.TEXT_PRIMARY).pack(pady=(15, 5))
        self.incognito_switch = ctk.CTkSwitch(incognito_card, text="", command=self.toggle_incognito_mode, progress_color=AppColors.BUTTON)
        self.incognito_switch.pack(pady=5)
        self.incognito_status_label = ctk.CTkLabel(incognito_card, text="", text_color=AppColors.TEXT_SECONDARY)
        self.incognito_status_label.pack(pady=(0, 10))

        # Blocked Items Card
        blocked_items_card = ctk.CTkFrame(dashboard_frame, fg_color=AppColors.CARD, corner_radius=12)
        blocked_items_card.grid(row=0, column=1, padx=10, sticky="nsew")
        blocked_items_card.pack_propagate(False); blocked_items_card.configure(height=120)
        ctk.CTkLabel(blocked_items_card, text="Blocked Items", font=ctk.CTkFont(size=16, weight="bold"), text_color=AppColors.TEXT_PRIMARY).pack(pady=(15, 5))
        self.blocked_count_label = ctk.CTkLabel(blocked_items_card, text="0", font=ctk.CTkFont(size=30, weight="bold"), text_color=AppColors.TEXT_PRIMARY)
        self.blocked_count_label.pack()
        ctk.CTkLabel(blocked_items_card, text="Total blocked", text_color=AppColors.TEXT_SECONDARY).pack(pady=(0, 10))

        # Protection Status Card
        protection_card = ctk.CTkFrame(dashboard_frame, fg_color=AppColors.CARD, corner_radius=12)
        protection_card.grid(row=0, column=2, padx=(10, 0), sticky="nsew")
        protection_card.pack_propagate(False); protection_card.configure(height=120)
        ctk.CTkLabel(protection_card, text="Protection Status", font=ctk.CTkFont(size=16, weight="bold"), text_color=AppColors.TEXT_PRIMARY).pack(pady=(15, 5))
        self.protection_status_label = ctk.CTkLabel(protection_card, text="● Active", text_color=AppColors.GREEN, font=ctk.CTkFont(size=20))
        self.protection_status_label.pack()
        ctk.CTkLabel(protection_card, text="All filters enabled", text_color=AppColors.TEXT_SECONDARY).pack(pady=(0, 10))

    def create_add_block_frame(self):
        add_frame = ctk.CTkFrame(self, fg_color=AppColors.CARD, corner_radius=12)
        add_frame.grid(row=2, column=0, padx=40, pady=20, sticky="new")
        add_frame.grid_columnconfigure(0, weight=1)
        ctk.CTkLabel(add_frame, text="Add New Block", font=ctk.CTkFont(size=16, weight="bold"), text_color=AppColors.TEXT_PRIMARY).grid(row=0, column=0, columnspan=3, sticky="w", padx=20, pady=(10,5))
        
        self.new_item_entry = ctk.CTkEntry(add_frame, placeholder_text="Enter website URL or application name...", height=40)
        self.new_item_entry.grid(row=1, column=0, padx=20, pady=10, sticky="ew")
        self.item_type_selector = ctk.CTkOptionMenu(add_frame, values=["Website", "Application"], height=40, fg_color=AppColors.BUTTON, button_color=AppColors.BUTTON, button_hover_color=AppColors.BUTTON_HOVER)
        self.item_type_selector.grid(row=1, column=1, padx=(0, 10), pady=10)
        add_button = ctk.CTkButton(add_frame, text="Add Block", command=self.add_block_item, height=40, fg_color=AppColors.BUTTON, hover_color=AppColors.BUTTON_HOVER)
        add_button.grid(row=1, column=2, padx=(0, 20), pady=10)

    def create_blocked_list_frame(self):
        list_container = ctk.CTkFrame(self, fg_color=AppColors.CARD, corner_radius=12)
        list_container.grid(row=3, column=0, padx=40, pady=10, sticky="nsew")
        self.grid_rowconfigure(3, weight=1)
        list_container.grid_columnconfigure(0, weight=1)
        ctk.CTkLabel(list_container, text="Blocked Items", font=ctk.CTkFont(size=16, weight="bold"), text_color=AppColors.TEXT_PRIMARY).pack(anchor="w", padx=20, pady=(10, 5))
        
        self.blocked_list_frame = ctk.CTkScrollableFrame(list_container, fg_color="transparent")
        self.blocked_list_frame.pack(fill="both", expand=True, padx=15, pady=10)

    # --- UI Update Logic ---
    def update_dashboard(self):
        self.blocked_count_label.configure(text=str(len(self.config['blocked_items'])))
        if self.config.get('incognito_blocked', False):
            self.incognito_switch.select()
            self.incognito_status_label.configure(text="Currently: Enabled", text_color=AppColors.BLUE_ACCENT)
        else:
            self.incognito_switch.deselect()
            self.incognito_status_label.configure(text="Currently: Disabled", text_color=AppColors.TEXT_SECONDARY)
    
    def update_blocked_list(self):
        for widget in self.blocked_list_frame.winfo_children():
            widget.destroy()
        
        for item in sorted(self.config['blocked_items'], key=lambda x: x['value']):
            item_frame = ctk.CTkFrame(self.blocked_list_frame, fg_color=AppColors.BACKGROUND, corner_radius=8)
            item_frame.pack(fill="x", pady=5, padx=5)
            item_frame.grid_columnconfigure(2, weight=1)

            item_switch = ctk.CTkSwitch(item_frame, text="", width=0, command=lambda i=item: self.toggle_item_status(i), progress_color=AppColors.BUTTON)
            if item.get('enabled', True): item_switch.select()
            item_switch.grid(row=0, column=0, rowspan=2, padx=10)

            icon = "🌐" if item['type'] == 'Website' else "💻"
            ctk.CTkLabel(item_frame, text=icon, font=ctk.CTkFont(size=20)).grid(row=0, column=1, rowspan=2, padx=(0, 10))
            ctk.CTkLabel(item_frame, text=item['value'], font=ctk.CTkFont(size=14, weight="bold"), text_color=AppColors.TEXT_PRIMARY).grid(row=0, column=2, sticky="w")
            ctk.CTkLabel(item_frame, text=f"{item['type']} • Added {item['date_added']}", text_color=AppColors.TEXT_SECONDARY, font=ctk.CTkFont(size=12)).grid(row=1, column=2, sticky="w")
            
            delete_button = ctk.CTkButton(item_frame, text="🗑️", width=30, fg_color="transparent", text_color=AppColors.DELETE_ICON, hover_color=AppColors.DELETE_ICON_HOVER, command=lambda i=item: self.delete_block_item(i))
            delete_button.grid(row=0, column=3, rowspan=2, padx=10)

    def update_all_ui(self):
        self.update_dashboard()
        self.update_blocked_list()

    # --- Core Logic Handlers ---
    def add_block_item(self):
        raw_value = self.new_item_entry.get().strip()
        item_type = self.item_type_selector.get()
        if not raw_value: return

        final_value = parse_domain(raw_value) if item_type == 'Website' else raw_value.lower()
        if any(item['value'] == final_value for item in self.config['blocked_items']):
            self.new_item_entry.delete(0, 'end'); return
            
        new_item = { "value": final_value, "type": item_type, "date_added": datetime.now().strftime("%Y-%m-%d"), "enabled": True }
        self.config['blocked_items'].append(new_item)
        self.save_config()
        self.update_all_ui()
        self.apply_all_blocks()
        self.new_item_entry.delete(0, 'end')

    def delete_block_item(self, item_to_delete):
        self.config['blocked_items'] = [item for item in self.config['blocked_items'] if item['value'] != item_to_delete['value']]
        self.save_config()
        self.update_all_ui()
        self.apply_all_blocks()

    def toggle_item_status(self, item_to_toggle):
        for item in self.config['blocked_items']:
            if item['value'] == item_to_toggle['value']:
                item['enabled'] = not item.get('enabled', True); break
        self.save_config()
        self.apply_all_blocks()

    def toggle_incognito_mode(self):
        self.config['incognito_blocked'] = bool(self.incognito_switch.get())
        self.save_config()
        self.update_dashboard()
        self.apply_all_blocks()

    # --- Backend Blocking Logic ---
    def apply_all_blocks(self):
        print("Applying all blocking rules...")
        self.update_hosts_file()
        self.set_incognito_policy()
        self.start_app_monitor()

    def update_hosts_file(self):
        websites = [item['value'] for item in self.config['blocked_items'] if item['type'] == 'Website' and item.get('enabled', True)]
        try:
            with open(HOSTS_PATH, 'r+') as f:
                content = f.readlines()
                f.seek(0)
                for line in content:
                    if BLOCK_MARKER not in line: f.write(line)
                f.truncate()
                for site in websites:
                    f.write(f"\n{REDIRECT_IP}\t{site}\t{BLOCK_MARKER}")
                    f.write(f"\n{REDIRECT_IP}\twww.{site}\t{BLOCK_MARKER}")
            print("Hosts file updated successfully.")
        except Exception as e:
            print(f"Error updating hosts file: {e}. Please run as administrator.")

    def set_incognito_policy(self):
        enabled = self.config.get('incognito_blocked', False)
        value = 1 if enabled else 0
        command = ""
        try:
            if sys.platform == "win32":
                command = (f'reg add "HKLM\\SOFTWARE\\Policies\\Google\\Chrome" /v IncognitoModeAvailability /t REG_DWORD /d {value} /f && ' f'reg add "HKLM\\SOFTWARE\\Policies\\Microsoft\\Edge" /v InPrivateModeAvailability /t REG_DWORD /d {value} /f')
            elif sys.platform == "darwin":
                command = f"defaults write com.google.Chrome IncognitoModeAvailability -integer {value}"
                if not enabled: command = "defaults delete com.google.Chrome IncognitoModeAvailability"
            
            if command:
                subprocess.run(command, shell=True, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                print("Incognito policy applied. Browser restart is required.")
        except Exception as e:
            print(f"Failed to set incognito policy: {e}. Admin rights required.")

    def start_app_monitor(self):
        if self.app_monitor_thread and self.app_monitor_thread.is_alive():
            self.app_monitor_stop_event.set()
            self.app_monitor_thread.join()
        self.app_monitor_stop_event.clear()
        self.app_monitor_thread = threading.Thread(target=self.monitor_apps_worker, daemon=True)
        self.app_monitor_thread.start()

    def monitor_apps_worker(self):
        print("Starting app monitor thread...")
        apps_to_block = [item['value'] for item in self.config['blocked_items'] if item['type'] == 'Application' and item.get('enabled', True)]
        if not apps_to_block:
            print("No active apps to block. Monitor stopping."); return
        while not self.app_monitor_stop_event.is_set():
            for process in psutil.process_iter(['name']):
                if process.info['name'].lower() in apps_to_block:
                    try:
                        process.kill(); print(f"Blocked and terminated app: {process.info['name']}")
                    except (psutil.NoSuchProcess, psutil.AccessDenied): pass
            time.sleep(3)
        print("App monitor thread stopped.")

    # --- Configuration Management ---
    def load_config(self):
        if os.path.exists(CONFIG_FILE):
            try:
                with open(CONFIG_FILE, 'r') as f:
                    return json.load(f)
            except json.JSONDecodeError:
                pass # If file is corrupted, return default
        return {"blocked_items": [], "incognito_blocked": False}

    def save_config(self):
        with open(CONFIG_FILE, 'w') as f:
            json.dump(self.config, f, indent=4)

# --- Administrator Check and App Start ---
def is_admin():
    try: return ctypes.windll.shell32.IsUserAnAdmin()
    except: return False

if __name__ == "__main__":
    if sys.platform == "win32" and not is_admin():
        ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, " ".join(sys.argv), None, 1)
        sys.exit(0)
    
    ctk.set_appearance_mode("Light")
    app = BlockGuardApp()
    app.mainloop()