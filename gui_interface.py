import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
from datetime import datetime
import threading
import subprocess
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg

from config import ADMIN_USERNAME, ADMIN_PASSWORD, USER_USERNAME, USER_PASSWORD


class IDSGUI:
    def __init__(self, ids_core):
        self.ids_core = ids_core
        self.root = tk.Tk()
        self.root.title("Intrusion Detection System")
        self.root.geometry("1200x700")
        self.root.configure(bg="#1e1e2f")

        self.current_user = None
        self.is_monitoring = False

        self.setup_style()
        self.setup_login_screen()

    # ---------------------------------------------------------
    # STYLE
    # ---------------------------------------------------------
    def setup_style(self):
        style = ttk.Style()
        style.theme_use("default")
        style.configure("TFrame", background="#1e1e2f")
        style.configure("TLabel", background="#1e1e2f", foreground="white")
        style.configure("TButton", font=("Segoe UI", 10), padding=6)

    # ---------------------------------------------------------
    # LOGIN
    # ---------------------------------------------------------
    def setup_login_screen(self):
        self.clear_window()

        tk.Label(self.root, text="IDS Login", font=("Segoe UI", 20, "bold"),
                 bg="#1e1e2f", fg="white").pack(pady=30)

        frame = tk.Frame(self.root, bg="#1e1e2f")
        frame.pack()

        tk.Label(frame, text="Username", fg="white",
                 bg="#1e1e2f").pack(anchor="w")
        self.username_entry = tk.Entry(frame, width=30)
        self.username_entry.pack(pady=5)

        tk.Label(frame, text="Password", fg="white",
                 bg="#1e1e2f").pack(anchor="w")
        self.password_entry = tk.Entry(frame, width=30, show="*")
        self.password_entry.pack(pady=5)

        tk.Button(frame, text="Login", width=20,
                  bg="#3498db", fg="white",
                  command=self.login).pack(pady=20)

        tk.Label(
            self.root,
            text="Admin: admin/admin123 | User: user/user123",
            fg="gray", bg="#1e1e2f"
        ).pack()

    def login(self):
        u = self.username_entry.get()
        p = self.password_entry.get()

        if u == ADMIN_USERNAME and p == ADMIN_PASSWORD:
            self.current_user = "admin"
            self.setup_admin_interface()
        elif u == USER_USERNAME and p == USER_PASSWORD:
            self.current_user = "user"
            self.setup_user_interface()
        else:
            messagebox.showerror("Login Failed", "Invalid credentials")

    # ---------------------------------------------------------
    # ADMIN INTERFACE
    # ---------------------------------------------------------
    def setup_admin_interface(self):
        self.clear_window()

        main = tk.Frame(self.root, bg="#1e1e2f")
        main.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        left = tk.Frame(main, bg="#2c2c3c", width=260)
        left.pack(side=tk.LEFT, fill=tk.Y, padx=(0, 10))

        right = tk.Frame(main, bg="#1e1e2f")
        right.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True)

        self.status_label = tk.Label(
            left, text="Status: Stopped",
            fg="red", bg="#2c2c3c"
        )
        self.status_label.pack(pady=10)

        tk.Button(left, text="Start Monitoring",
                  bg="#2ecc71", fg="white",
                  width=22, command=self.start_monitoring).pack(pady=5)

        tk.Button(left, text="Stop Monitoring",
                  bg="#e74c3c", fg="white",
                  width=22, command=self.stop_monitoring).pack(pady=5)

        tk.Button(left, text="View Alerts",
                  bg="#f39c12", width=22,
                  command=self.show_alerts).pack(pady=5)

        tk.Button(left, text="Statistics",
                  bg="#3498db", fg="white",
                  width=22, command=self.show_statistics).pack(pady=5)

        tk.Button(left, text="Attack Panel",
                  bg="#9b59b6", fg="white",
                  width=22, command=self.open_attack_panel).pack(pady=5)

        tk.Button(left, text="Clear Old Logs",
                  bg="#95a5a6", width=22,
                  command=self.clear_logs).pack(pady=5)

        tk.Button(left, text="Logout",
                  bg="#7f8c8d", width=22,
                  command=self.logout).pack(pady=20)

        self.display_area = scrolledtext.ScrolledText(
            right, bg="black", fg="lime",
            font=("Consolas", 10)
        )
        self.display_area.pack(fill=tk.BOTH, expand=True)

    # ---------------------------------------------------------
    # USER INTERFACE
    # ---------------------------------------------------------
    def setup_user_interface(self):
        self.clear_window()

        tk.Label(self.root, text="User Dashboard",
                 font=("Segoe UI", 18),
                 bg="#1e1e2f", fg="white").pack(pady=20)

        self.user_display = scrolledtext.ScrolledText(
            self.root, width=100, height=25
        )
        self.user_display.pack(padx=20, pady=10)

        self.update_user_view()

        tk.Button(self.root, text="Refresh",
                  command=self.update_user_view).pack()
        tk.Button(self.root, text="Logout",
                  command=self.logout).pack(pady=10)

    def update_user_view(self):
        self.user_display.delete(1.0, tk.END)
        alerts = self.ids_core.get_recent_alerts(20)

        if alerts.empty:
            self.user_display.insert(tk.END, "No recent alerts.")
        else:
            for _, a in alerts.iterrows():
                self.user_display.insert(
                    tk.END, f"{a['timestamp']} - {a['message']}\n"
                )

    # ---------------------------------------------------------
    # MONITORING
    # ---------------------------------------------------------
    def start_monitoring(self):
        if not self.is_monitoring:
            self.is_monitoring = True
            self.status_label.config(text="Status: Running", fg="lime")

            threading.Thread(
                target=self.ids_core.start_monitoring,
                daemon=True
            ).start()

            self.display_area.insert(
                tk.END, f"[{datetime.now()}] Monitoring started\n"
            )

    def stop_monitoring(self):
        if self.is_monitoring:
            self.is_monitoring = False
            self.ids_core.stop_monitoring()
            self.status_label.config(text="Status: Stopped", fg="red")
            self.display_area.insert(
                tk.END, f"[{datetime.now()}] Monitoring stopped\n"
            )

    # ---------------------------------------------------------
    # DISPLAY
    # ---------------------------------------------------------
    def show_alerts(self):
        self.display_area.delete(1.0, tk.END)
        alerts = self.ids_core.get_recent_alerts()

        self.display_area.insert(tk.END, "=== ALERTS ===\n\n")
        if alerts.empty:
            self.display_area.insert(tk.END, "No alerts\n")
        else:
            for _, a in alerts.iterrows():
                self.display_area.insert(
                    tk.END, f"{a['timestamp']} - {a['message']}\n"
                )

    def show_statistics(self):
        stats = self.ids_core.get_statistics()
        self.display_area.delete(1.0, tk.END)

        for k, v in stats.items():
            self.display_area.insert(tk.END, f"{k}: {v}\n")

    # ---------------------------------------------------------
    # ATTACK PANEL
    # ---------------------------------------------------------
    def open_attack_panel(self):
        win = tk.Toplevel(self.root)
        win.title("Attack Simulation")
        win.geometry("800x500")

        tk.Button(
            win, text="Launch Bruteforce Attack",
            bg="#e74c3c", fg="white", width=30,
            command=lambda: self.run_attack(
                "Bruteforce", ["python", "test_bruteforce.py"]
            )
        ).pack(pady=10)

        tk.Button(
            win, text="Launch Scapy Attack",
            bg="#f39c12", width=30,
            command=lambda: self.run_attack(
                "Scapy", ["python", "test_scapy_attacks.py"]
            )
        ).pack(pady=10)

        self.attack_output = scrolledtext.ScrolledText(
            win, bg="black", fg="white", height=20
        )
        self.attack_output.pack(fill=tk.BOTH, expand=True)

    def run_attack(self, name, command):
        self.attack_output.insert(
            tk.END, f"[{datetime.now()}] Launching {name} attack...\n"
        )

        def task():
            process = subprocess.Popen(
                ["python", "-u", command[1]],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )

            for line in process.stdout:
                self.attack_output.insert(tk.END, line)

            err = process.stderr.read()
            if err:
                self.attack_output.insert(tk.END, "\nErrors:\n" + err)

            self.attack_output.insert(
                tk.END, f"\n[{datetime.now()}] {name} finished\n"
            )

        threading.Thread(target=task, daemon=True).start()

    # ---------------------------------------------------------
    def clear_logs(self):
        if messagebox.askyesno("Confirm", "Clear old logs?"):
            self.ids_core.clear_old_logs()
            self.display_area.delete(1.0, tk.END)
            self.display_area.insert(
                tk.END, f"[{datetime.now()}] Logs cleared\n"
            )

    def logout(self):
        self.current_user = None
        self.is_monitoring = False
        self.setup_login_screen()

    def clear_window(self):
        for w in self.root.winfo_children():
            w.destroy()

    def run(self):
        self.root.mainloop()
