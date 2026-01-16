# main.py
from ids_core import IDSCore
from gui_interface import IDSGUI

def main():
    print("""
    ╔══════════════════════════════════════════════════╗
    ║      Intrusion Detection System (IDS)            ║
    ║              Mini Project                        ║
    ║      Group: Mohamed Aziz, Chahin, Youssef        ║
    ╚══════════════════════════════════════════════════╝
    """)
    
    # Initialize IDS
    ids = IDSCore()
    
    # Start GUI
    gui = IDSGUI(ids)
    gui.run()

if __name__ == "__main__":
    main()