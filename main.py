# image_encryptor/main.py

import customtkinter as ctk
from tkinterdnd2 import TkinterDnD
from gui.app import CryptoAppFrame

# Define a root window class that is compatible with both libraries
class AppRoot(TkinterDnD.Tk, ctk.CTk):
    def __init__(self, *args, **kwargs):
        ctk.CTk.__init__(self, *args, **kwargs)
        TkinterDnD.Tk.__init__(self)

if __name__ == '__main__':
    ctk.set_appearance_mode("System")
    ctk.set_default_color_theme("blue")

    root = AppRoot()
    root.title("Secure Image Encryptor")
    root.geometry("800x600")
    root.minsize(700, 500)

    root.grid_columnconfigure(0, weight=1)
    root.grid_rowconfigure(0, weight=1)

    app_frame = CryptoAppFrame(master=root)
    app_frame.grid(row=0, column=0, padx=10, pady=10, sticky="nsew")

    # --- UPDATED SHUTDOWN HANDLER ---
    def on_closing():
        """Handles the window closing event gracefully."""
        app_frame.shutdown() # Signal to the app frame that we are closing
        root.destroy()

    root.protocol("WM_DELETE_WINDOW", on_closing)
    # ------------------------------------

    # Start the main loop with graceful shutdown for Ctrl+C
    try:
        root.mainloop()
    except KeyboardInterrupt:
        on_closing()