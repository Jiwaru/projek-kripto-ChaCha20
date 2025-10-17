# image_encryptor/gui/app.py

import customtkinter as ctk
from tkinter import filedialog, messagebox
from tkinterdnd2 import DND_FILES
import threading
import os
import io
from PIL import Image

from core import crypto

class CryptoAppFrame(ctk.CTkFrame):
    def __init__(self, master, **kwargs):
        super().__init__(master, **kwargs)
        self.master = master

        # --- State Variables ---
        self.file_path = ctk.StringVar()
        self.key = ctk.StringVar()
        self.status_text = ctk.StringVar(value="Drag & drop a file here, or use the browse button.")
        self.operation_thread = None
        self.is_shutting_down = False # <-- NEW: Shutdown flag

        # --- Configure Responsive Grid Layout for the Frame ---
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(1, weight=1)

        self._create_widgets()
        self._setup_drag_and_drop()

    def shutdown(self):
        """Prepares the frame for a clean shutdown."""
        self.is_shutting_down = True # <-- NEW: Method to set the flag

    def _create_widgets(self):
        """Creates and lays out all the widgets in the window."""
        padding = {'padx': 10, 'pady': 5}

        # --- Controls Frame (for inputs and buttons) ---
        controls_frame = ctk.CTkFrame(self)
        controls_frame.grid(row=0, column=0, sticky="ew", padx=10, pady=(10, 5))
        controls_frame.grid_columnconfigure(0, weight=1)

        # --- File Selection Widgets (inside controls_frame) ---
        file_frame = ctk.CTkFrame(controls_frame, fg_color="transparent")
        file_frame.grid(row=0, column=0, sticky="ew", pady=(0, 5))
        file_frame.grid_columnconfigure(1, weight=1)
        ctk.CTkLabel(file_frame, text="Input File:").grid(row=0, column=0, padx=(0, 10))
        self.file_entry = ctk.CTkEntry(file_frame, textvariable=self.file_path, state="readonly")
        self.file_entry.grid(row=0, column=1, sticky="ew")
        self.browse_button = ctk.CTkButton(file_frame, text="Browse...", command=self.browse_file, width=100)
        self.browse_button.grid(row=0, column=2, padx=(10, 0))

        # --- Key and Action Widgets (inside controls_frame) ---
        key_frame = ctk.CTkFrame(controls_frame, fg_color="transparent")
        key_frame.grid(row=1, column=0, sticky="ew")
        key_frame.grid_columnconfigure(1, weight=1)
        ctk.CTkLabel(key_frame, text="Secret Key:").grid(row=0, column=0, padx=(0, 10))
        self.key_entry = ctk.CTkEntry(key_frame, textvariable=self.key, show="*")
        self.key_entry.grid(row=0, column=1, sticky="ew")
        
        action_buttons_frame = ctk.CTkFrame(key_frame, fg_color="transparent")
        action_buttons_frame.grid(row=0, column=2, padx=(10, 0))
        self.encrypt_button = ctk.CTkButton(action_buttons_frame, text="Encrypt", command=self.encrypt_action, width=100)
        self.encrypt_button.pack(side="left", padx=(0, 5))
        self.decrypt_button = ctk.CTkButton(action_buttons_frame, text="Decrypt", command=self.decrypt_action, width=100)
        self.decrypt_button.pack(side="left")

        # --- Image Display Frame ---
        self.image_frame = ctk.CTkFrame(self, fg_color="gray20")
        self.image_frame.grid(row=1, column=0, sticky="nsew", **padding)
        self.image_frame.grid_columnconfigure(0, weight=1)
        self.image_frame.grid_rowconfigure(0, weight=1)

        self.image_label = ctk.CTkLabel(self.image_frame, text="")
        self.image_label.grid(row=0, column=0, sticky="nsew")

        # --- Status and Progress Widgets ---
        status_frame = ctk.CTkFrame(self)
        status_frame.grid(row=2, column=0, sticky="ew", padx=10, pady=(5, 10))
        status_frame.grid_columnconfigure(0, weight=1)
        
        self.status_label = ctk.CTkLabel(status_frame, textvariable=self.status_text)
        self.status_label.grid(row=0, column=0, sticky="ew")
        
        self.progress_bar = ctk.CTkProgressBar(status_frame, mode='indeterminate')
        self.progress_bar.grid(row=1, column=0, sticky="ew", pady=(5, 0))
        self.progress_bar.grid_remove()

    def _monitor_thread(self, thread, on_success, on_error):
        """Checks if the thread is still running and updates UI accordingly."""
        if self.is_shutting_down: # <-- NEW: Check flag
            return

        if thread.is_alive():
            self.after(100, lambda: self._monitor_thread(thread, on_success, on_error))
        else:
            self._end_task()
            if hasattr(thread, 'error') and thread.error:
                on_error(thread.error)
            else:
                on_success()

    def encrypt_action(self):
        if not self._validate_inputs():
            return
        
        self._clear_image_display()
        output_path = filedialog.asksaveasfilename(defaultextension=".enc", filetypes=[("Encrypted Files", "*.enc")])
        if not output_path:
            return

        self.status_text.set("Encrypting...")
        self._start_task()

        self.operation_thread = threading.Thread(
            target=self._perform_operation,
            args=(crypto.encrypt_image, self.file_path.get(), output_path)
        )
        self.operation_thread.daemon = True # Set thread as daemonic
        self.operation_thread.start()
        self._monitor_thread(
            self.operation_thread,
            on_success=lambda: self._on_encrypt_success(output_path),
            on_error=self._on_operation_error
        )

    def decrypt_action(self):
        if not self._validate_inputs():
            return

        output_path = filedialog.asksaveasfilename(defaultextension=".jpg", filetypes=[("JPEG files", "*.jpg"), ("PNG files", "*.png"), ("All files", "*.*")])
        if not output_path:
            return

        self.status_text.set("Decrypting...")
        self._start_task()

        self.operation_thread = threading.Thread(
            target=self._perform_operation,
            args=(crypto.decrypt_image, self.file_path.get(), output_path)
        )
        self.operation_thread.daemon = True # Set thread as daemonic
        self.operation_thread.start()
        self._monitor_thread(
            self.operation_thread,
            on_success=lambda: self._on_decrypt_success(output_path),
            on_error=self._on_operation_error
        )

    # --- All other methods remain the same as the previous full code version ---
    def _clear_image_display(self):
        self.image_label.configure(image=None)
        self.image_label.image = None

    def _display_image(self, image_data):
        try:
            image = Image.open(io.BytesIO(image_data))
            frame_width = self.image_frame.winfo_width()
            frame_height = self.image_frame.winfo_height()
            if frame_width < 2 or frame_height < 2:
                frame_width, frame_height = 500, 400
            img_ratio = image.width / image.height
            frame_ratio = frame_width / frame_height
            if img_ratio > frame_ratio:
                new_width = frame_width
                new_height = int(new_width / img_ratio)
            else:
                new_height = frame_height
                new_width = int(new_height * img_ratio)
            ctk_image = ctk.CTkImage(light_image=image, dark_image=image, size=(new_width, new_height))
            self.image_label.configure(image=ctk_image, text="")
            self.image_label.image = ctk_image
        except Exception as e:
            self.status_text.set("Decryption successful, but failed to display image.")
            messagebox.showwarning("Display Error", f"Could not display the decrypted image.\nError: {e}")

    def _setup_drag_and_drop(self):
        self.master.drop_target_register(DND_FILES)
        self.master.dnd_bind('<<Drop>>', self._handle_drop)

    def _handle_drop(self, event):
        filepaths = self.master.tk.splitlist(event.data)
        if filepaths:
            self._clear_image_display()
            self.file_path.set(filepaths)
            self.status_text.set(f"Selected: {os.path.basename(filepaths)}")

    def browse_file(self):
        path = filedialog.askopenfilename()
        if path:
            self._clear_image_display()
            self.file_path.set(path)
            self.status_text.set(f"Selected: {os.path.basename(path)}")

    def _validate_inputs(self):
        if not self.file_path.get():
            messagebox.showerror("Error", "Please select an input file.")
            return False
        if not self.key.get():
            messagebox.showerror("Error", "Please enter a secret key.")
            return False
        return True

    def _toggle_controls(self, is_enabled):
        state = "normal" if is_enabled else "disabled"
        self.browse_button.configure(state=state)
        self.key_entry.configure(state=state)
        self.encrypt_button.configure(state=state)
        self.decrypt_button.configure(state=state)

    def _start_task(self):
        self._toggle_controls(False)
        self.progress_bar.grid()
        self.progress_bar.start()

    def _end_task(self):
        self.progress_bar.stop()
        self.progress_bar.grid_remove()
        self._toggle_controls(True)

    def _perform_operation(self, operation_func, input_path, output_path):
        try:
            derived_key = crypto.derive_key_from_password(self.key.get())
            result = operation_func(input_path, derived_key, output_path)
            threading.current_thread().result = result
            threading.current_thread().error = None
        except Exception as e:
            threading.current_thread().result = None
            threading.current_thread().error = e

    def _on_decrypt_success(self, path):
        self.status_text.set("Decryption successful!")
        messagebox.showinfo("Success", f"File decrypted and saved to:\n{path}")
        image_data = getattr(self.operation_thread, 'result', None)
        if image_data:
            self.after(100, lambda: self._display_image(image_data))

    def _on_encrypt_success(self, path):
        self.status_text.set("Encryption successful!")
        messagebox.showinfo("Success", f"File encrypted and saved to:\n{path}")

    def _on_operation_error(self, error):
        self.status_text.set("Operation failed. Check key or file.")
        if isinstance(error, (ValueError, TypeError)):
             messagebox.showerror("Decryption Failed", "Decryption failed. The key may be incorrect or the file may be corrupted.")
        else:
            messagebox.showerror("Operation Failed", f"An unexpected error occurred:\n{error}")