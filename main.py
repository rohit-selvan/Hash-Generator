import tkinter as tk
from tkinter import filedialog, messagebox
import hashlib

class HashGenerator(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Hash Generator")
        self.geometry("600x500")
        self.configure(bg="#f0f4f8")  # Soft pastel background
        self.create_widgets()

    def create_widgets(self):
        # Title
        tk.Label(self, text="Hash Generator", font=("Verdana", 24, "bold"), bg="#f0f4f8", fg="#2c3e50").pack(pady=20)
        
        # Text input for hash generation
        tk.Label(self, text="Enter text to hash:", font=("Verdana", 14), bg="#f0f4f8").pack(pady=5)
        self.text_entry = tk.Entry(self, font=("Verdana", 14), width=50)
        self.text_entry.pack(pady=10)
        
        # Generate hash buttons
        tk.Button(self, text="Generate MD5 Hash", command=lambda: self.generate_hash('md5'), font=("Verdana", 14), bg="#3498db", fg="white", width=20).pack(pady=5)
        tk.Button(self, text="Generate SHA-256 Hash", command=lambda: self.generate_hash('sha256'), font=("Verdana", 14), bg="#2ecc71", fg="white", width=20).pack(pady=5)
        
        # Hash result display
        self.result_text = tk.Text(self, font=("Verdana", 12), height=5, width=70, state=tk.DISABLED, wrap=tk.WORD)
        self.result_text.pack(pady=10)
        
        # Button to select file and generate hash
        tk.Button(self, text="Generate Hash from File", command=self.select_file, font=("Verdana", 14), bg="#f39c12", fg="white", width=25).pack(pady=10)

    def generate_hash(self, algorithm):
        text = self.text_entry.get().strip()
        if not text:
            messagebox.showwarning("Input Error", "Please enter some text.")
            return
        try:
            hash_func = hashlib.new(algorithm)
            hash_func.update(text.encode('utf-8'))
            hash_value = hash_func.hexdigest()
            self.display_hash(hash_value)
        except Exception as e:
            messagebox.showerror("Error", f"An error occurred: {str(e)}")
    
    def select_file(self):
        file_path = filedialog.askopenfilename(title="Select a File")
        if not file_path:
            return
        try:
            hash_value = self.generate_file_hash(file_path, 'sha256')
            self.display_hash(hash_value)
        except Exception as e:
            messagebox.showerror("Error", f"An error occurred: {str(e)}")
    
    def generate_file_hash(self, file_path, algorithm):
        hash_func = hashlib.new(algorithm)
        with open(file_path, 'rb') as file:
            while chunk := file.read(8192):
                hash_func.update(chunk)
        return hash_func.hexdigest()

    def display_hash(self, hash_value):
        self.result_text.config(state=tk.NORMAL)
        self.result_text.delete("1.0", tk.END)
        self.result_text.insert(tk.END, f"Hash Value: {hash_value}\n")
        self.result_text.config(state=tk.DISABLED)

if __name__ == "__main__":
    app = HashGenerator()
    app.mainloop()
