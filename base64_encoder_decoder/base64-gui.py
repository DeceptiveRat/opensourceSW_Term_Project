import tkinter as tk
from tkinter import messagebox
import base64

class Base64App:
    def __init__(self, master):
        self.master = master
        master.title("Base64 Encoder/Decoder")
        master.geometry("500x400")
        master.configure(bg='#f0f0f0')

        # Input Label and Text Area
        self.input_label = tk.Label(master, text="Input Text:", bg='#f0f0f0', font=('Arial', 12))
        self.input_label.pack(pady=(10, 5))

        self.input_text = tk.Text(master, height=6, width=60, wrap=tk.WORD)
        self.input_text.pack(pady=5)

        # Result Label and Text Area
        self.result_label = tk.Label(master, text="Result:", bg='#f0f0f0', font=('Arial', 12))
        self.result_label.pack(pady=(10, 5))

        self.result_text = tk.Text(master, height=6, width=60, wrap=tk.WORD)
        self.result_text.pack(pady=5)
        self.result_text.config(state=tk.DISABLED)

        # Button Frame
        self.button_frame = tk.Frame(master, bg='#f0f0f0')
        self.button_frame.pack(pady=10)

        # Encode Button
        self.encode_button = tk.Button(
            self.button_frame, 
            text="Encode to Base64", 
            command=self.encode_text, 
            bg='#4CAF50', 
            fg='white', 
            font=('Arial', 10, 'bold')
        )
        self.encode_button.pack(side=tk.LEFT, padx=5)

        # Decode Button
        self.decode_button = tk.Button(
            self.button_frame, 
            text="Decode from Base64", 
            command=self.decode_text, 
            bg='#2196F3', 
            fg='white', 
            font=('Arial', 10, 'bold')
        )
        self.decode_button.pack(side=tk.LEFT, padx=5)

        # Copy Result Button
        self.copy_button = tk.Button(
            self.button_frame, 
            text="Copy Result", 
            command=self.copy_result, 
            bg='#FF9800', 
            fg='white', 
            font=('Arial', 10, 'bold')
        )
        self.copy_button.pack(side=tk.LEFT, padx=5)

    def encode_text(self):
        # Clear previous result
        self.result_text.config(state=tk.NORMAL)
        self.result_text.delete(1.0, tk.END)
        
        # Get input text
        input_text = self.input_text.get(1.0, tk.END).strip()
        
        try:
            # Encode to base64
            encoded = base64.b64encode(input_text.encode('utf-8')).decode('utf-8')
            
            # Display result
            self.result_text.insert(tk.END, encoded)
        except Exception as e:
            messagebox.showerror("Encoding Error", str(e))
        
        self.result_text.config(state=tk.DISABLED)

    def decode_text(self):
        # Clear previous result
        self.result_text.config(state=tk.NORMAL)
        self.result_text.delete(1.0, tk.END)
        
        # Get input text
        input_text = self.input_text.get(1.0, tk.END).strip()
        
        try:
            # Decode from base64
            decoded = base64.b64decode(input_text.encode('utf-8')).decode('utf-8')
            
            # Display result
            self.result_text.insert(tk.END, decoded)
        except Exception as e:
            messagebox.showerror("Decoding Error", str(e))
        
        self.result_text.config(state=tk.DISABLED)

    def copy_result(self):
        # Copy result to clipboard
        result = self.result_text.get(1.0, tk.END).strip()
        if result:
            self.master.clipboard_clear()
            self.master.clipboard_append(result)
            messagebox.showinfo("Copied", "Result copied to clipboard!")

def main():
    root = tk.Tk()
    app = Base64App(root)
    root.mainloop()

if __name__ == "__main__":
    main()
