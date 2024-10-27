import base64
from tkinter import END, filedialog, messagebox

import ttkbootstrap as ttk
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from docx import Document


# Fungsi untuk enkripsi
def encrypt_text(plaintext):
    key = entry_key.get()
    
    # Validasi panjang kunci
    if len(key) not in [16, 24, 32]:
        messagebox.showerror("Error", "Panjang kunci harus 16, 24, atau 32 karakter.")
        return
    
    try:
        cipher = AES.new(key.encode(), AES.MODE_ECB)
        encrypted_text = cipher.encrypt(pad(plaintext.encode(), AES.block_size))
        encoded_ciphertext = base64.b64encode(encrypted_text).decode()
        entry_ciphertext.delete(0, END)
        entry_ciphertext.insert(0, encoded_ciphertext)
    except Exception as e:
        messagebox.showerror("Error", f"Terjadi kesalahan: {e}")

# Fungsi untuk dekripsi
def decrypt_text():
    ciphertext = entry_ciphertext.get()
    key = entry_key.get()
    
    # Validasi panjang kunci
    if len(key) not in [16, 24, 32]:
        messagebox.showerror("Error", "Panjang kunci harus 16, 24, atau 32 karakter.")
        return
    
    try:
        decoded_ciphertext = base64.b64decode(ciphertext)
        cipher = AES.new(key.encode(), AES.MODE_ECB)
        decrypted_data = unpad(cipher.decrypt(decoded_ciphertext), AES.block_size).decode()
        entry_decrypted.delete(0, END)
        entry_decrypted.insert(0, decrypted_data)
    except Exception as e:
        messagebox.showerror("Error", f"Terjadi kesalahan: {e}")

# Fungsi untuk menyimpan hasil enkripsi
def save_result():
    result = entry_ciphertext.get()  # Ambil hasil enkripsi
    if not result:
        messagebox.showwarning("Peringatan", "Tidak ada hasil untuk disimpan.")
        return
    file_path = filedialog.asksaveasfilename(defaultextension=".txt", title="Simpan Hasil Sebagai")
    if file_path:
        try:
            with open(file_path, 'w') as file:
                file.write(result)
            messagebox.showinfo("Info", "Hasil berhasil disimpan.")
        except Exception as e:
            messagebox.showerror("Error", f"Terjadi kesalahan saat menyimpan file: {e}")

# Fungsi untuk mengupload file
def upload_file():
    file_path = filedialog.askopenfilename(title="Pilih File untuk Diupload", 
                                            filetypes=[("Text Files", "*.txt"), ("Word Files", "*.docx")])
    if file_path:
        try:
            if file_path.endswith('.txt'):
                with open(file_path, 'r') as file:
                    file_content = file.read()
            elif file_path.endswith('.docx'):
                doc = Document(file_path)
                file_content = '\n'.join([para.text for para in doc.paragraphs])
            else:
                messagebox.showwarning("Peringatan", "Format file tidak didukung.")
                return

            entry_plaintext.delete(0, END)
            entry_plaintext.insert(0, file_content)
        except Exception as e:
            messagebox.showerror("Error", f"Terjadi kesalahan saat membaca file: {e}")

# Fungsi untuk melakukan enkripsi dari inputan
def process_encrypt():
    plaintext = entry_plaintext.get()
    if not plaintext:
        messagebox.showwarning("Peringatan", "Tidak ada teks untuk dienkripsi.")
        return
    encrypt_text(plaintext)

# GUI dengan ttkbootstrap
root = ttk.Window(themename="darkly")
root.title("Enkripsi dan Dekripsi AES")
root.geometry("600x600")


# Judul aplikasi
title_label = ttk.Label(root, text="Enkripsi dan Dekripsi AES", font=("Helvetica", 16), bootstyle="primary")
title_label.pack(pady=10)

# Frame untuk Inputan
input_frame = ttk.Frame(root)
input_frame.pack(pady=10)

# Label dan Entry untuk Plaintext
ttk.Label(input_frame, text="Plaintext", font=("Helvetica", 10)).grid(row=0, column=0, padx=5, pady=5)
entry_plaintext = ttk.Entry(input_frame, width=40)
entry_plaintext.grid(row=1, column=0, padx=5, pady=5)

# Label dan Entry untuk Kunci
ttk.Label(input_frame, text="Kunci (16, 24, atau 32 karakter)", font=("Helvetica", 10)).grid(row=0, column=1, padx=5, pady=5)
entry_key = ttk.Entry(input_frame, width=40, show="*")  # Password-style entry
entry_key.grid(row=1, column=1, padx=5, pady=5)

# Frame untuk tombol Upload dan Clear
action_frame = ttk.Frame(root)
action_frame.pack(pady=10)

# Tombol untuk Upload File
btn_upload = ttk.Button(action_frame, text="Upload File", command=upload_file, bootstyle="info")
btn_upload.grid(row=0, column=0, padx=(0, 10))

# Tombol untuk Clear
btn_clear = ttk.Button(action_frame, text="Clear All", command=lambda: [entry_plaintext.delete(0, END), 
                                                                        entry_ciphertext.delete(0, END), 
                                                                        entry_decrypted.delete(0, END), 
                                                                        entry_key.delete(0, END)], 
                       bootstyle="danger")
btn_clear.grid(row=0, column=1)

# Tombol untuk Enkripsi
btn_encrypt = ttk.Button(action_frame, text="Enkripsi", command=process_encrypt, width=20, bootstyle="success")
btn_encrypt.grid(row=0, column=2, padx=(10, 0))

# Tombol untuk Dekripsi
btn_decrypt = ttk.Button(action_frame, text="Dekripsi", command=decrypt_text, width=20, bootstyle="info")
btn_decrypt.grid(row=0, column=3)

# Frame untuk Output
output_frame = ttk.Frame(root)
output_frame.pack(pady=10)

# Label dan Entry untuk Ciphertext (Output Enkripsi)
ttk.Label(output_frame, text="Ciphertext (Output Enkripsi)", font=("Helvetica", 10)).grid(row=0, column=0, padx=5, pady=5)
entry_ciphertext = ttk.Entry(output_frame, width=40)
entry_ciphertext.grid(row=1, column=0, padx=5, pady=5)

# Label dan Entry untuk Hasil Dekripsi
ttk.Label(output_frame, text="Teks Dekripsi (Output Dekripsi)", font=("Helvetica", 10)).grid(row=0, column=1, padx=5, pady=5)
entry_decrypted = ttk.Entry(output_frame, width=40)
entry_decrypted.grid(row=1, column=1, padx=5, pady=5)

# Frame untuk tombol Simpan Hasil
file_frame = ttk.Frame(root)
file_frame.pack(pady=10)

# Tombol untuk Simpan Hasil
btn_save = ttk.Button(file_frame, text="Simpan Hasil", command=save_result, width=20, bootstyle="secondary")
btn_save.grid(row=0, column=0)

# Membuat garis tebal 2 cm di bawah tombol
separator = ttk.Separator(file_frame, orient='horizontal')
separator.grid(row=8, column=0, sticky='ew', pady=(10, 0))

# Mengatur ukuran garis menjadi 2 cm
separator.configure(style='Solid.TSeparator')
file_frame.grid_columnconfigure(0, weight=4)

# Frame untuk informasi Tugas Kelompok
group_frame = ttk.Frame(root)
group_frame.pack(pady=10)

# Label untuk Tugas Kelompok Kelas
ttk.Label(group_frame, text="TUGAS KELOMPOK KRIPTOGRAFI KELAS 5TKKO-G :", font=("Helvetica", 12)).pack(anchor='w', padx=5)

# Anggota 1
ttk.Label(group_frame, text="Nama Lengkap: Sitti Rohani", font=("Helvetica", 10)).pack(anchor='w', padx=5)
ttk.Label(group_frame, text="STB: 222061", font=("Helvetica", 10)).pack(anchor='w', padx=5)

# Anggota 2
ttk.Label(group_frame, text="Nama Lengkap: Sarini", font=("Helvetica", 10)).pack(anchor='w', padx=5)
ttk.Label(group_frame, text="STB: 222047", font=("Helvetica", 10)).pack(anchor='w', padx=5)

# Anggota 3
ttk.Label(group_frame, text="Nama Lengkap: Andi Ulil Akbar", font=("Helvetica", 10)).pack(anchor='w', padx=5)
ttk.Label(group_frame, text="STB: 222060 ", font=("Helvetica", 10)).pack(anchor='w', padx=5)

# Jalankan aplikasi
root.mainloop()
