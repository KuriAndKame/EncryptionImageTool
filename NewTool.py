import tkinter as tk
from tkinter import *
from tkinter import Tk, Button, Label, Entry, filedialog, messagebox
from tkinter import ttk
from PIL import Image, ImageTk 
from tkinterdnd2 import DND_FILES, TkinterDnD
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
from Crypto.Cipher import Salsa20
from Crypto.Hash import SHA256

def get_aes_key(key):
    # Хешируем ключ с помощью SHA-256 и берем первые 32 байта
    return SHA256.new(key.encode('utf-8')).digest()

def get_salsa20_key(key):
    # Хешируем ключ с помощью SHA-256 и берем первые 32 байта
    return SHA256.new(key.encode('utf-8')).digest()[:32]  # Salsa20 требует 16 или 32 байта

def encrypt_aes(input_image_path, output_image_path, key):
    cipher = AES.new(key, AES.MODE_CBC)
    with open(input_image_path, 'rb') as f:
        plaintext = f.read()
    ciphertext = cipher.encrypt(pad(plaintext, AES.block_size))
    
    # Сохраняем инициализационный вектор (IV) вместе с шифротекстом
    with open(output_image_path, 'wb') as f:
        f.write(cipher.iv)  # Записываем IV в начало файла
        f.write(ciphertext)

def decrypt_aes(input_image_path, output_image_path, key):
    with open(input_image_path, 'rb') as f:
        iv = f.read(16)  # Читаем IV
        ciphertext = f.read()
    
    cipher = AES.new(key, AES.MODE_CBC, iv)
    plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)
    
    with open(output_image_path, 'wb') as f:
        f.write(plaintext)



def encrypt_salsa20(input_image_path, output_image_path, key):
    cipher = Salsa20.new(key=key)
    with open(input_image_path, 'rb') as f:
        plaintext = f.read()
    ciphertext = cipher.encrypt(plaintext)
    
    # Сохраняем nonce вместе с шифротекстом
    with open(output_image_path, 'wb') as f:
        f.write(cipher.nonce)  # Записываем nonce в начало файла
        f.write(ciphertext)

def decrypt_salsa20(input_image_path, output_image_path, key):
    with open(input_image_path, 'rb') as f:
        nonce = f.read(8)  # Читаем nonce
        ciphertext = f.read()
    
    cipher = Salsa20.new(key=key, nonce=nonce)
    plaintext = cipher.decrypt(ciphertext)
    
    with open(output_image_path, 'wb') as f:
        f.write(plaintext)


def encrypt():
    input_path = input_image_label.cget("text")  # Получаем путь к изображению
    output_path = output_image_label.cget("text")  # Получаем путь для сохранения
    key = seed_entry.get()  # Получаем ключ от пользователя
    aes_key = get_aes_key(key)  # Преобразуем ключ для AES
    salsa_key = get_salsa20_key(key)  # Преобразуем ключ для Salsa20
    
    method = var.get()
    try:
        if method == 'AES':
            encrypt_aes(input_path, output_path, aes_key)
        elif method == 'Salsa20':
            encrypt_salsa20(input_path, output_path, salsa_key)
        
        # Если операция прошла успешно
        messagebox.showinfo("Успех", "Изображение успешно зашифровано!")
    except Exception as e:
        # Если произошла ошибка
        messagebox.showerror("Ошибка", f"Не удалось зашифровать изображение: {e}")

def decrypt():
    input_path = input_image_label.cget("text")  # Получаем путь к изображению
    output_path = output_image_label.cget("text")  # Получаем путь для сохранения
    key = seed_entry.get()  # Получаем ключ от пользователя
    aes_key = get_aes_key(key)  # Преобразуем ключ для AES
    salsa_key = get_salsa20_key(key)  # Преобразуем ключ для Salsa20
    
    method = var.get()
    try:
        if method == 'AES':
            decrypt_aes(input_path, output_path, aes_key)
        elif method == 'Salsa20':
            decrypt_salsa20(input_path, output_path, salsa_key)
        
        # Если операция прошла успешно
        messagebox.showinfo("Успех", "Изображение успешно дешифровано!")
    except Exception as e:
        # Если произошла ошибка
        messagebox.showerror("Ошибка", f"Не удалось дешифровать изображение: {e}")

def show_image(image_path):
    try:
        # Загружаем изображение
        img = Image.open(image_path)
        img.thumbnail((300, 300))  # Изменяем размер изображения для отображения
        img_tk = ImageTk.PhotoImage(img)

        # Обновляем метку для отображения изображения
        image_label.config(image=img_tk)
        image_label.image = img_tk  # Сохраняем ссылку на изображение
    except Exception as e:
        # Если не удалось загрузить изображение, очищаем метку
        image_label.config(image=None)
        image_label.image = None  # Убираем ссылку на изображение
        print(f"Ошибка при загрузке изображения: {e}")  # Выводим ошибку в консоль

def select_input_image():
    file_path = filedialog.askopenfilename(title="Выберите изображение", filetypes=[("Image files", "*.jpg;*.jpeg;*.png;*.bmp")])
    if file_path:
        input_image_label.config(text=file_path)  # Обновляем метку с путем к изображению
        show_image(file_path)  # Отображаем выбранное изображение


def select_output_image():
    file_path = filedialog.asksaveasfilename(title="Сохранить изображение как", defaultextension=".png", filetypes=[("Image files", "*.jpg;*.jpeg;*.png;*.bmp")])
    if file_path:
        output_image_label.config(text=file_path)  # Обновляем метку с путем для сохранения

def drop(event):
    file_path = event.data  # Получаем путь к файлу из события
    input_image_label.config(text=file_path)  # Обновляем метку с путем к изображению
    show_image(file_path)  # Отображаем изображение при перетаскивании

# Создаем основное окно
root = TkinterDnD.Tk()
root.title("Image Encryption Tool")

Label(root, text="Выберите изображение для шифрации/дешифрации:").pack(pady=5)
input_drop_image = Label(root, text="Перетащите изображение сюда")
input_drop_image.pack(pady=5)
input_image_label = Label(root, text="Изображение не было выбрано")
input_image_label.pack(pady=5)

image_label = tk.Label(root)  # Метка для отображения изображения
image_label.pack(pady=5)

Button(root, text="Выбрать", command=select_input_image).pack(pady=5)

Label(root, text="Путь для сохранения:").pack(pady=5)
output_image_label = Label(root, text="Путь для сохранения не выбран")
output_image_label.pack(pady=5)

Button(root, text="Сохранить", command=select_output_image).pack(pady=5)

Label(root, text="Введите ключ:").pack(pady=5)
seed_entry = Entry(root)
seed_entry.pack(pady=5)

# Настройка перетаскивания
root.drop_target_register(DND_FILES)
root.dnd_bind('<<Drop>>', drop)

# Картеж методов шифрования
encryption_methods = ('AES', 'Salsa20')

# Виджет со списком
var = StringVar()
combobox = ttk.Combobox(root, textvariable=var)
combobox['values'] = encryption_methods
combobox['state'] = 'readonly'
combobox.pack(pady=5)

Button(root, text="Зашифровать изображение", command=encrypt).pack(pady=5)
Button(root, text="Дешифровать изображение", command=decrypt).pack(pady=5)

root.mainloop()