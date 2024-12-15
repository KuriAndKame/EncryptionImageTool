import os
import tkinter as tk
import random
import base64
import hashlib
from tkinter import *
from tkinter import Tk, Button, Label, Entry, filedialog, messagebox
from tkinter import ttk
from PIL import Image, ImageTk 
from tkinterdnd2 import DND_FILES, TkinterDnD
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES


def get_seeded_random(seed):
    """Генерирует seed."""
    return random.Random(seed)

def generate_rsa_keys():
    """Генерация пары ключей RSA."""
    key = RSA.generate(2048)  # Генерация 2048-битного ключа
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    return private_key, public_key

def text_to_32_byte_key(seed):
    """Конвертирует введенный текст в 32-байтовый ключ."""
    # Create a SHA-256 hash of the input text
    sha256_hash = hashlib.sha256(seed.encode('utf-8')).digest()
    return sha256_hash

def encrypt_image(input_image_path, output_image_path, seed, method):
    """Шифрация изображения."""
    match method:
        case 'AES':
            image = Image.open(input_image_path)
            width, height = image.size
            
            pixels = list(image.getdata())
            random_gen = get_seeded_random(seed)

            indices = list(range(len(pixels)))
            random_gen.shuffle(indices)

            encrypted_pixels = [pixels[i] for i in indices]

            encrypted_image = Image.new(image.mode, (width, height))
            encrypted_image.putdata(encrypted_pixels)
            encrypted_image.save(output_image_path)
            return True
        
        case 'RSA':
            # Загружаем изображение и конвертируем его в байты
            image = Image.open(input_image_path)
            image_data = image.tobytes()  # Получаем сырые данные изображения
            
            # Генерируем 32-байтный ключ из seed
            aes_key = text_to_32_byte_key(seed)
            
            # Шифруем данные изображения с помощью AES
            cipher_aes = AES.new(aes_key, AES.MODE_EAX)
            ciphertext, tag = cipher_aes.encrypt_and_digest(image_data)

            # Генерируем RSA ключи и шифруем AES ключ
            private_key, public_key = generate_rsa_keys()
            cipher_rsa = PKCS1_OAEP.new(RSA.import_key(public_key))
            encrypted_aes_key = cipher_rsa.encrypt(aes_key)

            # Сохраняем зашифрованные данные в бинарный файл
            with open(output_image_path, 'wb') as encrypted_file:
                # Записываем зашифрованный AES ключ
                encrypted_file.write(base64.b64encode(encrypted_aes_key) + b'\n')
                # Записываем nonce, tag и ciphertext
                encrypted_file.write(cipher_aes.nonce + tag + ciphertext)

            return True

def decrypt_image(input_image_path, output_image_path, seed, method):
    """Расшифровка изображения."""
    match method:
        case 'AES':
            image = Image.open(input_image_path)
            width, height = image.size
            
            encrypted_pixels = list(image.getdata())
            random_gen = get_seeded_random(seed)

            indices = list(range(len(encrypted_pixels)))
            random_gen.shuffle(indices)

            decrypted_pixels = [None] * len(encrypted_pixels)

            for original_index, shuffled_index in enumerate(indices):
                decrypted_pixels[shuffled_index] = encrypted_pixels[original_index]

            decrypted_image = Image.new(image.mode, (width, height))
            decrypted_image.putdata(decrypted_pixels)
            decrypted_image.save(output_image_path)
            return True
        
        case 'RSA':
                       # Генерация пары ключей RSA
            private_key, public_key = generate_rsa_keys()
            cipher_rsa = PKCS1_OAEP.new(RSA.import_key(private_key))

            # Читаем зашифрованные данные из файла
            with open(input_image_path, 'rb') as encrypted_file:
                # Читаем зашифрованный AES ключ
                encrypted_aes_key = base64.b64decode(encrypted_file.readline().strip())
                nonce = encrypted_file.read(16)  # Читаем nonce
                tag = encrypted_file.read(16)     # Читаем tag
                ciphertext = encrypted_file.read() # Читаем оставшиеся данные

            # Расшифровываем AES ключ
            aes_key = cipher_rsa.decrypt(encrypted_aes_key)

            # Расшифровываем данные изображения с помощью AES
            cipher_aes = AES.new(aes_key, AES.MODE_EAX, nonce=nonce)
            decrypted_image_data = cipher_aes.decrypt_and_verify(ciphertext, tag)

            # Создаем изображение из расшифрованных данных
            decrypted_image = Image.frombytes('RGB', (width, height), decrypted_image_data)  # Укажите правильные параметры
            decrypted_image.save(output_image_path)
            return True


def load_image(path):
    global photo, image_label
    image = Image.open(path)
    
    # Изменяем размер изображения
    max_size = (300, 300)  # Максимальный размер (ширина, высота)
    image.thumbnail(max_size)  # Изменяем размер с сохранением пропорций
    
    photo = ImageTk.PhotoImage(image)
    
    # Обновляем или создаем Label для отображения изображения
    if 'image_label' not in globals():
        image_label = tk.Label(root)
        image_label.pack()
    
    #input_drop_image.config("")
    image_label.config(image=photo)  # Обновляем изображение в Label
    image_label.image = photo  # Сохраняем ссылку на изображение


def select_input_image():
    """Выбор изображения."""
    global image_path
    image_path = filedialog.askopenfilename(title="Выберите изображение")
    input_image_label.config(text=image_path)
    if image_path:
        load_image(image_path)

def select_output_image():
    """Выбор для сохранения результата."""
    global output_image_path
    output_image_path = filedialog.asksaveasfilename(defaultextension=".png", filetypes=[("PNG files", "*.png"),("JPEG files", "*.jpg;*.jpeg"),("All files", "*.*")], title="Сохранить как")
    output_image_label.config(text=output_image_path)

def encrypt():
    input_image_path = input_image_label.cget("text")
    output_image_path = output_image_label.cget("text")
    seed = seed_entry.get()
    method = combobox.get()

    if not input_image_path or not output_image_path:
        messagebox.showerror("Ошибка", "Пожалуйста, выберите изображение или путь для сохранения результата.")
        return

    
    if encrypt_image(input_image_path, output_image_path, seed, method):
        messagebox.showinfo("Успех!", "Изображение успешно зашифровано!")

def decrypt():
    input_image_path = input_image_label.cget("text")
    output_image_path = output_image_label.cget("text")
    seed = seed_entry.get()
    method = combobox.get()

    if not input_image_path or not output_image_path:
        messagebox.showerror("Ошибка", "Пожалуйста, выберите изображение или путь для сохранения результата.")
        return

    if decrypt_image(input_image_path, output_image_path, seed, method):
        messagebox.showinfo("Успех!", "Изображение успешно дешифровано!")


def drop(event):
    """Обработка перетаскивания изображения."""
    file_path = event.data
    
    if os.path.isfile(file_path) and file_path.lower().endswith(('.png', '.jpg', '.jpeg')):
        load_image(file_path)
        input_image_label.config(text=file_path)



# Создаем основное окно
root = TkinterDnD.Tk()
root.title("Image Encryption Tool")

Label(root, text="Выберите изображение для шифрации/дешифрации:").pack(pady=5)
input_drop_image = Label(root, text="Перетащите изображение сюда")
input_drop_image.pack(pady=5)
input_image_label = Label(root, text="Изображение не было выбрано")
input_image_label.pack(pady=5)

image_label = tk.Label(root)
image_label.pack()

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


#Картеж методов шифрования
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


