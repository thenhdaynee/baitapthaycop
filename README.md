# 🔒 Báo Cáo Môn An Toàn và Bảo Mật Thông Tin

Báo cáo nghiên cứu chuyên sâu về các thuật toán mã hóa hiện đại (**DES**, **AES**), thuật toán mã hóa bất đối xứng (**RSA**), và mô hình kết hợp sức mạnh mã hóa **Hybrid Encryption**.

---

## 📑 Mục Lục
1. [Thuật Toán Mã Hóa Hiện Đại (DES & AES)](#1-thuật-toán-mã-hóa-hiện-đại-des--aes)
   - [Thuật toán DES](#11-thuật-toán-des-data-encryption-standard)
   - [Thuật toán AES](#12-thuật-toán-aes-advanced-encryption-standard)
   - [Cài đặt AES-128 (CBC Mode) bằng Python](#13-cài-đặt-aes-128-chế-độ-cbc-bằng-python)
2. [Thuật Toán Mã Hóa Bất Đối Xứng RSA](#2-thuật-toán-mã-hóa-bất-đối-xứng-rsa)
   - [Nguyên lý sinh cặp khóa RSA](#21-nguyên-lý-sinh-cặp-khóa-rsa)
3. [Mô Hình Bảo Mật RSA & Mã Hóa Hỗn Hợp](#3-mô-hình-bảo-mật-rsa--mã-hóa-hỗn-hợp)
   - [Các mô hình áp dụng RSA](#31-các-mô-hình-áp-dụng-thuật-toán-rsa)
   - [So sánh RSA vs AES](#32-so-sánh-thời-gian-và-đặc-tính-rsa-vs-aes)
   - [Mô hình Kết hợp (Hybrid Encryption)](#33-mô-hình-mã-hóa-hỗn-hợp-hybrid-encryption)

---

## 1. Thuật Toán Mã Hóa Hiện Đại (DES & AES)

Mã hóa đối xứng (*Symmetric Encryption*) sử dụng chung một khóa bí mật (*Secret Key*) cho cả hai quá trình mã hóa dữ liệu đầu vào và giải mã dữ liệu đầu ra.

### 1.1 Thuật toán DES (Data Encryption Standard)
DES là thuật toán mã hóa khối (*Block Cipher*) dựa trên cấu trúc Feistel, được NIST công nhận làm chuẩn mã hóa từ năm 1977.

* **Kích thước khối (Block size):** 64-bit.
* **Độ dài khóa (Key length):** 64-bit (trong đó 8-bit kiểm tra parity, độ dài thực tế là **56-bit**).
* **Số vòng lặp (Rounds):** 16 vòng.

#### Quy trình mã hóa / giải mã
1. **Hoán vị ban đầu (IP):** Khối 64-bit qua bảng hoán vị cố định.
2. **Phân chia khối:** Chia thành 2 nửa $L_0$ (32-bit) và $R_0$ (32-bit).
3. **16 vòng Feistel:** 
   - Từ khóa 56-bit sinh ra 16 khóa con $K_1, K_2, \dots, K_{16}$ (mỗi khóa 48-bit).
   - Công thức lặp: $L_i = R_{i-1}$ và $R_i = L_{i-1} \oplus f(R_{i-1}, K_i)$.
   - **Hàm $f(R_{i-1}, K_i)$:** Mở rộng $R_{i-1}$ lên 48-bit $\rightarrow$ Cộng XOR với khóa $K_i$ $\rightarrow$ Qua bảng thế S-Box phi tuyến (48-bit $\rightarrow$ 32-bit) $\rightarrow$ Hoán vị P.
4. **Hoán vị nghịch đảo ($IP^{-1}$):** Đổi chỗ $R_{16}, L_{16}$ ghép lại thành 64-bit và qua bảng $IP^{-1}$ tạo bản mã.
5. **Giải mã:** Áp dụng quy trình tương tự mã hóa nhưng đảo ngược thứ tự các khóa con từ $K_{16}$ về $K_1$.

---

### 1.2 Thuật toán AES (Advanced Encryption Standard)
AES được NIST lựa chọn năm 2001 để thay thế DES nhờ tốc độ và tính an toàn vượt trội (dựa trên mạng thế - hoán vị SPN).

* **Kích thước khối:** 128-bit cố định (ma trận $4 \times 4$ byte).
* **Biến thể khóa & Số vòng:**
  - **AES-128:** Khóa 128-bit $\rightarrow$ **10 vòng**.
  - **AES-192:** Khóa 192-bit $\rightarrow$ **12 vòng**.
  - **AES-256:** Khóa 256-bit $\rightarrow$ **14 vòng**.

```text
Input Block (128-bit)
       │
       ▼
 [AddRoundKey] ◄─── Khóa ban đầu (K0)
       │
   ┌───┴──────────────────────────────┐
   │ Loop 1 to N-1 rounds:           │
   │  1. SubBytes    (Thế S-Box)      │
   │  2. ShiftRows   (Dịch hàng)      │
   │  3. MixColumns  (Trộn cột)       │
   │  4. AddRoundKey (Cộng khóa con) ◄┼── Khóa vòng Ki
   └───┬──────────────────────────────┘
       │
   ┌───┴──────────────────────────────┐
   │ Final Round (Round N):           │
   │  1. SubBytes                     │
   │  2. ShiftRows                    │
   │  3. AddRoundKey                 ◄┼── Khóa vòng KN
   └───┬──────────────────────────────┘
       ▼
Ciphertext (128-bit)
### 1.3 Cài đặt AES-128 (Chế độ CBC) bằng Python

```python
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend

def generate_key_and_iv():
    # Khóa 128-bit (16 bytes) và IV 128-bit (16 bytes)
    key = os.urandom(16)
    iv = os.urandom(16)
    return key, iv

def encrypt_aes_cbc(plaintext: str, key: bytes, iv: bytes) -> bytes:
    # Padding dữ liệu về bội số của 16 bytes (PKCS7)
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(plaintext.encode('utf-8')) + padder.finalize()
    
    # Mã hóa AES-CBC
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    return encryptor.update(padded_data) + encryptor.finalize()

def decrypt_aes_cbc(ciphertext: bytes, key: bytes, iv: bytes) -> str:
    # Giải mã AES-CBC
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded_data = decryptor.update(ciphertext) + decryptor.finalize()
    
    # Unpadding dữ liệu
    unpadder = padding.PKCS7(128).unpadder()
    data = unpadder.update(padded_data) + unpadder.finalize()
    return data.decode('utf-8')

if __name__ == "__main__":
    message = "Thong tin bao mat mon An toan thong tin!"
    key, iv = generate_key_and_iv()
    
    print(f"Văn bản gốc: {message}")
    encrypted = encrypt_aes_cbc(message, key, iv)
    print(f"Bản mã (Hex): {encrypted.hex()}")
    
    decrypted = decrypt_aes_cbc(encrypted, key, iv)
    print(f"Văn bản giải mã: {decrypted}")
