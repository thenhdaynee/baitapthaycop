# 🔒 Báo Cáo Môn An Toàn và Bảo Mật Thông Tin

Báo cáo nghiên cứu về các thuật toán mã hóa **DES**, **AES**, thuật toán mã hóa bất đối xứng **RSA** và mô hình kết hợp **Hybrid Encryption**.

---

## 📑 Mục Lục

1. [Thuật Toán Mã Hóa Hiện Đại (DES & AES)](#1-thuật-toán-mã-hóa-hiện-đại-des--aes)
   - [Thuật toán DES](#11-thuật-toán-des-data-encryption-standard)
   - [Thuật toán AES](#12-thuật-toán-aes-advanced-encryption-standard)
   - [Cài đặt AES-128 bằng Python](#13-cài-đặt-aes-128-chế-độ-cbc-bằng-python)
2. [Thuật Toán Mã Hóa Bất Đối Xứng RSA](#2-thuật-toán-mã-hóa-bất-đối-xứng-rsa)
   - [Nguyên lý sinh cặp khóa RSA](#22-nguyên-lý-sinh-cặp-khóa-rsa)
3. [Mô Hình Bảo Mật RSA & Mã Hóa Hỗn Hợp](#3-mô-hình-bảo-mật-rsa--mã-hóa-hỗn-hợp)
   - [Các mô hình áp dụng RSA](#31-các-mô-hình-áp-dụng-rsa)
   - [So sánh RSA và AES](#34-so-sánh-thời-gian-rsa-và-aes)
   - [Mô hình kết hợp Hybrid Encryption](#35-kết-hợp-rsa-và-aes)

---

## 1. Thuật Toán Mã Hóa Hiện Đại (DES & AES)

Mã hóa đối xứng (*Symmetric Encryption*) sử dụng cùng một khóa bí mật (*Secret Key*) cho cả quá trình mã hóa và giải mã.

### 1.1. Thuật toán DES (Data Encryption Standard)

DES là thuật toán mã hóa khối (*Block Cipher*) dựa trên cấu trúc Feistel, từng được sử dụng rộng rãi làm tiêu chuẩn mã hóa.

- **Kích thước khối:** 64-bit.
- **Độ dài khóa:** 64-bit, trong đó 8-bit dùng cho parity nên độ dài khóa thực tế là **56-bit**.
- **Số vòng:** 16 vòng.

#### Quy trình mã hóa / giải mã

1. **Hoán vị ban đầu (IP):** Khối 64-bit được đưa qua bảng hoán vị.
2. **Phân chia:** Chia thành hai nửa `L0` và `R0`, mỗi nửa 32-bit.
3. **16 vòng Feistel:**
   - Sinh 16 khóa con `K1, K2, ..., K16`.
   - Công thức:
   
```text
Li = R(i-1)
Ri = L(i-1) XOR f(R(i-1), Ki)
```

   - Hàm `f` gồm các bước mở rộng, XOR với khóa con, qua S-Box và hoán vị.
4. **Hoán vị cuối:** Áp dụng hoán vị nghịch đảo `IP⁻¹` để tạo bản mã.
5. **Giải mã:** Thực hiện tương tự nhưng sử dụng các khóa con theo thứ tự ngược lại.

> DES hiện nay không còn được xem là an toàn do khóa 56-bit quá ngắn.

---

### 1.2. Thuật toán AES (Advanced Encryption Standard)

AES là thuật toán mã hóa đối xứng được NIST lựa chọn để thay thế DES. AES sử dụng cấu trúc mạng thế - hoán vị (*Substitution-Permutation Network*).

- **Kích thước khối:** 128-bit.
- **AES-128:** Khóa 128-bit, 10 vòng.
- **AES-192:** Khóa 192-bit, 12 vòng.
- **AES-256:** Khóa 256-bit, 14 vòng.

#### Các bước chính của AES

```text
Input Block (128-bit)
        |
        v
   AddRoundKey
        |
        v
+-----------------------+
| SubBytes              |
| ShiftRows              |
| MixColumns             |
| AddRoundKey            |
+-----------------------+
        |
        | Lặp N-1 vòng
        v
+-----------------------+
| SubBytes              |
| ShiftRows              |
| AddRoundKey            |
+-----------------------+
        |
        v
Ciphertext (128-bit)
```

Ở vòng cuối, AES bỏ qua bước `MixColumns`.

---

### 1.3. Cài đặt AES-128 (Chế độ CBC) bằng Python

```python
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend


def generate_key_and_iv():
    # Khóa AES-128 (16 bytes) và IV (16 bytes)
    key = os.urandom(16)
    iv = os.urandom(16)
    return key, iv


def encrypt_aes_cbc(plaintext: str, key: bytes, iv: bytes) -> bytes:
    # Padding dữ liệu bằng PKCS7
    padder = padding.PKCS7(128).padder()
    padded_data = (
        padder.update(plaintext.encode("utf-8"))
        + padder.finalize()
    )

    # Mã hóa AES-CBC
    cipher = Cipher(
        algorithms.AES(key),
        modes.CBC(iv),
        backend=default_backend()
    )

    encryptor = cipher.encryptor()

    return (
        encryptor.update(padded_data)
        + encryptor.finalize()
    )


def decrypt_aes_cbc(ciphertext: bytes, key: bytes, iv: bytes) -> str:
    # Giải mã AES-CBC
    cipher = Cipher(
        algorithms.AES(key),
        modes.CBC(iv),
        backend=default_backend()
    )

    decryptor = cipher.decryptor()

    padded_data = (
        decryptor.update(ciphertext)
        + decryptor.finalize()
    )

    # Unpadding dữ liệu
    unpadder = padding.PKCS7(128).unpadder()

    data = (
        unpadder.update(padded_data)
        + unpadder.finalize()
    )

    return data.decode("utf-8")


if __name__ == "__main__":
    message = "Thong tin bao mat mon An toan thong tin!"

    key, iv = generate_key_and_iv()

    print(f"Văn bản gốc: {message}")

    encrypted = encrypt_aes_cbc(message, key, iv)

    print(f"Bản mã (Hex): {encrypted.hex()}")

    decrypted = decrypt_aes_cbc(encrypted, key, iv)

    print(f"Văn bản giải mã: {decrypted}")
```

> **Lưu ý:** AES-CBC chỉ cung cấp tính bí mật, không tự cung cấp cơ chế xác thực và kiểm tra toàn vẹn. Trong các hệ thống thực tế có thể sử dụng AES-GCM để kết hợp mã hóa và xác thực.

---

## 2. Thuật Toán Mã Hóa Bất Đối Xứng RSA

### 2.1. RSA là gì?

RSA (*Rivest–Shamir–Adleman*) là thuật toán mã hóa bất đối xứng, sử dụng một cặp khóa:

- **Public Key (khóa công khai):** có thể chia sẻ cho mọi người.
- **Private Key (khóa bí mật):** phải được giữ bí mật.

RSA có thể được sử dụng cho:

- Mã hóa dữ liệu hoặc bảo vệ khóa.
- Chữ ký số.
- Xác thực nguồn gốc dữ liệu.

---

### 2.2. Nguyên lý sinh cặp khóa RSA

Các bước sinh khóa:

1. Chọn hai số nguyên tố lớn `p` và `q`.

2. Tính:

```text
n = p × q
```

3. Tính hàm phi Euler:

```text
φ(n) = (p - 1)(q - 1)
```

4. Chọn số `e` sao cho:

```text
1 < e < φ(n)

gcd(e, φ(n)) = 1
```

5. Tìm `d` sao cho:

```text
d × e ≡ 1 (mod φ(n))
```

6. Tạo cặp khóa:

```text
Public Key  = (e, n)
Private Key = (d, n)
```

### Ví dụ

Chọn:

```text
p = 61
q = 53
```

Ta có:

```text
n = 61 × 53
  = 3233
```

Tính:

```text
φ(n) = (61 - 1)(53 - 1)
     = 60 × 52
     = 3120
```

Chọn:

```text
e = 17
```

Tính được:

```text
d = 2753
```

Vậy:

```text
Public Key  = (17, 3233)
Private Key = (2753, 3233)
```

---

### 2.3. Mã hóa và giải mã RSA

#### Mã hóa

Sử dụng Public Key:

```text
C = M^e mod n
```

Trong đó:

- `M`: dữ liệu ban đầu.
- `C`: dữ liệu đã mã hóa.

#### Giải mã

Sử dụng Private Key:

```text
M = C^d mod n
```

Sơ đồ:

```text
Message
   |
   | Public Key
   v
Ciphertext
   |
   | Private Key
   v
Message
```

---

## 3. Mô Hình Bảo Mật RSA & Mã Hóa Hỗn Hợp

### 3.1. Các mô hình áp dụng RSA

#### a. Xác thực người gửi

RSA có thể được sử dụng để tạo **chữ ký số**.

Người gửi sử dụng Private Key để tạo chữ ký trên giá trị băm của dữ liệu:

```text
Message
   |
   v
Hash
   |
   | Private Key người gửi
   v
Digital Signature
```

Người nhận sử dụng Public Key của người gửi để kiểm tra chữ ký.

Mô hình này giúp:

- Xác thực nguồn gốc dữ liệu.
- Kiểm tra dữ liệu có bị thay đổi hay không.
- Hỗ trợ chống phủ nhận trong hệ thống chữ ký số.

> Chữ ký số không nhằm mục đích giữ bí mật nội dung dữ liệu.

---

#### b. Bảo mật dữ liệu cho người nhận

Nếu muốn chỉ người nhận có thể đọc dữ liệu, người gửi sử dụng **Public Key của người nhận** để mã hóa.

```text
Message
   |
   | Public Key người nhận
   v
Ciphertext
   |
   | Private Key người nhận
   v
Message
```

Mô hình này bảo vệ tính bí mật của dữ liệu.

> Việc mã hóa bằng Public Key của người nhận không tự động xác thực danh tính người gửi.

---

#### c. Xác thực người gửi và bảo mật cho người nhận

Có thể kết hợp **chữ ký số** và **mã hóa**:

```text
                Message
                   |
          +--------+--------+
          |                 |
          v                 v
        Hash            Encryption
          |                 |
          | Private Key     | Public Key
          v                 | người nhận
   Digital Signature        |
          |                 |
          +--------+--------+
                   |
                   v
              Dữ liệu gửi
```

Người nhận:

```text
Dữ liệu gửi
     |
     v
Decrypt bằng Private Key
     |
     v
Message + Digital Signature
     |
     v
Verify bằng Public Key người gửi
```

Mô hình này cung cấp:

- **Bảo mật:** chỉ người nhận có Private Key phù hợp mới giải mã được.
- **Xác thực người gửi:** kiểm tra chữ ký bằng Public Key của người gửi.
- **Toàn vẹn dữ liệu:** sử dụng hàm băm kết hợp với chữ ký số.

---

### 3.2. So sánh thời gian RSA và AES

| Đặc điểm | RSA | AES |
|---|---|---|
| Loại | Bất đối xứng | Đối xứng |
| Số khóa | Public Key + Private Key | Một khóa bí mật |
| Tốc độ | Chậm hơn | Nhanh hơn |
| Dữ liệu lớn | Không phù hợp | Phù hợp |
| Bảo vệ/trao đổi khóa | Phù hợp | Cần cơ chế phân phối khóa |
| Chữ ký số | Có thể sử dụng | Không |
| Chi phí tính toán | Cao hơn | Thấp hơn |

**Kết luận:** AES có tốc độ mã hóa và giải mã dữ liệu lớn nhanh hơn rất nhiều so với RSA. RSA phù hợp hơn với chữ ký số và bảo vệ/trao đổi khóa.

---

### 3.3. Kết hợp RSA và AES - Hybrid Encryption

Do RSA chậm và không phù hợp để mã hóa trực tiếp file lớn, có thể kết hợp RSA với AES theo mô hình **Hybrid Encryption**.

#### Quá trình mã hóa

1. Sinh một khóa AES ngẫu nhiên.
2. Dùng AES để mã hóa dữ liệu.
3. Dùng Public Key RSA của người nhận để mã hóa khóa AES.
4. Gửi cho người nhận:

```text
Encrypted Data
+
Encrypted AES Key
```

#### Quá trình giải mã

1. Người nhận dùng Private Key RSA để giải mã khóa AES.
2. Sử dụng khóa AES để giải mã dữ liệu.

Sơ đồ:

```text
                 RSA
                  |
                  | Bảo vệ AES Key
                  v
               AES Key
                  |
                  | Mã hóa dữ liệu lớn
                  v
            Encrypted Data
```

### Ưu điểm

- **RSA:** bảo vệ/trao đổi khóa AES và hỗ trợ chữ ký số.
- **AES:** mã hóa dữ liệu lớn nhanh và hiệu quả.

Vì vậy, mô hình Hybrid Encryption tận dụng được ưu điểm của cả mã hóa bất đối xứng và mã hóa đối xứng.

---

# Kết Luận

RSA sử dụng cặp **Public Key và Private Key**, phù hợp cho bảo vệ khóa, chữ ký số và các cơ chế xác thực.

AES sử dụng một **Secret Key**, có tốc độ cao và phù hợp để mã hóa dữ liệu lớn.

Mô hình kết hợp thường được sử dụng:

```text
RSA
 ↓
Bảo vệ khóa AES
 ↓
AES
 ↓
Mã hóa dữ liệu lớn
```

Nếu kết hợp thêm chữ ký số:

```text
RSA Digital Signature
          +
     RSA bảo vệ AES Key
          +
         AES
          ↓
Bảo mật + Xác thực + Toàn vẹn dữ liệu
```
