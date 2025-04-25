# ByteFlow-FTP - Secure File Transfer System

## Project Description
**ByteFlow-FTP** is a high-performance, secure FTP server developed in C, enabling seamless file exchange across networks. Designed as a 5th semester Operating Systems project at FAST NUCES, the system integrates key OS concepts such as multiprocessing, multithreading, synchronization, concurrency, and memory management to ensure efficient and secure data transfer.
This hybrid-architecture FTP server utilizes process isolation for authentication, thread pools for client handling, and inter-process communication mechanisms to achieve both performance and scalability. Featuring TLS/SSL encryption, SQLite-backed user authentication, and a custom protocol for file operations, ByteFlow-FTP offers robust multi-user support with real-time administrative controls and secure, optimized connection management.

## Team Members
- **Aisha Asif** (23K-0915) - Team Lead, Security Implementation  
- **Nabira Khan** (23K-0914) - Database & Authentication Specialist  
- **Rameen Zehra** (23K-0501) - Network Protocols & Threading Expert

### Key Features
- 🔒 Secure TLS/SSL-encrypted communication  
- 👥 Multi-user support with role-based permissions  
- 🧵 Threaded server architecture for concurrent sessions  
- 🗂 Comprehensive file operations (upload/download, directory management)  
- 🗃 SQLite-based backend for user authentication  
- 🔐 Process isolation for secure credential handling  

---

## Features

### ✅ Core Functionality
- Encrypted file transfers via TLS/SSL  
- Secure login system using SQLite  
- Multiple clients served concurrently using thread pool  
- File operations: upload, download, mkdir, rmdir, cd, ls, pwd  
- Custom protocol for client-server communication  

### 🛠 Admin Features
- Add/delete users  
- View list of all system users  
- Access privileged admin-only commands  

---

## Technical Highlights
- 🔐 SSL/TLS via OpenSSL  
- 🔄 Fork-based authentication process isolation  
- 🔧 POSIX Threads with thread pool and shared task queue  
- 🔁 Read-write locks for concurrent file reads  
- 🚦 Binary semaphores for upload synchronization  
- 💾 SQLite database for credentials and user metadata  
- 📡 Custom command-response protocol  

---

## Installation

### 📦 Prerequisites
- OpenSSL development libraries  
- SQLite3  
- POSIX Threads (`pthread`)  
- GCC and Make  

### 🛠 Build Instructions
```bash
# Compile the server
gcc server.c -o ftp_server -lssl -lcrypto -lsqlite3 -lpthread

# Compile the client
gcc client.c -o ftp_client -lssl -lcrypto -lpthread

# Optional: Generate self-signed certificates
openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365

