---

# **Network Traffic Analyzer**  

A web-based **Network Traffic Analyzer** that processes **PCAP** files to extract valuable network information such as **HTTP communication, DNS queries, FTP sessions, SSL/TLS connections, open ports, SMB announcements, and WiFi information**.  

## **Features**  
✅ User authentication (Login & Register)  
✅ Upload and analyze **PCAP** files  
✅ Extract and display:  
   - HTTP communication  
   - DNS queries  
   - FTP & SSL/TLS sessions  
   - Open ports & network mapping  
   - SIP communication & SMB announcements  
   - WiFi network data  
✅ Interactive network map visualization  

## **Installation & Setup**  

### **1. Clone the repository**  
```bash
git clone https://github.com/your-username/network-traffic-analyzer.git
cd network-traffic-analyzer
```

### **2. Install dependencies**  
Ensure you have Python installed. Install required libraries:  
```bash
pip install flask scapy mysql-connector-python
```

### **3. Set up MySQL database**  
- Create a database **`net_probe`**  
- Run the following SQL script:  
```sql
CREATE TABLE user (
    u_id INT AUTO_INCREMENT PRIMARY KEY,
    uname VARCHAR(100),
    uemail VARCHAR(100) UNIQUE,
    upassword VARCHAR(255)
);
```
- Update **`db_config`** in `app.py` with your MySQL credentials.  

### **4. Run the Flask App**  
```bash
python app.py
```
It will start the server at `http://127.0.0.1:5000/`  

### **5. Access Web Interface**  
- Visit `http://127.0.0.1:5000/`  
- Register/Login  
- Upload **PCAP** files for analysis  

## **License**  
This project is open-source under the **MIT License**.  

---
