import os
import pickle
import time
from datetime import datetime, timedelta

import scapy.all as scapy
from flask import Flask, render_template, request,session
from scapy.all import rdpcap, IP, TCP, DNS, Dot11
from scapy.packet import Raw

import mysql.connector
from hashlib import sha256


app = Flask(__name__)
app.secret_key = 'zambdbdb'

db_config = {
    'host': 'localhost',
    'user': 'root',           # Replace with your MySQL username
    'password': '',       # Replace with your MySQL password
    'database': 'net_probe',        # Replace with your MySQL database name
}


def get_db_connection():
    return mysql.connector.connect(**db_config)

# Function to hash password
def hash_password(password):
    return sha256(password.encode()).hexdigest()



ALLOWED_EXTENSIONS = {'pcap', 'pcapng'}
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


# Define functions to extract data for each category

def extract_credentials(packets):
    credentials = []
    for packet in packets:
        if packet.haslayer(Raw) and b'User-Agent' in packet[Raw].load and b'Password' in packet[Raw].load:
            user_agent, password = packet[Raw].load.split(b':', 1)
            credentials.append((user_agent.decode(), password.decode()))
    return credentials

def extract_dns_queries(packets):
    dns_queries = []
    for packet in packets:
        if DNS in packet and packet[DNS].qd:
            dns_queries.append(packet[DNS].qd.qname.decode())
    return dns_queries

def extract_http_communication(packets):
    http_communication = []
    for packet in packets:
        if packet.haslayer(Raw) and b'HTTP' in packet[Raw].load:
            http_communication.append(packet[Raw].load.decode('utf-8', errors='ignore'))
    return http_communication

# Implement functions for other categories

def extract_ftp_sessions(packets):
    ftp_sessions = []
    for packet in packets:
        if TCP in packet and packet[TCP].dport == 21:
            ftp_sessions.append(packet[TCP])
    return ftp_sessions

def extract_ssl_tls_sessions(packets):
    ssl_tls_sessions = []
    for packet in packets:
        if packet.haslayer(TCP) and packet[TCP].dport == 443:
            ssl_tls_sessions.append(packet[TCP])
    return ssl_tls_sessions

def extract_smb_announcements(packets):
    smb_announcements = []
    for packet in packets:
        if packet.haslayer(Raw) and b'SMB' in packet[Raw].load:
            smb_announcements.append(packet[Raw].load.decode('utf-8', errors='ignore'))
    return smb_announcements

def extract_network_map(packets):
    network_map = {}
    for packet in packets:
        if IP in packet:
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            if src_ip not in network_map:
                network_map[src_ip] = []
            if dst_ip not in network_map:
                network_map[dst_ip] = []
            network_map[src_ip].append(dst_ip)
            network_map[dst_ip].append(src_ip)
    return network_map

def extract_open_ports(packets):
    open_ports = []
    for packet in packets:
        if TCP in packet and packet[TCP].flags == 0x12:
            open_ports.append(packet[TCP].sport)
    return open_ports

def extract_sip_communications(packets):
    sip_communications = []
    for packet in packets:
        if packet.haslayer(Raw) and b'SIP' in packet[Raw].load:
            sip_communications.append(packet[Raw].load.decode('utf-8', errors='ignore'))
    return sip_communications

def extract_documents(packets):
    documents = []
    for packet in packets:
        if packet.haslayer(Raw) and b'PDF' in packet[Raw].load:
            documents.append(packet[Raw].load)
    return documents

def extract_wifi_information(packets):
    wifi_information = []
    for packet in packets:
        if packet.haslayer(Dot11):
            wifi_information.append(packet[Dot11])
    return wifi_information

# Analyze pcap function
def analyze_pcap(packets):
    credentials = extract_credentials(packets)
    dns_queries = extract_dns_queries(packets)
    http_communication = extract_http_communication(packets)
    ftp_sessions = extract_ftp_sessions(packets)
    ssl_tls_sessions = extract_ssl_tls_sessions(packets)
    smb_announcements = extract_smb_announcements(packets)
    network_map = extract_network_map(packets)
    open_ports = extract_open_ports(packets)
    sip_communications = extract_sip_communications(packets)
    documents = extract_documents(packets)
    wifi_information = extract_wifi_information(packets)
    
    formatted_credentials = [(user_agent, password) for user_agent, password in credentials]
    formatted_http_communication = [communication.strip() for communication in http_communication]
    formatted_smb_announcements = [announcement.strip() for announcement in smb_announcements]
    formatted_documents = ["PDF Document" for document in documents]  # Just an example, you can improve this
    
    return (formatted_credentials, dns_queries, formatted_http_communication, ftp_sessions, ssl_tls_sessions,
            formatted_smb_announcements, network_map, open_ports, sip_communications, formatted_documents,
            wifi_information)



# Flask app
# Flask app



@app.route("/login", methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        # Check user credentials
        connection = get_db_connection()
        cursor = connection.cursor(dictionary=True)
        query = "SELECT * FROM user WHERE uemail = %s AND upassword = %s"
        hashed_password = hash_password(password)
        cursor.execute(query, (email, hashed_password))
        user = cursor.fetchone()
        connection.close()

        if user:
            session['user_id'] = user['u_id']  # Store user ID in session
             # Store user role in session
            
            return render_template('index.html', response="Successfull Login") # Redirect to dashboard based on role

        return render_template('login.html', response="Invalid email or password. Please try again.")

    return render_template('login.html')

@app.route("/register", methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['name']
        email = request.form['email']
        password = request.form['password']

        # Create a new user
        connection = get_db_connection()
        cursor = connection.cursor()
        query = "SELECT * FROM user WHERE uemail = %s"
        cursor.execute(query, (email,))
        existing_user = cursor.fetchone()
        if existing_user:
            connection.close()
            return render_template('register.html',response="Email address already exists. Please choose a different one.")
            

        # Encrypt password
        hashed_password = hash_password(password)
        query = "INSERT INTO user (uname, uemail, upassword) VALUES (%s, %s, %s)"
        cursor.execute(query, (username, email, hashed_password))
        connection.commit()
        
        connection.close()
        

        return render_template('login.html',response="registration Successfull")  # Redirect to login page after successful registration

    return render_template('register.html')


@app.route("/logout")
def logout():
    # Clear user-related data from session
    
    session.pop('user_id', None)
    
    return render_template('login.html',response='logout succesfull')



@app.route("/", methods=["GET"])
def index():
    return render_template("index.html")

@app.route("/about", methods=["GET"])
def about():
    return render_template("about.html")

@app.route("/contact", methods=["GET"])
def contact():
    return render_template("contact.html")


@app.route("/analyze", methods=["POST"])
def analyze():
    pcap_file = request.files["pcap-file"]
    if not pcap_file:
        return render_template("index.html",response="No file provided")
    if pcap_file.filename == '':
        return render_template("index.html", response="No selected file")
    
    if not allowed_file(pcap_file.filename):
        return render_template("index.html", response="Invalid file type. Please upload a pcap file.")

    packets = rdpcap(pcap_file)
    (credentials, dns_queries, http_communication, ftp_sessions, ssl_tls_sessions,
     smb_announcements, network_map, open_ports, sip_communications, documents,
     wifi_information) = analyze_pcap(packets)
    
    global http_communication_data
    http_communication_data = http_communication
    
    global dns_queries_data
    dns_queries_data = dns_queries
    
    global ssl_tls_sessions_data
    ssl_tls_sessions_data = ssl_tls_sessions
    
    global open_ports_data
    open_ports_data = open_ports
    
    global network_map_data
    network_map_data = network_map

    # Print data in the terminal
    print("Credentials:", credentials)
    print("DNS Queries:", dns_queries)
    print("HTTP Communication:", http_communication)
    print("FTP Sessions:", ftp_sessions)
    print("SSL/TLS Sessions:", ssl_tls_sessions)
    print("SMB Announcements:", smb_announcements)
    print("Network Map:", network_map)
    print("Open Ports:", open_ports)
    print("SIP Communications:", sip_communications)
    print("Documents:", documents)
    print("WiFi Information:", wifi_information)

    # Render the data in result.html
    return render_template(
        "result.html",
        credentials=credentials,
        dns_queries=dns_queries,
        http_communication=http_communication,
        ftp_sessions=ftp_sessions,
        ssl_tls_sessions=ssl_tls_sessions,
        smb_announcements=smb_announcements,
        network_map=network_map,
        open_ports=open_ports,
        sip_communications=sip_communications,
        documents=documents,
        wifi_information=wifi_information
    )
    
@app.route("/network_map", methods=["GET"])
def network_map():
    return render_template("network_map.html",network_map=network_map_data)  
  
@app.route("/open_ports", methods=["GET"])
def open_ports():
    return render_template("open_ports.html",open_ports=open_ports_data)  
    
@app.route("/dns_query", methods=["GET"])
def dns_query():
    return render_template("dns_query.html",dns_queries=dns_queries_data)

# Flask route to render SSL/TLS session data in the browser
@app.route("/ssl_tls_sessions", methods=["GET"])
def ssl_tls_sessions():
    # Assuming ssl_tls_sessions_data contains the list of SSL/TLS packet objects
    
    # Create an empty list to store parsed SSL/TLS session data
    parsed_ssl_tls_sessions = []
    
    # Iterate through each TCP packet in ssl_tls_sessions_data
    for packet in ssl_tls_sessions_data:
        if hasattr(packet, 'load'):
            payload_length = len(packet.load)
        else:
            payload_length = 0

        packet_info = {
        "Source Port": packet.sport,
        "Destination Port": packet.dport,
        "Sequence Number": packet.seq,
        "Acknowledgment Number": packet.ack,
        "Flags": packet.sprintf("%flags%"),
        "Payload Length": payload_length
        # Add more fields as needed
        }

        parsed_ssl_tls_sessions.append(packet_info)

    
    # Pass the parsed SSL/TLS session data to the HTML template
    return render_template("ssl_tls_sessions.html", ssl_tls_sessions=parsed_ssl_tls_sessions)


@app.route("/http_communication", methods=["GET"])
def http_communication():
    # Assuming http_communication_data contains the list of HTTP request strings
  

    user_agents = []
    protocols = []

    for request in http_communication_data:
        # Split the request by lines
        lines = request.split('\r\n')
        user_agent = None
        protocol = None

        # Iterate through each line to find User-Agent and Protocol
        for line in lines:
            if line.startswith('USER-AGENT:'):
                user_agent = line.split(':', 1)[1].strip()
                break  # Exit loop once user agent is found

        # Extract protocol from "M-SEARCH" line
        if 'M-SEARCH' in lines[0]:
            protocol = lines[0].split()[2]

        # Append User-Agent and Protocol to their respective lists
        user_agents.append(user_agent)
        protocols.append(protocol)

    # Pass the HTTP communication and extracted data to your HTML template
    return render_template('http_communication.html', http_communication=http_communication_data, user_agent_analyzation=user_agents, protocol_analyzation=protocols)


   

    
    





if __name__ == "__main__":
    app.run(debug=True)

