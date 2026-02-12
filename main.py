import os
import sqlite3
document = 'Module_structure'
mainfile = 'main.py'
testfile = 'access.log'
if not os.path.exists(document):
    os.mkdir(document)
base_file=os.path.join(document, mainfile)
log_file=os.path.join(document, testfile)

logs_data = """192.168.1.1 - - [11/Feb/2026:10:00:01] "GET /home HTTP/1.1" 200
192.168.1.5 - - [11/Feb/2026:10:00:05] "POST /login HTTP/1.1" 403
192.168.1.1 - - [11/Feb/2026:10:00:10] "GET /about HTTP/1.1" 200
10.0.0.15 - - [11/Feb/2026:10:00:15] "GET /admin HTTP/1.1" 404
192.168.1.5 - - [11/Feb/2026:10:00:20] "POST /login HTTP/1.1" 403
192.168.1.5 - - [11/Feb/2026:10:00:25] "POST /login HTTP/1.1" 403"""
with open(log_file, 'w') as x:
    x.write(logs_data)
print(f'System is ready. {log_file} is created')

def log_analysis(file_shortcut):
    IP_collector = {}
    with open(file_shortcut, 'r') as file:
        for line in file:
            chunks = line.split()
            if chunks:
                ip=chunks[0]
                if ip in IP_collector:
                    IP_collector[ip]+=1
                else:
                    IP_collector[ip]=1
    return IP_collector

results = log_analysis(log_file)

print("\n" + "="*30)
print("GENERAL IP STATİSTiCS")
print("="*30)

for ip, number in results.items():
    print(f"device: {ip} | Inquiry attempts: {number}")

report_file = os.path.join(document, "security_report.txt")

def generate_report(source_file, output_file):
    with open(source_file, 'r') as infile, open(output_file, 'w') as outfile:
        outfile.write("SECURITY REPORT - SUSPICIOUS ENTRIES \n")
        outfile.write("="*40 + "\n")
        
        found_threat = False
        for line in infile:
            chunks = line.split()
            if chunks and chunks[-1] == "403": 
                outfile.write(f"Şübhəli Cəhd: {line}")
                found_threat = True
        
        if not found_threat:
            outfile.write("NOTHING SUSPICIOUS FOUND.\n")

generate_report(log_file, report_file)
print(f"\n[!] REPORT HAS BEEN CREATED: {report_file}")


db_path = os.path.join(document, "logs_archive.db")

def save_to_database(db_name, data_dict):
    conn = sqlite3.connect(db_name)
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS ip_stats (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip_address TEXT,
            request_count INTEGER
        )
    """)
    cursor.execute("DELETE FROM ip_stats")
    
    
    for ip, count in data_dict.items():
        cursor.execute("INSERT INTO ip_stats (ip_address, request_count) VALUES (?, ?)", (ip, count))
    
    conn.commit()
    conn.close()

def get_suspicious_from_db(db_name):
    conn = sqlite3.connect(db_name)
    cursor = conn.cursor()
    cursor.execute("SELECT ip_address, request_count FROM ip_stats WHERE request_count >= 2")
    rows = cursor.fetchall()
    
    conn.close()
    return rows

save_to_database(db_path, results)
print(f"[!] Data archieved to SQLite base: {db_path}")

alerts = get_suspicious_from_db(db_path)
if alerts:
    print("\n Danger information comeing from base:")
    for row in alerts:
        print(f"Attention: {row[0]} adress {row[1]} times asked for inquery!")
