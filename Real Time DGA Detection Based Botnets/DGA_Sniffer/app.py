from flask import Flask, jsonify,render_template
import threading
import time
import scapy.all as scapy
from scapy.all import sniff, DNS, DNSQR
import joblib
from scipy.sparse import csr_matrix
from collections import Counter
from flask_cors import CORS


app = Flask(__name__)
CORS(app)

# Load your pre-trained model and necessary files
logreg_model = joblib.load(r'C:\Users\Tushar\Desktop\DGA\dgaa\UTL_DGA22-Dataset-main/logreg_model.pkl')
idf = joblib.load(r'C:\Users\Tushar\Desktop\DGA\dgaa\UTL_DGA22-Dataset-main/idf.pkl')
ngram_index = joblib.load(r'C:\Users\Tushar\Desktop\DGA\dgaa\UTL_DGA22-Dataset-main/ngram_index.pkl')

# Store logs in a global list
current_logs = []

# Helper functions
def extract_ngrams(domain, ngram_range=(2, 5)):
    """Extracts n-grams from a domain name"""
    ngrams = []
    min_n, max_n = ngram_range
    for n in range(min_n, max_n + 1):
        ngrams.extend([domain[i:i + n] for i in range(len(domain) - n + 1)])
    return ngrams

def calculate_tf(ngrams):
    """Calculate Term Frequency for the extracted n-grams"""
    tf = Counter(ngrams)
    max_freq = max(tf.values()) if tf else 1
    for ngram in tf:
        tf[ngram] /= max_freq
    return tf

def classify_domain(domain_name):
    """Classifies the domain using TF-IDF and the pre-trained model"""
    ngrams = extract_ngrams(domain_name)
    tf = calculate_tf(ngrams)
    tfidf = {term: tf[term] * idf.get(term, 0) for term in tf}
    rows, cols, values = [], [], []
    for term, value in tfidf.items():
        if term in ngram_index:
            col_idx = ngram_index[term]
            rows.append(0)
            cols.append(col_idx)
            values.append(value)
    tfidf_sparse_vector = csr_matrix((values, (rows, cols)), shape=(1, len(ngram_index)))
    prediction = logreg_model.predict(tfidf_sparse_vector)
    return "DGA" if prediction[0] == 1 else "Legit"

def process_dns_packet(packet):
    """Process DNS packets and classify the domain"""
    if packet.haslayer(scapy.DNS) and packet[scapy.DNS].qr == 0:  # QR == 0 means it's a query
        dns_query = packet[scapy.DNS].qd.qname.decode('utf-8')
        domain = dns_query[:-1]  # Remove the trailing dot
        print(f"Captured DNS Query: {domain}")
        
        # Classify the domain using the model
        prediction = classify_domain(domain)
        print(f"Prediction for {domain}: {prediction}")
        
        # Log to the current_logs
        log_entry = f"Captured DNS Query: {domain}, Prediction: {prediction}"
        current_logs.append(log_entry)
        
        # Limit logs to the most recent 50 entries
        if len(current_logs) > 50:
            current_logs.pop(0)
        
        # If DGA detected, you can log or take action
        if prediction == "DGA":
            print(f"Alert! DGA detected for domain: {domain}")

# Function to start sniffing network traffic
def start_sniffing():
    print("Starting to sniff DNS traffic...")
    scapy.sniff(filter="udp port 53", prn=process_dns_packet, store=0)  # Filter for DNS (UDP port 53)

@app.route('/')
def index():
    """Render the homepage"""
    return render_template('index.html') 

@app.route('/get_logs', methods=['GET'])
def get_logs():
    """Serve the logs to the frontend"""
    print("Serving logs: ", current_logs)
    return jsonify({"logs": current_logs})

# Start sniffing in a separate thread so Flask doesn't block
def start_sniffer_thread():
    sniffing_thread = threading.Thread(target=start_sniffing)
    sniffing_thread.daemon = True
    sniffing_thread.start()

if __name__ == '__main__':
    # Start sniffing the network in a background thread
    start_sniffer_thread()
    
    # Run the Flask app
    app.run(debug=True)
