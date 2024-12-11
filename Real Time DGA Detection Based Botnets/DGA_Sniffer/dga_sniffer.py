import scapy.all as scapy
from collections import Counter
import joblib
from scipy.sparse import csr_matrix
from flask import Flask, jsonify, render_template
import threading

# Load your pre-trained model and necessary files
logreg_model = joblib.load(r'C:\Users\Tushar\Desktop\DGA\dgaa\UTL_DGA22-Dataset-main/logreg_model.pkl')
idf = joblib.load(r'C:\Users\Tushar\Desktop\DGA\dgaa\UTL_DGA22-Dataset-main/idf.pkl')
ngram_index = joblib.load(r'C:\Users\Tushar\Desktop\DGA\dgaa\UTL_DGA22-Dataset-main/ngram_index.pkl')

# Store DGA domain logs
dga_domains = []

# Helper functions (same as before)
def extract_ngrams(domain, ngram_range=(2, 5)):
    ngrams = []
    min_n, max_n = ngram_range
    for n in range(min_n, max_n + 1):
        ngrams.extend([domain[i:i + n] for i in range(len(domain) - n + 1)])
    return ngrams

def calculate_tf(ngrams):
    tf = Counter(ngrams)
    max_freq = max(tf.values()) if tf else 1
    for ngram in tf:
        tf[ngram] /= max_freq
    return tf

def classify_domain(domain_name):
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
    if packet.haslayer(scapy.DNS) and packet[scapy.DNS].qr == 0:  # QR == 0 means it's a query
        dns_query = packet[scapy.DNS].qd.qname.decode('utf-8')
        domain = dns_query[:-1]  # Remove the trailing dot

        # Classify the domain using the model
        prediction = classify_domain(domain)

        # If DGA detected, log it
        if prediction == "DGA":
            dga_domains.append(domain)

# Function to start sniffing network traffic
def start_sniffing():
    scapy.sniff(filter="udp port 53", prn=process_dns_packet, store=0)  # Filter for DNS (UDP port 53)

# Flask App to display the results
app = Flask(__name__)

@app.route('/')
def home():
    return render_template('index.html', dga_domains=dga_domains)

@app.route('/get_domains')
def get_domains():
    return jsonify({'dga_domains': dga_domains})

if __name__ == "__main__":
    # Start sniffing in a separate thread
    sniff_thread = threading.Thread(target=start_sniffing)
    sniff_thread.daemon = True
    sniff_thread.start()

    # Start Flask app
    app.run(host='0.0.0.0', port=5000, debug=True)
