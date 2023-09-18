import requests
from sklearn.ensemble import IsolationForest

# Function to perform anomaly detection on web responses
def detect_anomalies(url, payloads):
    responses = []
    
    # Send requests with different payloads and collect responses
    for payload in payloads:
        response = requests.get(url + payload)
        responses.append(response.text)
    
    # Train an Isolation Forest model on response lengths
    response_lengths = [len(resp) for resp in responses]
    model = IsolationForest(contamination=0.05)  # Adjust contamination as needed
    model.fit([[length] for length in response_lengths])
    
    # Predict anomalies based on response lengths
    anomalies = model.predict([[length] for length in response_lengths])
    
    # Analyze responses for anomalies
    for i, anomaly in enumerate(anomalies):
        if anomaly == -1:
            print(f"Anomaly detected in response for payload {payloads[i]}")
        else:
            print(f"No anomaly detected in response for payload {payloads[i]}")

# Main function to perform vulnerability scan
def vulnerability_scan():
    target_url = input("Enter the URL to scan: ")
    print("Scanning", target_url, "for anomalies...")
    
    # Define payloads for testing
    payloads = [
        "<script>alert('XSS')</script>",
        "1' OR '1'='1",
        # Add more payloads for testing other vulnerabilities if needed
    ]
    
    detect_anomalies(target_url, payloads)
    print("Scan complete.")

# Usage example
vulnerability_scan()
