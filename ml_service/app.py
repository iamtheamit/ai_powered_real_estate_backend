# ml_service/app.py
from flask import Flask, request, jsonify
import joblib
import numpy as np

app = Flask(__name__)

# Load the trained model, scaler, and label encoder
model = joblib.load('lead_score_model.joblib')
scaler = joblib.load('scaler.joblib')
location_encoder = joblib.load('location_encoder.joblib')

@app.route('/predict', methods=['POST'])
def predict():
    try:
        # Get JSON input
        data = request.get_json()

        # Extract features
        property_price = float(data['property_price'])
        location = data['location']
        user_email = data['user_email']

        # Preprocess features
        has_priority_email = 1 if 'priority' in user_email.lower() or 'vip' in user_email.lower() else 0
        location_encoded = location_encoder.transform([location.lower()])[0]

        # Create feature array
        features = np.array([[property_price, location_encoded, has_priority_email]])

        # Scale numerical features
        features[:, 0:1] = scaler.transform(features[:, 0:1])

        # Predict lead score
        score = model.predict(features)[0]

        # Ensure score is between 0 and 1
        score = max(0.0, min(1.0, float(score)))

        return jsonify({'score': score})

    except Exception as e:
        return jsonify({'error': str(e)}), 400

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)


#app.py
