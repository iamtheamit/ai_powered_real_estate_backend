# ml_service/train_model.py
import numpy as np
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.linear_model import LinearRegression
from sklearn.model_selection import train_test_split
import joblib

# Generate synthetic data for training
np.random.seed(42)
num_samples = 1000

data = {
    'property_price': np.random.uniform(50000, 10000000, num_samples),
    'location': np.random.choice(['city center', 'suburbs', 'rural'], num_samples),
    'has_priority_email': np.random.randint(0, 2, num_samples),
    'lead_score': np.zeros(num_samples)
}

for i in range(num_samples):
    base_score = data['property_price'][i] / 10000000.0
    location_boost = 0.3 if data['location'][i] == 'city center' else (0.1 if data['location'][i] == 'suburbs' else 0.0)
    email_boost = 0.3 if data['has_priority_email'][i] == 1 else 0.0
    data['lead_score'][i] = min(1.0, max(0.0, base_score + location_boost + email_boost))

import pandas as pd
df = pd.DataFrame(data)

# Encode categorical features
le_location = LabelEncoder()
df['location'] = le_location.fit_transform(df['location'])

# Features and target
X = df[['property_price', 'location', 'has_priority_email']].values
y = df['lead_score'].values

# Scale numerical features
scaler = StandardScaler()
X[:, 0:1] = scaler.fit_transform(X[:, 0:1])

# Split data
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

# Train a simple linear regression model
model = LinearRegression()
model.fit(X_train, y_train)

# Evaluate
score = model.score(X_test, y_test)
print(f"Model R² Score: {score}")

# Save the model, scaler, and label encoder
joblib.dump(model, 'lead_score_model.joblib')
joblib.dump(scaler, 'scaler.joblib')
joblib.dump(le_location, 'location_encoder.joblib')

print("Model and preprocessing objects saved successfully")