import pandas as pd
import pickle
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
import numpy as np

# -----------------------------
# Create sample dataset
# -----------------------------
print("📊 Creating dataset...")

# Generate more realistic data
np.random.seed(42)

# Legitimate behavior (higher values)
legitimate_samples = 500
phishing_samples = 500

# Legitimate website behavior (normal users)
legitimate_data = {
    'mouse_moves': np.random.randint(200, 500, legitimate_samples),
    'mouse_clicks': np.random.randint(15, 40, legitimate_samples),
    'keystrokes': np.random.randint(40, 120, legitimate_samples),
    'scrolls': np.random.randint(10, 30, legitimate_samples),
    'time_spent': np.random.randint(300, 600, legitimate_samples),
    'label': [0] * legitimate_samples  # 0 = Legitimate
}

# Phishing website behavior (suspicious users)
phishing_data = {
    'mouse_moves': np.random.randint(20, 100, phishing_samples),
    'mouse_clicks': np.random.randint(2, 10, phishing_samples),
    'keystrokes': np.random.randint(5, 20, phishing_samples),
    'scrolls': np.random.randint(1, 5, phishing_samples),
    'time_spent': np.random.randint(30, 120, phishing_samples),
    'label': [1] * phishing_samples  # 1 = Phishing
}

# Combine data
legitimate_df = pd.DataFrame(legitimate_data)
phishing_df = pd.DataFrame(phishing_data)
data = pd.concat([legitimate_df, phishing_df], ignore_index=True)

# Shuffle the data
data = data.sample(frac=1, random_state=42).reset_index(drop=True)

print("✅ Dataset Created:")
print(f"Shape: {data.shape}")
print(f"\nClass distribution:")
print(f"Legitimate (0): {sum(data['label'] == 0)} samples")
print(f"Phishing (1): {sum(data['label'] == 1)} samples")
print(f"\nSample data:")
print(data.head())

# -----------------------------
# Prepare features and labels
# -----------------------------
features = ['mouse_moves', 'mouse_clicks', 'keystrokes', 'scrolls', 'time_spent']
X = data[features]
y = data['label']

# Split data
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

print(f"\n📈 Data split:")
print(f"Training samples: {X_train.shape[0]}")
print(f"Testing samples: {X_test.shape[0]}")

# -----------------------------
# Train Random Forest Classifier
# -----------------------------
print("\n🤖 Training Random Forest Classifier...")
model = RandomForestClassifier(
    n_estimators=200,
    max_depth=10,
    min_samples_split=5,
    min_samples_leaf=2,
    random_state=42,
    n_jobs=-1
)

model.fit(X_train, y_train)

# -----------------------------
# Test the model
# -----------------------------
print("\n🧪 Testing model performance:")
print("-" * 60)

# Training accuracy
train_accuracy = model.score(X_train, y_train)
test_accuracy = model.score(X_test, y_test)

print(f"Training Accuracy: {train_accuracy:.2%}")
print(f"Testing Accuracy: {test_accuracy:.2%}")

# Test specific cases
test_cases = [
    {"name": "Typical Legitimate", "values": [350, 28, 85, 22, 450], "expected": 0},
    {"name": "Typical Phishing", "values": [45, 3, 8, 2, 65], "expected": 1},
    {"name": "High Activity Legitimate", "values": [480, 38, 115, 28, 580], "expected": 0},
    {"name": "Very Low Activity", "values": [15, 1, 3, 0, 25], "expected": 1},
    {"name": "Borderline Case", "values": [120, 12, 25, 8, 180], "expected": 1},
]

print("\n🔍 Detailed test cases:")
for test in test_cases:
    test_df = pd.DataFrame([test['values']], columns=features)
    prediction = model.predict(test_df)[0]
    probability = model.predict_proba(test_df)[0]
    
    result = "LEGITIMATE" if prediction == 0 else "PHISHING"
    expected = "LEGITIMATE" if test['expected'] == 0 else "PHISHING"
    
    print(f"\n{test['name']}:")
    print(f"  Input: {test['values']}")
    print(f"  Predicted: {result} (Class: {prediction})")
    print(f"  Expected: {expected}")
    print(f"  Probability: Legitimate={probability[0]:.2%}, Phishing={probability[1]:.2%}")
    
    if prediction == test['expected']:
        print(f"  ✅ CORRECT")
    else:
        print(f"  ❌ WRONG")

# Feature importance
feature_importance = pd.DataFrame({
    'feature': features,
    'importance': model.feature_importances_
}).sort_values('importance', ascending=False)

print("\n📊 Feature Importance:")
print(feature_importance)

# -----------------------------
# Save the model
# -----------------------------
with open("model.pkl", "wb") as f:
    pickle.dump(model, f)

with open("features.pkl", "wb") as f:
    pickle.dump(features, f)

print("\n" + "=" * 60)
print("✅ Model trained and saved successfully!")
print(f"📁 Model saved as 'model.pkl'")
print(f"📁 Features saved as 'features.pkl'")
print(f"🎯 Features used: {features}")
print(f"📈 Model accuracy: {test_accuracy:.2%}")
print("=" * 60)

# Calculate and display thresholds
print("\n📋 Suggested Thresholds for Detection:")
for feature in features:
    legitimate_values = data[data['label'] == 0][feature]
    phishing_values = data[data['label'] == 1][feature]
    
    phishing_max = phishing_values.quantile(0.75)  # 75th percentile of phishing
    legitimate_min = legitimate_values.quantile(0.25)  # 25th percentile of legitimate
    
    print(f"{feature}:")
    print(f"  Phishing (max): {phishing_max:.0f}")
    print(f"  Legitimate (min): {legitimate_min:.0f}")
    print(f"  Phishing range: {phishing_values.min():.0f} - {phishing_values.max():.0f}")
    print(f"  Legitimate range: {legitimate_values.min():.0f} - {legitimate_values.max():.0f}")
    print()
