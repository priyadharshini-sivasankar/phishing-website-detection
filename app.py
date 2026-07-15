from flask import Flask, render_template, request, jsonify, session
import pickle
import pandas as pd
import mysql.connector
import uuid
import time
from datetime import datetime
import threading
import numpy as np

app = Flask(__name__)
app.secret_key = 'phishing-detection-secret-key-2024'

# -----------------------------
# Load Trained Random Forest Model
# -----------------------------
try:
    with open("model.pkl", "rb") as f:
        model = pickle.load(f)
    print("✅ Random Forest model loaded successfully!")
    
    with open("features.pkl", "rb") as f:
        FEATURES = pickle.load(f)
    print(f"✅ Features: {FEATURES}")
    
except Exception as e:
    print(f"❌ Error loading model: {e}")
    model = None
    FEATURES = ['mouse_moves', 'mouse_clicks', 'keystrokes', 'scrolls', 'time_spent']

# -----------------------------
# Database Connection with NumPy support
# -----------------------------
def get_db():
    try:
        conn = mysql.connector.connect(
            host="localhost",
            user="root",
            password="",
            database="phishing_db",
            auth_plugin='mysql_native_password',
            use_pure=True
        )
        return conn
    except Exception as e:
        print(f"❌ Database error: {e}")
        return None

# -----------------------------
# Threshold values for automatic detection
# -----------------------------
THRESHOLDS = {
    'mouse_moves': {'phishing_max': 100, 'legitimate_min': 200},
    'mouse_clicks': {'phishing_max': 10, 'legitimate_min': 15},
    'keystrokes': {'phishing_max': 15, 'legitimate_min': 30},
    'scrolls': {'phishing_max': 5, 'legitimate_min': 10},
    'time_spent': {'phishing_max': 120, 'legitimate_min': 240}  # seconds
}

# -----------------------------
# Helper Functions
# -----------------------------
def predict_phishing(features):
    """Predict using Random Forest model"""
    if model is None:
        return None, None, None
    
    try:
        input_df = pd.DataFrame([features], columns=FEATURES)
        prediction = model.predict(input_df)[0]
        probabilities = model.predict_proba(input_df)[0]
        confidence = probabilities[prediction] * 100
        
        # Convert NumPy types to Python native types
        prediction = int(prediction)
        confidence = float(confidence)
        probabilities = [float(p) for p in probabilities]
        
        result = "PHISHING WEBSITE" if prediction == 1 else "LEGITIMATE WEBSITE"
        return result, confidence, probabilities
    except Exception as e:
        print(f"Prediction error: {e}")
        return None, None, None

def check_thresholds(features):
    """Check if features exceed thresholds"""
    warnings = []
    for feature, value in features.items():
        if feature in THRESHOLDS:
            threshold = THRESHOLDS[feature]
            if value < threshold['phishing_max']:
                warnings.append(f"Low {feature.replace('_', ' ')}: {value} (suspicious)")
            elif value > threshold['legitimate_min']:
                warnings.append(f"High {feature.replace('_', ' ')}: {value} (normal)")
    return warnings

# Context processor to make 'now' available in all templates
@app.context_processor
def utility_processor():
    def get_current_time():
        return datetime.now()
    return dict(now=get_current_time)

# -----------------------------
# Routes
# -----------------------------
@app.route("/")
def home():
    """Home page with options"""
    return render_template("index.html", model_loaded=model is not None)

@app.route("/manual")
def manual_detection():
    """Manual input page"""
    return render_template("manual.html", thresholds=THRESHOLDS)

@app.route("/predict", methods=["POST"])
def predict():
    """Predict using Random Forest model (manual input)"""
    try:
        # Get form data
        mouse_moves = int(request.form.get("mouse_moves", 0))
        mouse_clicks = int(request.form.get("mouse_clicks", 0))
        keystrokes = int(request.form.get("keystrokes", 0))
        scrolls = int(request.form.get("scrolls", 0))
        time_spent = int(request.form.get("time_spent", 0))
        page_url = request.form.get("page_url", "Unknown")
        
        input_data = {
            "mouse_moves": mouse_moves,
            "mouse_clicks": mouse_clicks,
            "keystrokes": keystrokes,
            "scrolls": scrolls,
            "time_spent": time_spent
        }
        
        print(f"\n🔍 Manual Prediction Request:")
        print(f"Input: {input_data}")
        
        # Check thresholds
        threshold_warnings = check_thresholds(input_data)
        
        if model is None:
            return render_template("result.html",
                result="MODEL NOT LOADED",
                result_class="error",
                confidence=0,
                explanation="Please train the model first using train_rf.py",
                input_values=input_data,
                probabilities={"legitimate": 0, "phishing": 0},
                thresholds=THRESHOLDS,
                threshold_warnings=threshold_warnings,
                page_url=page_url
            )
        
        # Get prediction
        features_list = [mouse_moves, mouse_clicks, keystrokes, scrolls, time_spent]
        result, confidence, probabilities = predict_phishing(features_list)
        
        if result is None:
            return render_template("error.html", error="Prediction failed")
        
        result_class = "phishing" if "PHISHING" in result else "legitimate"
        
        if result_class == "phishing":
            explanation = "Random Forest model detected phishing behavior patterns"
        else:
            explanation = "Random Forest model detected legitimate behavior patterns"
        
        # Store in database
        try:
            conn = get_db()
            if conn:
                cursor = conn.cursor()
                
                # Ensure confidence is Python float
                confidence_float = float(confidence) if confidence else 0.0
                
                cursor.execute(
                    """
                    INSERT INTO behavior_data 
                    (mouse_moves, mouse_clicks, keystrokes, scrolls, time_spent, result, confidence, page_url, session_id) 
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
                    """,
                    (mouse_moves, mouse_clicks, keystrokes, scrolls, time_spent, 
                     result, confidence_float, page_url, str(uuid.uuid4()))
                )
                conn.commit()
                cursor.close()
                conn.close()
                print("✅ Result stored in database")
        except Exception as e:
            print(f"❌ Database error: {e}")
        
        # Prepare response
        response_data = {
            "result": result,
            "result_class": result_class,
            "confidence": round(confidence, 1) if confidence else 0,
            "explanation": explanation,
            "input_values": input_data,
            "probabilities": {
                "legitimate": round(probabilities[0] * 100, 1) if probabilities else 0,
                "phishing": round(probabilities[1] * 100, 1) if probabilities else 0
            } if probabilities else {"legitimate": 0, "phishing": 0},
            "model_type": "Random Forest Classifier",
            "thresholds": THRESHOLDS,
            "threshold_warnings": threshold_warnings,
            "page_url": page_url
        }
        
        print(f"Random Forest Prediction: {result} ({confidence:.1f}% confidence)")
        
        return render_template("result.html", **response_data)
        
    except ValueError as e:
        return render_template("error.html", error=f"Invalid input: {str(e)}")
    except Exception as e:
        return render_template("error.html", error=f"Prediction error: {str(e)}")

@app.route("/auto-login")
def auto_login():
    """Automatic detection login page"""
    session_id = str(uuid.uuid4())
    session['session_id'] = session_id
    session['start_time'] = time.time()
    session['mouse_moves'] = 0
    session['mouse_clicks'] = 0
    session['keystrokes'] = 0
    session['scrolls'] = 0
    
    # Initialize session in database
    try:
        conn = get_db()
        if conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT INTO auto_sessions (session_id) 
                VALUES (%s)
                """,
                (session_id,)
            )
            conn.commit()
            cursor.close()
            conn.close()
    except Exception as e:
        print(f"❌ Database error: {e}")
    
    return render_template("auto_login.html", session_id=session_id)

@app.route("/track-behavior", methods=["POST"])
def track_behavior():
    """Track user behavior from JavaScript"""
    try:
        data = request.json
        session_id = data.get('session_id')
        event_type = data.get('event_type')
        event_value = data.get('value', '')
        
        if not session_id:
            return jsonify({'status': 'error', 'message': 'No session ID'})
        
        # Update session counts
        if event_type == 'mouse_move':
            if 'mouse_moves' in session:
                session['mouse_moves'] = session.get('mouse_moves', 0) + 1
        elif event_type == 'click':
            if 'mouse_clicks' in session:
                session['mouse_clicks'] = session.get('mouse_clicks', 0) + 1
        elif event_type == 'keypress':
            if 'keystrokes' in session:
                session['keystrokes'] = session.get('keystrokes', 0) + 1
        elif event_type == 'scroll':
            if 'scrolls' in session:
                session['scrolls'] = session.get('scrolls', 0) + 1
        
        # Log event in database
        try:
            conn = get_db()
            if conn:
                cursor = conn.cursor()
                cursor.execute(
                    """
                    INSERT INTO behavior_logs (session_id, event_type, event_value) 
                    VALUES (%s, %s, %s)
                    """,
                    (session_id, event_type, str(event_value))
                )
                conn.commit()
                cursor.close()
                conn.close()
        except Exception as e:
            print(f"❌ Database error logging behavior: {e}")
        
        return jsonify({'status': 'success', 'counts': {
            'mouse_moves': session.get('mouse_moves', 0),
            'mouse_clicks': session.get('mouse_clicks', 0),
            'keystrokes': session.get('keystrokes', 0),
            'scrolls': session.get('scrolls', 0)
        }})
    
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)})

@app.route("/submit-login", methods=["POST"])
def submit_login():
    """Process login form and analyze behavior"""
    try:
        session_id = session.get('session_id')
        if not session_id:
            return jsonify({'status': 'error', 'message': 'No active session'})
        
        # Calculate time spent
        start_time = session.get('start_time', time.time())
        time_spent = int(time.time() - start_time)
        
        # Get behavior counts
        mouse_moves = session.get('mouse_moves', 0)
        mouse_clicks = session.get('mouse_clicks', 0)
        keystrokes = session.get('keystrokes', 0)
        scrolls = session.get('scrolls', 0)
        
        # Get form data
        username = request.form.get('username', '')
        password = request.form.get('password', '')
        page_url = request.form.get('page_url', 'Dummy Login Page')
        
        features = [mouse_moves, mouse_clicks, keystrokes, scrolls, time_spent]
        
        # Get prediction
        result, confidence, probabilities = predict_phishing(features)
        
        if result is None:
            result = "ERROR"
            confidence = 0
            result_class = "error"
        else:
            result_class = "phishing" if "PHISHING" in result else "legitimate"
        
        # Update session in database
        try:
            conn = get_db()
            if conn:
                cursor = conn.cursor()
                
                # Ensure confidence is Python float
                confidence_float = float(confidence) if confidence else 0.0
                
                cursor.execute(
                    """
                    UPDATE auto_sessions 
                    SET username = %s, mouse_moves = %s, mouse_clicks = %s, 
                        keystrokes = %s, scrolls = %s, time_spent = %s,
                        end_time = CURRENT_TIMESTAMP, prediction_result = %s,
                        confidence = %s, page_url = %s
                    WHERE session_id = %s
                    """,
                    (username, mouse_moves, mouse_clicks, keystrokes, scrolls,
                     time_spent, result, confidence_float, page_url, session_id)
                )
                conn.commit()
                cursor.close()
                conn.close()
        except Exception as e:
            print(f"❌ Database error updating session: {e}")
        
        # Clear session
        for key in ['mouse_moves', 'mouse_clicks', 'keystrokes', 'scrolls', 'start_time']:
            session.pop(key, None)
        
        # Prepare response
        response_data = {
            'status': 'success',
            'result': result,
            'result_class': result_class,
            'confidence': round(confidence, 1) if confidence else 0,
            'behavior_data': {
                'mouse_moves': mouse_moves,
                'mouse_clicks': mouse_clicks,
                'keystrokes': keystrokes,
                'scrolls': scrolls,
                'time_spent': time_spent
            },
            'probabilities': {
                'legitimate': round(probabilities[0] * 100, 1) if probabilities else 0,
                'phishing': round(probabilities[1] * 100, 1) if probabilities else 0
            } if probabilities else {'legitimate': 0, 'phishing': 0},
            'thresholds': THRESHOLDS,
            'page_url': page_url
        }
        
        return jsonify(response_data)
    
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)})

@app.route("/history")
def history():
    """Show prediction history"""
    try:
        conn = get_db()
        if conn:
            cursor = conn.cursor(dictionary=True)
            
            # Get manual predictions
            cursor.execute("""
                SELECT *, DATE_FORMAT(prediction_time, '%%Y-%%m-%%d %%H:%%i:%%s') as formatted_time 
                FROM behavior_data 
                ORDER BY prediction_time DESC 
                LIMIT 50
            """)
            manual_history = cursor.fetchall()
            
            # Get auto session predictions
            cursor.execute("""
                SELECT *, DATE_FORMAT(end_time, '%%Y-%%m-%%d %%H:%%i:%%s') as formatted_time 
                FROM auto_sessions 
                WHERE prediction_result IS NOT NULL 
                ORDER BY end_time DESC 
                LIMIT 50
            """)
            auto_history = cursor.fetchall()
            
            cursor.close()
            conn.close()
            
            # Calculate statistics
            total_predictions = len(manual_history) + len(auto_history)
            phishing_count = sum(1 for h in manual_history if h.get('result') and 'PHISHING' in h['result']) + \
                           sum(1 for h in auto_history if h.get('prediction_result') and 'PHISHING' in h['prediction_result'])
            legitimate_count = total_predictions - phishing_count
            
            phishing_percentage = round((phishing_count/total_predictions*100), 1) if total_predictions > 0 else 0
            
            return render_template("history.html",
                manual_history=manual_history,
                auto_history=auto_history,
                total_predictions=total_predictions,
                phishing_count=phishing_count,
                legitimate_count=legitimate_count,
                phishing_percentage=phishing_percentage
            )
        else:
            return render_template("history.html",
                manual_history=[],
                auto_history=[],
                total_predictions=0,
                phishing_count=0,
                legitimate_count=0,
                phishing_percentage=0
            )
    except Exception as e:
        print(f"❌ Error fetching history: {e}")
        return render_template("error.html", error=f"Failed to load history: {str(e)}")

@app.route("/test")
def test():
    """Test page to verify model is working"""
    if model is None:
        return "Model not loaded. Please run train_rf.py first."
    
    test_cases = [
        {"name": "Clear Legitimate", "values": [350, 28, 85, 22, 450], "expected": "LEGITIMATE"},
        {"name": "Clear Phishing", "values": [45, 3, 8, 2, 65], "expected": "PHISHING"},
        {"name": "Medium Legitimate", "values": [250, 20, 60, 15, 350], "expected": "LEGITIMATE"},
        {"name": "Medium Phishing", "values": [80, 5, 15, 3, 120], "expected": "PHISHING"},
    ]
    
    results = []
    for test in test_cases:
        test_df = pd.DataFrame([test['values']], columns=FEATURES)
        prediction = int(model.predict(test_df)[0])
        probabilities = [float(p) for p in model.predict_proba(test_df)[0]]
        
        predicted_class = "LEGITIMATE" if prediction == 0 else "PHISHING"
        
        results.append({
            "name": test['name'],
            "input": test['values'],
            "predicted": predicted_class,
            "expected": test['expected'],
            "confidence": round(probabilities[prediction] * 100, 1),
            "prob_legit": round(probabilities[0] * 100, 1),
            "prob_phishing": round(probabilities[1] * 100, 1),
            "correct": predicted_class == test['expected']
        })
    
    return render_template("test.html", results=results)

# -----------------------------
# Run the app
# -----------------------------
if __name__ == "__main__":
    print("\n" + "="*60)
    print("PHISHING DETECTION SYSTEM - RANDOM FOREST CLASSIFIER")
    print("="*60)
    
    if model:
        print("✅ Model loaded and ready for predictions!")
        print("📊 Features:", FEATURES)
        print("📈 Thresholds for automatic detection:")
        for feature, thresholds in THRESHOLDS.items():
            print(f"  {feature}: Phishing < {thresholds['phishing_max']}, Legitimate > {thresholds['legitimate_min']}")
    else:
        print("❌ Model not loaded. Run train_rf.py first.")
    
    print("\n🌐 Starting server on http://localhost:5000")
    print("="*60)
    
    app.run(debug=True, host='0.0.0.0', port=5000)
