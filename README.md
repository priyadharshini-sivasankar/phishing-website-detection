# Phishing Detection Using Behavioural Cues in Browser Interaction

A machine learning-based system that detects phishing websites by analyzing **real-time user behavioral patterns** during browser interaction — going beyond traditional URL/content-based detection methods.

## Overview

Most phishing detection systems rely on static analysis: URL structure, blacklists, or page content. These approaches struggle against new, unlisted phishing sites and sophisticated attacks that closely mimic legitimate pages.

This project takes a different approach — it monitors **how a user interacts** with a website in real time, since people tend to behave differently (more hesitant, erratic, or rushed) when facing a suspicious or unfamiliar site versus a trusted one. These behavioral signals are combined with a trained classifier to flag likely phishing attempts.

## Behavioral Signals Tracked

- **Mouse movement** — trajectory, velocity, acceleration, click precision
- **Keystroke dynamics** — dwell time, flight time, typing rhythm, correction/backspace patterns
- **Clickstream behavior** — click timing, sequence, navigation patterns
- **Scrolling activity** — speed, pause points, depth of exploration
- **Session characteristics** — total duration, page navigation, abandonment patterns

## Tech Stack

- **Backend:** Python, Flask
- **Machine Learning:** scikit-learn (Random Forest Classifier), pandas, numpy
- **Database:** MySQL
- **Frontend:** HTML, CSS

## Project Structure

```
├── app.py                 # Main Flask application
├── train_rf.py             # Script to train the Random Forest model
├── model.pkl                # Trained ML model
├── features.pkl               # Extracted feature set used by the model
├── dataset.csv                # Training dataset
├── requirements.txt             # Python dependencies
├── database/                    # Database schema and related files
├── static/                       # CSS and static assets
└── templates/                     # HTML templates (index, result, history, etc.)
```

## How It Works

1. User interaction data (mouse, keystrokes, clicks, scrolling, session timing) is captured through the browser interface.
2. Raw data is preprocessed — noise filtering, normalization, and feature extraction.
3. The processed features are passed to a trained Random Forest Classifier.
4. The system classifies the session/site as **legitimate** or **phishing**, with results shown through the web interface and stored in the database for later review.

The web application supports both **manual URL input analysis** and **automatic real-time behavioral monitoring**.

## Setup & Installation

1. Clone the repository:
   ```
   git clone https://github.com/priyadharshini-sivasankar/phishing-website-detection.git
   cd phishing-website-detection
   ```

2. Install dependencies:
   ```
   pip install -r requirements.txt
   ```

3. Set up the MySQL database using the schema provided in `database/`.

4. Run the application:
   ```
   python app.py
   ```

5. Open your browser at `http://localhost:5000`

## Model Training

To retrain the model on new data:
```
python train_rf.py
```
This reads from `dataset.csv` and produces an updated `model.pkl` and `features.pkl`.

## Project Context

This project was developed as a final-year B.E. Computer Science and Engineering project, exploring behavioral analytics as an underused signal in phishing detection — most existing research focuses on website-side features rather than how a real user interacts with a page.

## Future Improvements

- Expand and diversify the training dataset
- Explore deep learning architectures (CNN/LSTM) for richer temporal pattern modeling
- Real-time browser extension deployment for live protection
- Integration with external URL reputation APIs

## Author

**Priyadharshini Sivasankar**
