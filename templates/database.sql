CREATE DATABASE IF NOT EXISTS phishing_db;
USE phishing_db;

-- Table for manual prediction results
CREATE TABLE IF NOT EXISTS behavior_data (
    id INT AUTO_INCREMENT PRIMARY KEY,
    mouse_moves INT,
    mouse_clicks INT,
    keystrokes INT,
    scrolls INT,
    time_spent INT,
    result VARCHAR(50),
    confidence DECIMAL(5,2),
    prediction_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    page_url VARCHAR(500),
    session_id VARCHAR(100)
);

-- Table for automatic detection sessions
CREATE TABLE IF NOT EXISTS auto_sessions (
    id INT AUTO_INCREMENT PRIMARY KEY,
    session_id VARCHAR(100) UNIQUE,
    username VARCHAR(100),
    mouse_moves INT DEFAULT 0,
    mouse_clicks INT DEFAULT 0,
    keystrokes INT DEFAULT 0,
    scrolls INT DEFAULT 0,
    time_spent INT DEFAULT 0,
    start_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    end_time TIMESTAMP NULL,
    prediction_result VARCHAR(50),
    confidence DECIMAL(5,2),
    page_url VARCHAR(500)
);

-- Table for user behavior logs (for analysis)
CREATE TABLE IF NOT EXISTS behavior_logs (
    id INT AUTO_INCREMENT PRIMARY KEY,
    session_id VARCHAR(100),
    event_type ENUM('mouse_move', 'mouse_click', 'keypress', 'scroll'),
    event_value TEXT,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Create indexes for better performance
CREATE INDEX idx_session_id ON auto_sessions(session_id);
CREATE INDEX idx_result_time ON behavior_data(prediction_time);