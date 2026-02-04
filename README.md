# 🛡️ ScamShield AI

**AI-Powered Scam & Fraud Detection for Digital Payments**

ScamShield AI is a web-based fintech application that detects scam and phishing messages before users lose money. It uses Natural Language Processing (NLP) to analyze suspicious messages and deliver real-time warnings with clear, explainable reasons.

![ScamShield AI](https://img.shields.io/badge/AI-Powered-00f0ff?style=for-the-badge)
![React](https://img.shields.io/badge/React-18.2.0-61DAFB?style=for-the-badge&logo=react)
![FastAPI](https://img.shields.io/badge/FastAPI-0.109.0-009688?style=for-the-badge&logo=fastapi)
![Python](https://img.shields.io/badge/Python-3.9+-3776AB?style=for-the-badge&logo=python)

## 🧩 Problem Statement

With the rapid adoption of digital wallets and online payments, users are increasingly exposed to:

- 📱 Phishing SMS and WhatsApp messages
- 🏦 Fake bank or wallet alerts
- 💳 Fraudulent payment confirmations
- ⚠️ Impersonation and urgency-based scams

Most existing solutions respond **after** fraud occurs. ScamShield AI focuses on **prevention**, identifying scams at the message level before users take action.

## 💡 Solution Overview

ScamShield AI analyzes user-submitted text using an AI/NLP model to:

- ✅ Classify messages as **Safe**, **Suspicious**, or **Scam**
- 📊 Generate a probability-based risk score (0-100)
- 🔍 Explain why a message is dangerous
- 💡 Provide clear safety guidance to users

## ✨ Key Features

### 🎯 Core Capabilities
- **Real-time Analysis**: Instant scam detection in milliseconds
- **Explainable AI**: Clear explanations for each classification
- **Risk Scoring**: Probability-based threat assessment (0-100)
- **Keyword Highlighting**: Visual identification of suspicious terms
- **Safety Recommendations**: Actionable guidance for users

### 🧠 AI Detection Capabilities
- ⏰ **Urgency Language Detection**: "urgent", "immediately", "expires"
- 🎭 **Impersonation Detection**: Bank, wallet, government entities
- 🔗 **Suspicious URL Recognition**: Shortened links, IP addresses
- 💰 **Financial Manipulation**: Unrealistic rewards, payment requests
- ⛔ **Threat Language**: Account suspension, legal action
- 🔐 **Sensitive Data Requests**: OTP, PIN, password requests

## 🛠️ Technology Stack

### Frontend
- **React.js 18.2.0**: Modern UI framework
- **Custom CSS**: Cyberpunk-inspired security theme
- **Google Fonts**: Orbitron (display) + Sora (body)
- **Responsive Design**: Mobile-first approach

### Backend
- **Python 3.9+**: Core language
- **FastAPI**: High-performance async API
- **Pydantic**: Data validation
- **RESTful Architecture**: Clean API design

### AI/NLP
- **Pattern Matching**: Regex-based detection
- **Heuristic Analysis**: Multi-factor risk scoring
- **Real-time Processing**: Sub-second analysis
- **Explainable Results**: Transparent decision making

## 📁 Project Structure

```
scamshield-ai/
├── backend/
│   ├── main.py                 # FastAPI application
│   ├── requirements.txt        # Python dependencies
│   └── README.md              # Backend documentation
├── frontend/
│   ├── public/
│   │   └── index.html         # HTML template
│   ├── src/
│   │   ├── App.jsx            # Main React component
│   │   ├── App.css            # Cyberpunk styling
│   │   ├── index.js           # React entry point
│   │   └── index.css          # Global styles
│   ├── package.json           # Node dependencies
│   └── README.md              # Frontend documentation
└── README.md                   # This file
```

## 🚀 Getting Started

### Prerequisites

- **Python 3.9+** installed
- **Node.js 16+** and npm installed
- **Terminal/Command Prompt**

### Backend Setup

1. Navigate to the backend directory:
```bash
cd backend
```

2. Install Python dependencies:
```bash
pip install -r requirements.txt
```

3. Start the FastAPI server:
```bash
python main.py
```

### Frontend Setup

1. Navigate to the frontend directory:
```bash
cd frontend
```

2. Install Node dependencies:
```bash
npm install
```

3. Start the React development server:
```bash
npm start
```

The frontend will open automatically at `http://localhost:3000`

## 🔄 Application Workflow

1. **User Input**: User pastes or types a suspicious message
2. **Frontend Submission**: Message sent to backend API via POST request
3. **Text Preprocessing**: Message normalized and cleaned
4. **Pattern Analysis**: AI analyzes scam indicators
5. **Risk Calculation**: Multi-factor risk score computed
6. **Classification**: Message labeled as Safe/Suspicious/Scam
7. **Response Generation**: Explanations and recommendations prepared
8. **Results Display**: Frontend shows analysis with visual indicators

## 📊 API Endpoints

### POST `/analyze`

Analyzes a message for scam indicators.

**Request:**
```json
{
  "message": "URGENT! Your account will be suspended..."
}
```

**Response:**
```json
{
  "classification": "SCAM",
  "risk_score": 85.5,
  "explanation": [
    "⚠️ Urgency language detected: Creates false time pressure",
    "🎭 Impersonation attempt: Pretends to be from trusted organization"
  ],
  "highlighted_keywords": ["urgent", "suspended", "verify"],
  "safety_recommendations": [
    "🚫 DO NOT respond to this message",
    "🗑️ Delete this message immediately"
  ],
  "analyzed_at": "2024-02-03T12:00:00"
}
```

### GET `/health`

Health check endpoint.

**Response:**
```json
{
  "status": "healthy",
  "timestamp": "2024-02-03T12:00:00"
}
```

## 🎨 Design Philosophy

The interface uses a **cybersecurity-inspired cyberpunk aesthetic**:

- **Typography**: Orbitron (futuristic display) + Sora (clean body)
- **Colors**: Dark theme with cyan accents (#00f0ff)
- **Animations**: Grid scrolling, scanning lines, pulse effects
- **Visual Hierarchy**: Risk-based color coding (red/yellow/green)
- **User Experience**: Clear, actionable, non-technical language

## 🧪 Testing Examples

Try these sample messages in the application:

### 🚨 SCAM (High Risk)
```
URGENT! Your bank account will be suspended in 24 hours. 
Click here to verify your identity immediately: bit.ly/verify-now
```

### ⚠️ SUSPICIOUS (Medium Risk)
```
Dear customer, we noticed unusual activity on your account. 
Please confirm your recent transaction by clicking the link below.
```

### ✅ SAFE (Low Risk)
```
Your order #12345 has been shipped and will arrive on Monday. 
Track your package at amazon.com/orders
```

## 🔒 Security Best Practices

The application promotes these security principles:

1. ✅ **Never share** passwords, OTPs, PINs, or CVV codes
2. 📞 **Verify directly** with organizations through official channels
3. ⏰ **Ignore urgency** - legitimate companies don't rush decisions
4. 🔗 **Check URLs** carefully before clicking any links
5. 🗑️ **Delete suspicious** messages immediately


## 🤝 Contributing

Contributions are welcome! Please follow these steps:

1. Fork the repository
2. Create a feature branch 
3. Commit your changes
4. Push to the branch 
5. Open a Pull Request

## 📄 License

This project is for educational and demonstration purposes.

## 👥 Authors

Sayad Akbar
Built with ❤️ for digital safety and fraud prevention.

## 🙏 Acknowledgments

- FastAPI for the excellent async framework
- React for the powerful UI library
- The cybersecurity community for scam pattern research

## 📞 Support

For issues, questions, or suggestions:
- Open an issue on the repository

- 
