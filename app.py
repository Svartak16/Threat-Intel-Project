from flask import Flask, render_template
import pymongo

app = Flask(__name__)
db = pymongo.MongoClient("mongodb://localhost:27017/")["threat_intel"]

@app.route('/')
def home():
    threats = list(db.indicators.find().sort("risk_score", -1).limit(50))
    stats = {
        "total": db.indicators.count_documents({}),
        "blocked": db.indicators.count_documents({"status": "blocked"}),
        "high_risk": db.indicators.count_documents({"risk_score": {"$gte": 8}})
    }
    return render_template("index.html", threats=threats, stats=stats)

if __name__ == "__main__":
    app.run(host='0.0.0.0', port=5000, debug=True)
