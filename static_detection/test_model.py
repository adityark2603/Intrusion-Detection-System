import joblib
import pandas as pd

model = joblib.load("model/ids_model.joblib")
df = pd.read_csv("data/flows_ready.csv")

# align features exactly
X = df[model.feature_names_in_]

preds = model.predict(X)
probs = model.predict_proba(X)

for i in range(10):
    print(f"Flow {i} → Prediction: {preds[i]}, Attack prob: {probs[i][1]:.3f}")
    
THRESHOLD = 0.7

for i, p in enumerate(probs):
    if p[1] > THRESHOLD:
        print(f"[ALERT] Suspicious flow {i} | prob={p[1]:.2f}")

