import pandas as pd
import lightgbm as lgb
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix, classification_report
import shap
import matplotlib.pyplot as plt
import os
import joblib

CSV_PATH = "data/features_binary.csv"
MODEL_PATH = "models/malware_detector3.pkl"

def load_dataset():
    df = pd.read_csv(CSV_PATH)
    df = df.drop(columns=["filename"], errors='ignore')  # Drop if exists
    X = df.drop(columns=["label"])
    y = df["label"]
    return X, y

def train_model(X, y):
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, stratify=y, random_state=42
    )

    model = lgb.LGBMClassifier(
        objective="binary",
        n_estimators=100,
        learning_rate=0.1,
        max_depth=5,
        random_state=42
    )

    model.fit(X_train, y_train)
    y_pred = model.predict(X_test)

    acc = accuracy_score(y_test, y_pred)
    precision = precision_score(y_test, y_pred)
    recall = recall_score(y_test, y_pred)
    f1 = f1_score(y_test, y_pred)

    print("\n=== 📊 Evaluation Metrics ===")
    print(f"✅ Accuracy:  {acc:.4f}")
    print(f"🎯 Precision: {precision:.4f}")
    print(f"🔁 Recall:    {recall:.4f}")
    print(f"🏆 F1 Score:  {f1:.4f}")
    print("\n=== 🔍 Classification Report ===")
    print(classification_report(y_test, y_pred))
    print("=== 📉 Confusion Matrix ===")
    print(confusion_matrix(y_test, y_pred))

    return model, X_test

def explain_with_shap(model, X_sample):
    print("[+] Generating SHAP explanation for one prediction...")
    explainer = shap.Explainer(model)
    shap_values = explainer(X_sample)
    shap.plots.bar(shap_values[0], show=False)
    plt.title("SHAP Feature Impact")
    plt.tight_layout()
    plt.savefig("shap_explanation.png")
    print("[✓] SHAP plot saved as: shap_explanation.png")

def main():
    os.makedirs("models", exist_ok=True)
    print("[+] Loading dataset...")
    X, y = load_dataset()

    print("[+] Training model...")
    model, X_test = train_model(X, y)

    print("[+] Saving model...")
    joblib.dump(model, MODEL_PATH)
    print(f"[✓] Model saved at: {MODEL_PATH}")

    explain_with_shap(model, X_test.iloc[[0]])

if __name__ == "__main__":
    main()
