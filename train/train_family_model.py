import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder
from sklearn.metrics import classification_report, confusion_matrix, precision_score, recall_score, f1_score
import joblib
import os
import seaborn as sns
import matplotlib.pyplot as plt
from lightgbm import LGBMClassifier  # You can replace with RandomForest if you prefer

# ==== Config ====
DATA_FILE = "data/family.csv"
MODEL_OUTPUT = "models/family_model2.pkl"
ENCODER_OUTPUT = "models/family_label_encoder2.pkl"
CONFUSION_MATRIX_PNG = "models/family_confusion_matrix.png"

# ==== Load & Prepare ====
def load_and_prepare_data():
    print("[+] Loading dataset...")
    df = pd.read_csv(DATA_FILE)

    print("[+] Filtering for malware samples...")
    malware_df = df[df["label"] == 1].copy()
    if malware_df.empty:
        raise ValueError("No malware samples found with label == 1.")

    print("[+] Encoding family labels...")
    le = LabelEncoder()
    malware_df["family_encoded"] = le.fit_transform(malware_df["family"])

    os.makedirs("models", exist_ok=True)
    joblib.dump(le, ENCODER_OUTPUT)
    print(f"[✓] Label encoder saved to: {ENCODER_OUTPUT}")

    X = malware_df.drop(columns=["filename", "label", "family", "family_encoded"])
    y = malware_df["family_encoded"]

    return train_test_split(X, y, test_size=0.2, stratify=y, random_state=42), le, X.columns

# ==== Train & Evaluate ====
def train_and_evaluate(X_train, X_test, y_train, y_test, le, feature_names):
    print("[+] Training malware family classifier...")
    model = LGBMClassifier(n_estimators=300, learning_rate=0.05, max_depth=10, random_state=42)
    model.fit(X_train, y_train)

    print("[+] Evaluating model...")
    y_pred = model.predict(X_test)

    print("\n[📊] Classification Report:")
    print(classification_report(y_test, y_pred, target_names=le.classes_))

    print("🎯 Precision (macro):", precision_score(y_test, y_pred, average="macro"))
    print("🔁 Recall (macro):   ", recall_score(y_test, y_pred, average="macro"))
    print("🏆 F1 Score (macro): ", f1_score(y_test, y_pred, average="macro"))

    print("\n[📉] Confusion Matrix:")
    cm = confusion_matrix(y_test, y_pred)
    print(cm)

    # ==== Confusion Matrix Heatmap ====
    plt.figure(figsize=(10, 6))
    sns.heatmap(cm, annot=True, fmt="d", xticklabels=le.classes_, yticklabels=le.classes_, cmap="Blues")
    plt.xlabel("Predicted")
    plt.ylabel("True")
    plt.title("Malware Family Confusion Matrix")
    plt.tight_layout()
    plt.savefig(CONFUSION_MATRIX_PNG)
    print(f"[✓] Confusion matrix saved to: {CONFUSION_MATRIX_PNG}")

    # ==== Feature Importance ====
    importances = model.feature_importances_
    print("\n🔥 Top Features:")
    sorted_idx = importances.argsort()[::-1]
    for i in range(min(10, len(importances))):
        print(f"{feature_names[sorted_idx[i]]}: {importances[sorted_idx[i]]:.4f}")

    joblib.dump(model, MODEL_OUTPUT)
    print(f"[✓] Model saved to: {MODEL_OUTPUT}")

# ==== Main ====
def main():
    (X_train, X_test, y_train, y_test), le, feature_names = load_and_prepare_data()
    train_and_evaluate(X_train, X_test, y_train, y_test, le, feature_names)

if __name__ == "__main__":
    main()
