# ransomware_detection_prototype.py

import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix
import joblib
import streamlit as st

DATA_PATH = 'Final_Dataset_without_duplicate.csv'
MODEL_PATH = 'ransomware_rf.pkl'

@st.cache_data
def load_data():
    df = pd.read_csv(DATA_PATH)
    # Remove non-feature columns
    columns_to_drop = ['md5', 'sha1', 'file_extension', 'Class', 'Category', 'Family']
    X = df.drop(columns=columns_to_drop)
    
    # Convert hex values and other object columns to numeric where possible
    for col in X.columns:
        if X[col].dtype == 'object':
            # Try to convert hex values (like 0x1c61) to decimal
            try:
                X[col] = X[col].apply(lambda x: int(str(x), 16) if isinstance(x, str) and str(x).startswith('0x') else x)
                X[col] = pd.to_numeric(X[col], errors='coerce')
            except:
                X[col] = pd.to_numeric(X[col], errors='coerce')
    
    # Select only numeric columns and fill NaN values
    X = X.select_dtypes(include=['number']).fillna(0)
    y = df['Class']
    return X, y

def train_model():
    X, y = load_data()
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
    clf = RandomForestClassifier(n_estimators=100, random_state=42)
    clf.fit(X_train, y_train)
    y_pred = clf.predict(X_test)
    print("Confusion Matrix:")
    print(confusion_matrix(y_test, y_pred))
    print("Classification Report:")
    print(classification_report(y_test, y_pred))
    joblib.dump(clf, MODEL_PATH)
    print(f"Model saved to {MODEL_PATH}")

def run_app():
    st.set_page_config(
        page_title="Ransomware Detector",
        page_icon=":rabbit2:",
        layout="centered",
        menu_items={
            "Get Help": "https://your-help-link.com",
            "Report a bug": "https://your-bug-link.com",
            "About": "# Ransomware Detector\nA prototype app."
        }
    )
    st.title("Ransomware Detection Prototype")
    uploaded = st.file_uploader("Upload CSV feature file for prediction", type="csv")
    if uploaded is not None:
        df = pd.read_csv(uploaded)
        
        # Apply same preprocessing as training
        columns_to_drop = ['md5', 'sha1', 'file_extension', 'Class', 'Category', 'Family']
        # Only drop columns that exist in the uploaded file
        existing_columns_to_drop = [col for col in columns_to_drop if col in df.columns]
        X = df.drop(columns=existing_columns_to_drop)
        
        # Convert hex values and other object columns to numeric where possible
        for col in X.columns:
            if X[col].dtype == 'object':
                try:
                    X[col] = X[col].apply(lambda x: int(str(x), 16) if isinstance(x, str) and str(x).startswith('0x') else x)
                    X[col] = pd.to_numeric(X[col], errors='coerce')
                except:
                    X[col] = pd.to_numeric(X[col], errors='coerce')
        
        # Select only numeric columns and fill NaN values
        X = X.select_dtypes(include=['number']).fillna(0)
        
        clf = joblib.load(MODEL_PATH)
        preds = clf.predict(X)
        probabilities = clf.predict_proba(X)
        
        # Add predictions to the original dataframe
        df['prediction'] = preds
        df['benign_probability'] = probabilities[:, 0]
        df['ransomware_probability'] = probabilities[:, 1]
        df['is_ransomware'] = df['ransomware_probability'].apply(lambda x: 'Ransomware' if x > 0.5 else 'Safe')
        
        st.write("## Prediction Results")
        st.write(f"Total files analyzed: {len(df)}")
        st.write(f"Predicted as Benign: {sum(preds == 'Benign')}")
        st.write(f"Predicted as Malware: {sum(preds == 'Malware')}")
        
        st.write("## Detailed Results")
        display_cols = ['md5', 'prediction', 'benign_probability', 'ransomware_probability', 'is_ransomware']
        st.dataframe(df[display_cols] if 'md5' in df.columns else df, use_container_width=True)

    # Warning notice
    st.markdown(
        """
        <div style='background-color: #0e1117; color:#dd3a52; padding:12px; border-radius:60px; border: 1px solid #rgb(37, 45, 61); text-align:center; font-weight:bold; font-size:18px;'>
            Note: This is a prototype for research/demo purposes only. Results may not be 100% accurate and should not be used for real-world security decisions.
        </div>
        """,
        unsafe_allow_html=True
    )

    # FAQ Section (always visible)
    st.markdown("""
---
## ❓ FAQ: Ransomware Detection Model

**Q1: What dataset is used to train this model?**  
- The model is trained on a labeled dataset ([Data set](https://zenodo.org/records/13890887))) containing thousands of samples of both ransomware and benign files. Each sample includes static and behavioral features extracted from executable files.

**Q2: What are the main features the model uses to decide if a file is ransomware?**  
- The model uses a combination of:
    - **Malicious process activity** (number of suspicious/malicious processes spawned)
    - **File system changes** (number of malicious/suspicious/unknown files created)
    - **Registry activity** (number of registry reads/writes/deletes)
    - **Network activity** (DNS/HTTP connections, network threats)
    - **PE file structure features** (section sizes, entry points, image base, etc.)
- Ransomware samples typically have much higher values in these behavioral features compared to benign files.

**Q3: How does the model make a decision?**  
- The model is a Random Forest classifier. It evaluates all features for each file and combines the results from 100 decision trees to predict if a file is benign or ransomware.

**Q4: What probability (percentage) decides if a file is ransomware or benign?**  
- The model outputs a probability for each class (benign and ransomware). By default, if the ransomware probability is **greater than 50% (0.5)**, the file is classified as ransomware. If the benign probability is higher, it is classified as benign.
- The app also shows the exact probability for each prediction so you can see how confident the model is.

**Q5: How can I test my own files?**  
- Prepare a CSV file with the same feature columns as the training data (excluding hashes and labels).
- Upload the file using the uploader above. The app will show the prediction and confidence for each sample.

---
    """, unsafe_allow_html=True)
    # Footer with your links and icons
    st.markdown("""
---
<div style='text-align: center; font-weight:bold; color: #555;'>
    Made by <b>UKI</b><br>
    <a href="https://github.com/ukihunter" target="_blank" style="margin-right: 16px;">
        <img src="https://cdn.jsdelivr.net/gh/devicons/devicon/icons/github/github-original.svg" alt="GitHub" width="28" style="vertical-align:middle;"/>
    </a>
    <a href="https://www.linkedin.com/in/uthpala-wijekoon-871296311/" target="_blank">
        <img src="https://img.icons8.com/ios-filled/50/1A1A1A/linkedin.png" alt="LinkedIn" width="28" style="vertical-align:middle;"/>
    </a>
</div>
""", unsafe_allow_html=True)
if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1 and sys.argv[1] == 'train':
        train_model()
    else:
        run_app()
