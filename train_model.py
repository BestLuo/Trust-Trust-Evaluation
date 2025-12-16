import pandas as pd
import numpy as np
import joblib
import xgboost as xgb
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import classification_report, confusion_matrix
from imblearn.combine import SMOTETomek
from imblearn.under_sampling import TomekLinks
from collections import Counter


DATA_FILE = "switch_trust_dataset.csv"
MODEL_FILE = "trust_model_advanced.pkl"
SCALER_FILE = "scaler_advanced.pkl"
COLS_FILE = "feature_columns.pkl" 

def create_rolling_features(df, window_size=5):
    """
    (MST-SW)
    The rolling mean and standard deviation of key features are calculated to capture the timing pattern.
    """
    
    target_cols = ['port_diversity', 'syn_ratio', 'psh_ratio', 'arp_ratio', 'bytes_out']
    
    
    df_rolled = df.copy()
    
    for col in target_cols:
        
        df_rolled[f'{col}_mean_{window_size}'] = df_rolled[col].rolling(window=window_size).mean()
        
        df_rolled[f'{col}_std_{window_size}'] = df_rolled[col].rolling(window=window_size).std()
    
    
    df_rolled.fillna(0, inplace=True)
    return df_rolled

def train():
    print("Loading Dataset...")
    
    df = pd.read_csv(DATA_FILE)
    

    # 1. clean
    df.replace([np.inf, -np.inf], np.nan, inplace=True)
    df.dropna(inplace=True)

    # 2.Construct temporal features
    print(f"Applying Temporal Feature Engineering (Window={5})...")
    df = create_rolling_features(df, window_size=5)

    
    feature_cols = [c for c in df.columns if c != 'label']
    X = df[feature_cols]
    y = df['label']

    print(f"Original Class Distribution: {Counter(y)}")

    # 3. dataset split 
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)

    # 4. Standard 
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)

    # 5. SMOTE-Tomek 
    # This will only be done on the training set, not the test set.
    
    
        
    resampler = SMOTETomek(tomek=TomekLinks(sampling_strategy='majority'), random_state=42)
    X_train_res, y_train_res = resampler.fit_resample(X_train_scaled, y_train)
    
    X_train_res, y_train_res = X_train_scaled, y_train

    # 6. cost sensitive weight
    # The weight of each class is calculated, and the class with fewer samples has a higher weight.
    classes_weights = len(y_train_res) / (len(np.unique(y_train_res)) * np.bincount(y_train_res))
    sample_weights = [classes_weights[label] for label in y_train_res]
    
    


    print("Training Advanced XGBoost Model...")
    model = xgb.XGBClassifier(
        objective='multi:softmax',
        num_class=4,
        n_estimators=300,        
        learning_rate=0.03,     
        max_depth=6,             
        min_child_weight=2,
        gamma=0.2,               
        subsample=0.8,
        colsample_bytree=1.0,
        reg_alpha=0.1,           
        reg_lambda=1.0,          
        n_jobs=-1,
        random_state=42
    )
    

    
    model.fit(X_train_res, y_train_res, sample_weight=sample_weights)

    # 7. Evaluation
    y_pred = model.predict(X_test_scaled)
    acc = model.score(X_test_scaled, y_test)
    
    print("-" * 30)
    print(f" Advanced Model Accuracy: {acc:.4f}")
    print("Classification Report:")
    print(classification_report(y_test, y_pred, target_names=['DoS(0)', 'Brute(1)', 'Scan(2)', 'Normal(3)'], digits=4))
    print(" Confusion Matrix:")
    print(confusion_matrix(y_test, y_pred))

    # 8. save model
    joblib.dump(model, MODEL_FILE)
    joblib.dump(scaler, SCALER_FILE)
    joblib.dump(feature_cols, COLS_FILE)
    print(f"Model saved to {MODEL_FILE}")

if __name__ == "__main__":
    train()