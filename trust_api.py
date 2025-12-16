import joblib
import pandas as pd
import numpy as np
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import uvicorn
from collections import deque

app = FastAPI(title="Advanced Trust Assessment API", version="1.0")


MODEL_FILE = "trust_model_advanced.pkl"
SCALER_FILE = "scaler_advanced.pkl"
COLS_FILE = "feature_columns.pkl"

model = None
scaler = None
feature_cols = None

# Used to store the most recent N samples to compute the rolling features.
WINDOW_SIZE = 5
history_buffer = deque(maxlen=WINDOW_SIZE)

# define labels
LABEL_MAP = {
    0: "DANGER (DoS)",
    1: "WARNING (BruteForce/Spoof)",
    2: "SUSPICIOUS (Scan)",
    3: "TRUSTED (Normal)"
}


class RawFeatures(BaseModel):
    cpu_usage: float
    mem_usage: float
    bytes_in: float
    bytes_out: float
    packets_in: float
    packets_out: float
    tcp_count: int
    udp_count: int
    icmp_count: int
    arp_count: int
    arp_ratio: float
    syn_count: int
    syn_ratio: float
    psh_count: int
    psh_ratio: float
    port_diversity: float
    ack_count: int
    fin_count: int
    rst_count: int
    fragmented_count: int
    unique_src_ips: int
    unique_dst_ports: int
    avg_packet_size: float


@app.on_event("startup")
def load_artifacts():
    global model, scaler, feature_cols

    model = joblib.load(MODEL_FILE)
    scaler = joblib.load(SCALER_FILE)
    feature_cols = joblib.load(COLS_FILE)
    print(f"Advanced Model Loaded. Feature Count: {len(feature_cols)}")
    
    

@app.post("/predict")
def predict_advanced(raw_data: RawFeatures):
    global history_buffer
    
    try:
        if model is None:
            raise HTTPException(status_code=503, detail="Model not loaded")

        # 1. receive raw datas.
        input_dict = raw_data.model_dump()
        
        # 2. Adds the current frame to the history buffer.
        history_buffer.append(input_dict)
        
        # 3. It needs to be calculated with all the data in the buffer, but only for the current frame.
        df_history = pd.DataFrame(list(history_buffer))
        
        # 4. Compute scrolling features in real time.
        target_cols = ['port_diversity', 'syn_ratio', 'psh_ratio', 'arp_ratio', 'bytes_out']
        
        
        # If the buffer is less than 5, rolling mean produces NaN, and we fill in 0.
        for col in target_cols:
            # Calculate mean/std for the entire buffer.
            roll_mean = df_history[col].rolling(window=WINDOW_SIZE, min_periods=1).mean()
            roll_std = df_history[col].rolling(window=WINDOW_SIZE, min_periods=1).std()
            
            
            df_history[f'{col}_mean_{WINDOW_SIZE}'] = roll_mean
            df_history[f'{col}_std_{WINDOW_SIZE}'] = roll_std
            
        df_history.fillna(0, inplace=True)
        
        # 5. The data of the current frame is extracted for prediction
        current_row = df_history.iloc[[-1]] 
        
        # 6. Alignment
        
        X_final = current_row.reindex(columns=feature_cols, fill_value=0)
        
        # 7. Standardization
        X_scaled = scaler.transform(X_final)
        
        # 8. Predict
        pred_idx = int(model.predict(X_scaled)[0])
        probs = model.predict_proba(X_scaled)[0]
        confidence = float(np.max(probs))
        
        # 9. Return results
        return {
            "trust_level": pred_idx,
            "description": LABEL_MAP[pred_idx],
            "confidence": confidence,
            "features_snapshot": {
                "port_div": input_dict['port_diversity'],
                "port_div_mean_5s": float(current_row[f'port_diversity_mean_{WINDOW_SIZE}'].iloc[0])
            }
        }

    except Exception as e:
        import traceback
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=str(e))

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000, log_level="warning")