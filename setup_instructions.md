# NetraAI Platform: Local Setup & Troubleshooting Guide

This guide contains the exact step-by-step instructions to start, shut down, and troubleshoot your NetraAI local VM dashboard and services.

---

## 🚀 Daily Startup Routine

Follow these steps in order to start the platform and open the dashboard:

### Step 1: Start Minikube & Verify Pods (In MobaXterm VM Terminal)
1. If your VM terminal has corporate proxy variables active, clear them so they don't interfere with local Kubernetes commands:
   ```bash
   unset http_proxy
   unset https_proxy
   unset HTTP_PROXY
   unset HTTPS_PROXY
   ```
2. Start the Kubernetes cluster:
   ```bash
   minikube start
   ```
3. Wait 1–2 minutes, and verify that all pods (especially the gateway) are **`1/1 READY`**:
   ```bash
   kubectl get pods -n netraai
   ```

### Step 2: Start Port-Forwarding on the VM (In MobaXterm VM Terminal)
Run the Kubernetes port-forwarder on the VM to expose the gateway pod:
```bash
kubectl port-forward svc/gateway 8000:8000 -n netraai --address 0.0.0.0
```
*👉 Leave this terminal window open. It must remain running.*

### Step 3: Establish the SSH Tunnel (In a Windows Command Prompt)
1. Open a **Windows Command Prompt** (press the Windows key, type `cmd`, and press Enter).
2. Run the SSH tunnel using a clean port (e.g., `9595`):
   ```cmd
   ssh -L 9595:127.0.0.1:8000 rajdeep@10.63.92.151
   ```
3. Type your VM password when prompted and press Enter.
4. *👉 Leave this Windows Command Prompt open. It will show your logged-in shell prompt.*

### Step 4: Access the Dashboard
Open your web browser on Windows and go to:
👉 **`http://127.0.0.1:9595/dashboard`**

---

## 🛑 Safe Shutdown Routine

To free up CPU and memory resources on your VM when you are done working:

1. **Stop the SSH Tunnel (Windows):** Go to your Windows Command Prompt running the SSH tunnel and type `exit` (or press `Ctrl + C`).
2. **Stop the Port-Forward (VM):** Go to your MobaXterm terminal and press `Ctrl + C`.
3. **Stop Minikube (VM):**
   ```bash
   minikube stop
   ```
   *Your database, campaigns, and files are persistent and will be safely saved.*

---

## 🛠️ Common Troubleshooting

### 1. Error: `Client.Timeout exceeded while awaiting headers`
* **Symptom:** `kubectl get pods` hangs or times out trying to connect to `192.168.49.2:8443`.
* **Cause:** Your terminal's corporate proxy is trying to intercept local Kubernetes traffic.
* **Fix:** Clear the proxy variables in your current VM terminal session:
  ```bash
  unset http_proxy; unset https_proxy; unset HTTP_PROXY; unset HTTPS_PROXY
  ```

### 2. Error: `bind [127.0.0.1]:9595: Address already in use`
* **Symptom:** The Windows SSH command fails to connect, complaining that the port is occupied.
* **Cause:** A leftover background SSH session or another app is holding port `9595` open on Windows.
* **Fix:** Change the local port number in the SSH command to a different 4-digit number (e.g., `9696`, `9797`):
  ```cmd
  ssh -L 9696:127.0.0.1:8000 rajdeep@10.63.92.151
  ```
  Then open the dashboard at `http://127.0.0.1:9696/dashboard`.

### 3. Error: `channel x: open failed: connect failed: Connection refused`
* **Symptom:** The Windows Command Prompt starts printing connection refused messages repeatedly when you open the browser.
* **Cause:** The `kubectl port-forward` command on the VM (Step 2) is not running, or the gateway pods are not fully started yet (`0/1 READY`).
* **Fix:** 
  1. Make sure `kubectl port-forward` is active on the VM.
  2. Run `kubectl get pods -n netraai` to make sure the gateway pods show `1/1 READY`.

### 4. How to Check Gateway Container Logs
If the gateway is acting up, you can inspect its logs by running:
```bash
kubectl logs -n netraai deployment/netraai-gateway --tail=100
```
