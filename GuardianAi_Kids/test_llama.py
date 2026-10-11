import subprocess
import json
import os

req = {
    "model": "gemma-4-E2B-it-Q4_K_M.gguf",
    "messages": [
        {"role": "user", "content": "Explain in 1 short kid-friendly sentence why never to click unknown links. Be brief."}
    ],
    "max_tokens": 350,
    "temperature": 0.1
}

with open("scratch_req.json", "w") as f:
    json.dump(req, f)

adb = r"C:\Users\welcome\AppData\Local\Android\Sdk\platform-tools\adb.exe"
subprocess.run([adb, "push", "scratch_req.json", "/data/local/tmp/scratch_req.json"], check=True)

cmd = [adb, "shell", "curl -s -X POST http://127.0.0.1:8080/v1/chat/completions -H 'Content-Type: application/json' -d @/data/local/tmp/scratch_req.json"]
res = subprocess.run(cmd, capture_output=True, text=True)
print("Response:\n", res.stdout)
if res.stderr:
    print("Stderr:\n", res.stderr)

if os.path.exists("scratch_req.json"):
    os.remove("scratch_req.json")
