# Weekly Quiz — Week 13 (Cloud & Container Security)

**~10 min · in-class · 6 questions · low-stakes** (drop lowest). No devices / locked browser.

**Name:** Pirisa Kitichai  **Student ID:** 6631503031

## MCQ (5 × 1)
1. Running a container **as root** is risky because:
   a) it is slower  b) a container escape gives host root  c) it uses more disk  d) logs grow faster
Ans: B

2. Where should secrets **not** live?
   a) a secrets manager  b) baked into image layers / committed env files  c) a vault  d) an injected runtime secret
Ans. B

3. **Least privilege** in cloud IAM means:
   a) one shared admin key  b) grant only the minimum permissions needed  c) disable logging  d) public buckets
Ans: B

4. A security-group rule of `0.0.0.0/0` on a port means:
   a) blocked  b) localhost only  c) open to the entire internet  d) VPN only
Ans: C

5. Container **image scanning** primarily finds:
   a) slow code  b) known CVEs in base image/layers  c) bad indentation  d) missing tests
Ans: B

## Short answer — 🔒 your own work (1 × 3)
6. From the container/cloud lab, name **one misconfiguration you fixed** and the **security principle** it violated.
Ans: I fixed an IAM policy that allowed all actions on all AWS resources. It violated the principle of least privilege, so I restricted access to only the required S3 permissions and resources.
