# Threat Model — Week 1 Sample Flask App

## Part 1 — Student Information
**Name:** Pirisa Kitichai  **Student ID:** 6631503031 **Date:** 15/08/2026  

## Part 2 — Lecture Questions
### 1. CIA Triad
CIA คือ Confidentiality, Integrity และ Availability  
พวก ข้อมูลรั่วไหล, ข้อมูลถูกแก้ไขโดยไม่ได้รับอนุญาต และระบบใช้งานไม่ได้จากการโจมตี DoS

### 2. Trust Boundary
Trust boundary คือจุดที่ข้อมูลข้ามระหว่างส่วนของระบบที่มีระดับความน่าเชื่อถือต่างกัน  
ข้อมูลที่ข้ามจุดนี้ควรถูกตรวจสอบ เพราะอาจเป็นข้อมูลอันตรายจากผู้ใช้หรือผู้โจมตี

### 3. Attack Surface
Attack surface คือทุกจุดของระบบที่ผู้โจมตีสามารถเข้าถึงหรือส่งข้อมูลเข้าไปได้  
ตัวอย่างที่ทำให้ attack surface เพิ่มขึ้นคือ API endpoint และระบบอัปโหลดไฟล์

### 4. STRIDE
S = Spoofing (Authentication), T = Tampering (Integrity), R = Repudiation (Non-repudiation)  
I = Information Disclosure (Confidentiality), D = Denial of Service (Availability), E = Elevation of Privilege (Authorization)

### 5. Secure by Design
Secure by Design คือการออกแบบระบบโดยคำนึงถึงความปลอดภัยตั้งแต่เริ่มต้น  
ดีกว่าการรอให้ระบบเสร็จหรือเกิดช่องโหว่แล้วค่อยเพิ่มความปลอดภัยภายหลัง

## Task 0 — Onboarding

The sample Flask application was started successfully using Docker.  
The `/notes` endpoint returned the sample note and `/files/demo.txt` returned the expected file content.

![Task 0 Onboarding](img/task0-onboarding.png)

## 1. Data-flow diagram

![Task 1 DFD](img/task1-dfd.png)

## 2. Elements & trust boundaries
| Element | Type (process/store/entity/flow) | Trust boundary crossed? |
|---|---|---|
| Web client | external entity | yes (Internet → app) |
| Flask app | process | yes (receives Internet → app requests) |
| SQLite DB (`notes.db`) | data store | no |
| `uploads/` | data store | no |

## 3. STRIDE analysis
### Task 2 — STRIDE Analysis

The application should authenticate users and derive the note owner from the authenticated identity instead of trusting the client-supplied `owner` value. File uploads should use a validated or server-generated filename, and the application should add audit logging and resource limits to reduce repudiation and denial-of-service risks.

| Element | S | T | R | I | D | E |
|---|---|---|---|---|---|---|
| `/notes` | Client can spoof another user by supplying any `owner` value because there is no authentication. | A client can insert arbitrary note content into the database. | There is no logging, so actions cannot be reliably tied to a real user. | `GET /notes` returns all stored notes without access control. | Repeated POST requests could grow the database and consume resources. | No explicit authorization exists, so a client may perform actions that should require a trusted identity. |
| `/upload` | The uploader is not authenticated, so the server cannot verify who submitted a file. | `f.filename` is used directly in the save path, so user-controlled input influences filesystem writes. | There is no audit logging for uploads. | The response reveals the accepted filename and the upload behavior may expose information about server-side file handling. | Large or repeated uploads could consume disk space. | If file writes reach unintended locations, the impact could extend beyond the intended upload directory. |
| `/files/<name>` | No authentication is required to request a file. | This endpoint is read-only, so direct tampering risk is lower than `/upload`. | File access is not logged. | Anyone who knows a filename may be able to retrieve the uploaded file. | Repeated file requests could consume server resources. | Direct privilege escalation is limited here because `send_from_directory()` constrains file reads to the upload directory. |

## Task 3 — Elevation of Privilege Game

I used the digital Elevation of Privilege (EoP) deck and drew five cards. I tied a card to my DFD only when the threat could honestly be connected to a real element or data flow in the sample application.

| Card | STRIDE | Result | Element / Flow | Finding |
|---|---|---|---|---|
| Denial of Service 3 | Denial of Service | Pass | — | The card describes draining an easily replaceable battery. The sample Flask application has no battery-powered component represented in the DFD, so there is no honest match. |
| Elevation of Privilege 5 | Elevation of Privilege | Valid (+1) | `/upload` → `uploads/` → `/files/<name>` | Filename/path data goes through different handling paths. `/upload` uses the client-supplied `f.filename` when saving, while `/files/<name>` uses `send_from_directory()` to constrain file reads. This inconsistent validation can create a security gap. |
| Denial of Service 10 | Denial of Service | Valid (+1) | `/upload` → `uploads/` | `/upload` accepts unauthenticated file uploads without an explicit upload-size or resource limit. Repeated uploads could consume persistent disk space, so the impact may remain after the attacker stops sending requests. |
| Denial of Service 7 | Denial of Service | Pass | — | The card describes making a client unavailable with a persistent effect. The analyzed Flask application does not provide a clear mechanism for causing this persistent client-side denial of service. |
| Denial of Service 6 | Denial of Service | Valid (+1) | Flask App / public endpoints | The application exposes endpoints without authentication or rate limiting. A large number of requests could temporarily consume server resources and reduce availability, with the effect ending when the request flood stops. |

**Cards Drawn:** 5  
**Tied to My DFD:** 3  
**Total Score:** 3

### Task 3 Summary

Three of the five drawn cards could be honestly connected to the sample application's DFD. The valid findings showed inconsistent filename/path handling and two denial-of-service risks: persistent resource consumption through file uploads and temporary server resource exhaustion through unauthenticated requests. The other two cards were passed because their threats could not be reasonably connected to the system.

## Task 3b — Systems-level Pass

### 1. Trust boundaries end-to-end

A request to `/notes` starts from the untrusted web client and crosses the Internet-to-application trust boundary before reaching the Flask application. The Flask application then accesses `notes.db` to store or retrieve note data, and the response travels back through the application to the client.

The most important unchecked crossing is the Internet → Flask application boundary. The application accepts the client-supplied `owner` value without authentication or authorization, so untrusted input is treated as if it represents a valid identity.

### 2. Owned-element reachability

**If the Flask process is fully compromised:**  
An attacker could reach both `notes.db` and the `uploads/` directory because the Flask process has legitimate access to both data stores. This could allow the attacker to read or modify notes and access or modify uploaded files.

**If the `uploads/` store is fully compromised:**  
An attacker could control files stored in the upload directory. Since `/files/<name>` serves files from this directory, attacker-controlled content could potentially be returned to clients through the Flask application.

### 3. Chain two low findings

Missing authentication on `/upload` → unrestricted repeated uploads → disk space is exhausted and the application becomes unavailable.

Another possible chain is:

Predictable/known uploaded filename → unauthenticated `/files/<name>` access → unauthorized disclosure of uploaded file contents.

### 4. One-line system claim

Even if every element-level mitigation in Task 8 is implemented, this system still fails if a compromised Flask process retains unrestricted access to both the database and uploaded files.

## Task 4 — Abuse Cases & Attacker Personas

### Persona 1 — Curious User

This attacker is a normal user who can access the web application but is curious about data belonging to other users. The attacker does not have administrative access and only interacts with the exposed application endpoints.

**Abuse Case 1 — Impersonating another note owner**  
The user sends a request to `/notes` and supplies another person's name in the `owner` field. Because the application does not authenticate the supplied owner, the Flask App accepts the value and stores the note in `notes.db` as if it belonged to that person.

**DFD elements:** Web Client → `/notes` → Flask App → `notes.db`

**Abuse Case 2 — Reading other users' notes**  
The user sends `GET /notes` and receives all notes stored in `notes.db`. Since there is no authentication or per-user authorization check, the user may see notes that were created by other users.

**DFD elements:** Web Client → `/notes` → Flask App → `notes.db`

### Persona 2 — Anonymous Internet Attacker

This attacker has no account and accesses the Flask application from the untrusted Internet. Their goal is to misuse publicly reachable endpoints without needing authentication.

**Abuse Case 3 — Uploading uncontrolled files**  
The attacker sends files to `/upload`. The application accepts the upload without authentication and uses the client-controlled `f.filename` when creating the filesystem path, allowing untrusted input to influence writes to the file store.

**DFD elements:** Web Client → `/upload` → Flask App → `uploads/`

**Abuse Case 4 — Consuming application resources**  
The attacker repeatedly sends uploads or other requests to the application. Because the application has no visible rate limiting or upload-size controls, repeated requests could consume disk or server resources and reduce availability.

**DFD elements:** Web Client → Flask App → `uploads/`

## Task 5 — Path-Traversal Deep Dive

### 1. Data Flow

เส้นทางการอัปโหลดไฟล์:

Web Client → `POST /upload` → Flask App → `uploads/`

เส้นทางการอ่านไฟล์:

Web Client → `GET /files/<name>` → Flask App → `uploads/` → Web Client

### 2. ความเสี่ยง

`/upload` ใช้ `f.filename` ที่มาจากผู้ใช้โดยตรงในการสร้าง path สำหรับบันทึกไฟล์ หากชื่อไฟล์มี `../` อาจทำให้ path ออกจากโฟลเดอร์ `uploads/` และเขียนไฟล์ไปยังตำแหน่งที่ไม่ควรได้

ส่วน `/files/<name>` ปลอดภัยกว่าฝั่ง upload เพราะใช้ `send_from_directory()` เพื่อจำกัดการอ่านไฟล์ให้อยู่ใน directory ที่กำหนด

### 3. Secure Design

ควรใช้ `secure_filename()` ตรวจสอบชื่อไฟล์, ใช้ allow-list จำกัดประเภทไฟล์ และเก็บไฟล์ไว้นอก web root นอกจากนี้ควรสร้างชื่อไฟล์ใหม่จากฝั่ง server เช่น UUID แทนการใช้ชื่อไฟล์จากผู้ใช้โดยตรง

### 4. Mitigation

ไม่ควรนำข้อมูลจากผู้ใช้มาเป็นส่วนหนึ่งของ filesystem path โดยตรง การใช้ชื่อไฟล์ที่ server สร้างเองช่วยลดความเสี่ยงของ path traversal และ arbitrary file write

## Task 6 — Threat Model: NoteVault

### DFD

Web Client → Flask App → SQLite DB (`/tmp/notevault.db`)

Main flows:
- Register/Login → Flask App → `users`
- Home/Notes → Flask App → `notes`
- `/api/notes/<id>` → Flask App → `notes`
- `/search` → Flask App → `notes`
- `/admin` → Flask App → `users`
- `/export` → Flask App → shell command

![Task 6 DFD](img/task6-dfd.png)

### Top 3 STRIDE Threats

1. **Elevation of Privilege — Client-controlled role**  
   `/register` accepts the `role` value from the client. An attacker could register with `role=admin` and gain administrator privileges.  
   **Mitigation:** Do not accept roles from the client. New users should always receive the `user` role on the server side.

2. **Information Disclosure — IDOR in `/api/notes/<nid>`**  
   The API checks that the requester is logged in, but does not check whether the requested note belongs to that user. An authenticated user may access another user's note by changing the note ID.  
   **Mitigation:** Check that `owner` matches the authenticated user before returning the note.

3. **Elevation of Privilege / Tampering — Command Injection in `/export`**  
   The `fmt` parameter is concatenated directly into a shell command and executed with `shell=True`. User-controlled input may therefore affect the command executed by the server.  
   **Mitigation:** Avoid `shell=True` and validate `fmt` against a fixed allow-list such as `txt` or `json`.

## Task 7 — Security Requirements

1. **The system must assign user roles only on the server side so that a client cannot register itself as an administrator.**
   - Mapped threat: Elevation of Privilege in `/register`

2. **The system must verify that a requested note belongs to the authenticated user before returning it so that users cannot read other users' notes.**
   - Mapped threat: Information Disclosure / IDOR in `/api/notes/<nid>`

3. **The system must validate untrusted input and avoid passing user-controlled values directly into SQL queries or shell commands so that injection attacks cannot alter application behavior.**
   - Mapped threat: Tampering / Injection in `/search` and `/export`

## Task 8 — Top 5 Risks and Mitigations

| Rank | Threat | Likelihood | Impact | Risk Score | Mitigation |
|---|---|---:|---:|---:|---|
| 1 | Client can spoof the `owner` in `/notes` because there is no authentication | 5 | 5 | 25 | Require authentication and derive the owner from the authenticated user |
| 2 | `/upload` uses the client-controlled filename as part of the filesystem path | 4 | 5 | 20 | Use `secure_filename()`, an extension allow-list, and preferably a server-generated filename |
| 3 | `GET /notes` returns all notes without access control | 4 | 4 | 16 | Require authentication and return only notes the user is authorized to view |
| 4 | The application has no audit logging | 4 | 3 | 12 | Add structured audit logs for authentication, note creation, uploads, and file access |
| 5 | There are no request-rate or upload-size limits | 3 | 4 | 12 | Add rate limiting, upload-size limits, and storage quotas |

### Implemented Fix

I selected the unsafe file upload handling in `/upload` for mitigation.

**Before:** The application accepted `test.exe` and returned:

`{"saved":"test.exe"}`

**Fix:** The upload endpoint now uses `secure_filename()` and an allow-list of permitted file extensions (`.txt`, `.png`, `.jpg`, `.jpeg`, `.pdf`).

**After:** The same `test.exe` upload was rejected and returned:

`{"error":"file type not allowed"}`

**Commit:** `bea3ba7`

### Fix Scope

This is mainly an instance-level fix because it protects the `/upload` endpoint specifically. A stronger class-level fix would ensure that user-controlled input is never used directly as a filesystem path component and that stored filenames are generated by the server.

### Evidence

**Before fix:**

![Task 8 Before Fix](img/task8-before.png)

The original `/upload` endpoint accepted `test.exe` and returned `{"saved":"test.exe"}`.

**After fix:**

![Task 8 After Fix](img/task8-after.png)

After applying the mitigation and rebuilding the application, the same upload was rejected with `{"error":"file type not allowed"}`.

## Part 4 — Reflection

### 1. CWE and OWASP A06 Mapping

My top finding is the unsafe file upload path in `/upload`, where a user-controlled filename is used as part of a filesystem path. This maps to CWE-501 (Trust Boundary Violation) and OWASP A06 Insecure Design because untrusted user input crosses into a trusted filesystem operation without sufficient validation.

### 2. Real-world Breach

A real-world example is the 2019 Capital One breach, where weaknesses in the system's cloud security design allowed access to sensitive data. A stronger least-privilege design and tighter access controls between system components could have reduced the impact.

### 3. Best Mitigation

The most effective mitigation for the effort required is securing `/upload` by validating filenames, restricting allowed file types, and avoiding direct use of user-controlled filenames as filesystem paths. This requires a relatively small code change but reduces the risk of unauthorized file writes significantly.


## Comprehension & Prompt

### A. Explain in Plain English (EiPE)

`/upload` รับไฟล์จากผู้ใช้และนำชื่อไฟล์ที่ผู้ใช้ส่งมาไปใช้ตอนบันทึกไฟล์โดยตรง ปัญหาคือชื่อไฟล์นั้นไม่ได้ถูกตรวจสอบอย่างเพียงพอ ทำให้ชื่อไฟล์ที่เป็นอันตรายอาจทำให้ระบบเขียนไฟล์ไปยังตำแหน่งที่ไม่ได้ตั้งใจได้

### B. Prompt Problem

**Final Prompt:**

ช่วยแก้ endpoint `/upload` ของ Flask application ให้ปลอดภัยจากการใช้ชื่อไฟล์ที่ผู้ใช้ควบคุมโดยตรง โดยใช้ `secure_filename()` ตรวจสอบชื่อไฟล์ และใช้ allow-list อนุญาตเฉพาะ `.txt`, `.png`, `.jpg`, `.jpeg`, และ `.pdf` หากไฟล์ไม่อยู่ในประเภทที่อนุญาตให้ตอบกลับด้วย HTTP 400 โดยไม่บันทึกไฟล์

**Verified Result:**

ก่อนแก้ไข ระบบยอมรับ `test.exe` และตอบกลับ:

`{"saved":"test.exe"}`

หลังแก้ไขและ rebuild application แล้ว ทดสอบด้วย request เดิม ระบบตอบกลับ:

`{"error":"file type not allowed"}`

ดังนั้นการแก้ไขทำงานตามที่ต้องการ เพราะไฟล์ประเภทที่ไม่ได้รับอนุญาตถูกปฏิเสธและไม่ถูกบันทึก

## Audit the AI

### 1. AI Answer

ฉันถาม AI ว่า:

> ช่วยแก้ Flask `/upload` endpoint ให้ปลอดภัยจาก path traversal โดยใช้ `secure_filename()` และอธิบายว่าการแก้นี้เพียงพอหรือไม่

AI ตอบว่า:

```python
from werkzeug.utils import secure_filename

@app.route("/upload", methods=["POST"])
def upload():
    f = request.files["file"]

    filename = secure_filename(f.filename)
    if not filename:
        return {"error": "invalid filename"}, 400

    f.save(os.path.join(UPLOAD_DIR, filename))
    return {"saved": filename}
```

AI อธิบายว่า `secure_filename()` ช่วยลดความเสี่ยง path traversal เพราะปรับชื่อไฟล์ให้ปลอดภัยขึ้นก่อนนำไปประกอบเป็น path แต่การแก้นี้ยังไม่เพียงพอทั้งหมด และควรเพิ่ม allow-list ของประเภทไฟล์ จำกัดขนาดไฟล์ และให้ server สร้างชื่อไฟล์เอง

### 2. สิ่งที่ยังไม่เพียงพอ

จุดที่ยังไม่เพียงพอคือโค้ดของ AI ใช้เพียง:

> `filename = secure_filename(f.filename)`

แม้จะช่วยจัดการชื่อไฟล์ที่ไม่ปลอดภัย แต่โค้ดยังไม่ได้ตรวจสอบประเภทไฟล์ ดังนั้นผู้ใช้ยังสามารถอัปโหลดไฟล์ประเภทที่ระบบไม่ต้องการได้ เช่น `.exe`

### 3. Correct and Verified Version

ฉันแก้เพิ่มเติมโดยใช้ `secure_filename()` ร่วมกับ allow-list:

```python
filename = secure_filename(f.filename)

if not filename:
    return {"error": "invalid filename"}, 400

allowed = {".txt", ".png", ".jpg", ".jpeg", ".pdf"}
ext = os.path.splitext(filename)[1].lower()

if ext not in allowed:
    return {"error": "file type not allowed"}, 400

f.save(os.path.join(UPLOAD_DIR, filename))
```

ฉันทดสอบก่อนแก้และพบว่า `test.exe` ถูกยอมรับ:

`{"saved":"test.exe"}`

หลังจากแก้และ rebuild ระบบแล้ว request เดิมถูกปฏิเสธ:

`{"error":"file type not allowed"}`

ดังนั้นคำตอบ AI เดิมช่วยลดความเสี่ยง path traversal ได้ แต่ยังเป็นการแก้ที่ไม่ครอบคลุม policy ของการอัปโหลดไฟล์ ฉันจึงเพิ่ม allow-list และตรวจสอบผลด้วย request เดิมก่อนและหลังการแก้ไข