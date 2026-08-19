# Connecting to the Arena — account + WireGuard setup

## 0. Your arena account

Your instructor gives you your account for the ZCR Security Arena (`ctf.zcr.ai`) —
you don't sign up yourself. You'll receive a slip with a **username and a
temporary password**. Log in at `ctf.zcr.ai`, then change the password
(top-right menu → Settings).

**Your username is your student ID, and it has to stay that way.** The arena
issues every challenge flag *individually to your username* — your flag for a
challenge is different from the person's next to you. That is also how your work
gets matched to your marks, so a changed username silently breaks the link
between the two. Everything else on your profile is yours to edit.

If you ever do create an account yourself (a replacement, a second cohort),
**use your student ID as the username** for the same reason.

---

Some challenges in the arena run on a private network — you
reach them through a VPN (WireGuard), not a public URL. This is the same reason your
bank's app doesn't put your account balance on a public web page: the challenge boxes are
deliberately vulnerable, so they stay off the open internet and only your own VPN tunnel
can reach them.

Your instructor will give you a file named `<your_student_id>.conf`. Treat it like a
password — don't post it, don't send it to classmates, don't paste it into a chat. It is
what proves the challenge instance is yours.

## 1. Install a WireGuard client

Pick the one for your device — all are free, official, from wireguard.com:

| Platform | Where |
|---|---|
| Windows | [WireGuard for Windows](https://www.wireguard.com/install/) |
| macOS | [App Store — "WireGuard"](https://apps.apple.com/us/app/wireguard/id1451685025) |
| Linux | `sudo apt install wireguard` (or your distro's package manager) |
| Android / iOS | Search "WireGuard" in Google Play / the App Store |

## 2. Import your config

- **Desktop app**: open WireGuard → "Import tunnel(s) from file" → select your `.conf`.
- **Phone app**: use the app's "Scan from QR code" if your instructor shows one, or
  "Import from file".

## 3. Connect

Click/tap the toggle to activate the tunnel. You should see a small amount of data
transferred within a few seconds (the app usually shows this) — that means the connection
to the arena is live.

## 4. Reach your challenge

In CTFd, when you start a challenge instance it gives you a connection string like:

```
10.66.0.1:30123
```

With the VPN connected, open that address in your browser (for HTTP challenges) or the
tool the challenge asks for. Without the VPN connected, that address will simply time out
— that's expected, it means the isolation is working correctly.

## A note on privacy between students

While connected, you can technically reach the entire range of ports the arena uses for
challenges, not just your own instance. **Do not scan, probe, or connect to ports other
than the one your own challenge instance gave you.** This is the same rule as not reading
someone else's exam paper — treat other students' running instances as off-limits, even
though the network layer doesn't block it for you. Doing so is an academic integrity
violation, same as flag sharing.

## Troubleshooting

- **Nothing loads at all, even the connection toggle does nothing**: some campus/hotel
  WiFi blocks WireGuard's UDP port. Try mobile data or a different network.
- **VPN connects but the challenge address still times out**: confirm you copied the
  address exactly (including the port after the `:`), and that your CTFd challenge
  instance hasn't expired (it says a countdown on the challenge page — restart it if so).
- **Starting a challenge instance says you already have one running**: this can happen
  even right after you stopped it — the stop request can silently fail to register. Wait
  about 60 seconds and retry, or ask your instructor to clear your stuck instance.
- **Still stuck**: message your instructor with your student ID and what you tried — don't
  share your `.conf` file to get help, a screenshot of the error is enough.
