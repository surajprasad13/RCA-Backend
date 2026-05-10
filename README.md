# RCA Backend

Local Node.js backend for the RCA demo.

## Start

```bash
cd backend
npm start
```

Defaults:

```text
http://<your-computer-ip>:3000
Admin PIN: 1234
```

If port `3000` is busy:

```bash
PORT=3002 npm start
```

## Two-Device Demo

1. Start this backend on a laptop connected to the same Wi-Fi as both phones.
2. Find the laptop IP address.
3. On the user phone, open RCA -> User -> Server Connection.
4. Enter `http://<laptop-ip>:3000` and tap **Save And Register**.
5. On the admin phone, open RCA -> Admin.
6. Enter the same backend URL and PIN `1234`.
7. Refresh devices, then send `Protect`, `Disable`, `Lock`, or `Unlock`.

The user phone polls the backend from `KioskControlService`, applies pending commands locally, and acknowledges them.
