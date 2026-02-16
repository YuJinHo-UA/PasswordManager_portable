
Portable Password Manager (TEST package)
Files included:
- main.py            : application (run with python main.py)
- requirements.txt   : pip dependencies
- admin.key          : SAMPLE admin recovery key (for testing). In real setup store admin.key separately on admin flash drive.
Notes:
- On first run, the app will ask to create a master password and will create dek_wrapped.json and database.db.
- admin.key included here is for TESTING. For a real deployment, place admin.key on a separate USB stick and do NOT keep it in the same folder.
- To build .exe (Windows): pip install pyinstaller; pyinstaller --onefile --icon=icon.ico main.py
