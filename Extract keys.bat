@echo off
"C:\python27\python.exe" walletaid.py
IF ERRORLEVEL 1 (
	CLS
	walletaid.py
)
IF ERRORLEVEL 1 (
	CLS
	python walletaid.py
)
IF ERRORLEVEL 1 (
	CLS
	ECHO Check if Python 2.7 is installed
	PAUSE
)