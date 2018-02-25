@echo off
walletaid.py
IF ERRORLEVEL 1 (
	CLS
	python walletaid.py
)
IF ERRORLEVEL 1 (
	CLS
	"C:\python27\python.exe" walletaid.py
)
IF ERRORLEVEL 1 (
	CLS
	ECHO Check Python install
	PAUSE
)