@echo off
"C:\python27\python.exe" getseed.py
IF ERRORLEVEL 1 (
	CLS
	getseed.py
)
IF ERRORLEVEL 1 (
	CLS
	python getseed.py
)
IF ERRORLEVEL 1 (
	CLS
	ECHO Check if Python 2.7 is installed
	PAUSE
)
PAUSE