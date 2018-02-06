@echo off
python walletaid.py
IF ERRORLEVEL 1 (
	CLS
	"C:\python27\python.ee" walletaid.py
)
if ERRORLEVEL 1 (
	CLS
	ECHO Check Python install
)
@pause