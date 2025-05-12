# Parsed Packages

These are the unique packages OpenAI models have found after parsing the following datasets:
- lolbas: https://github.com/camsterrrr/raconteur/blob/main/parquet/separated_parquets/lolbas.json
- metta: https://github.com/camsterrrr/raconteur/blob/main/parquet/separated_parquets/metta.json
- ThreatActorProcedures: https://github.com/camsterrrr/raconteur/blob/main/parquet/separated_parquets/ThreatActorProcedures.json

Unique packages are as follows:

```
	Active Directory Domain Services,
	Active Directory Module for Windows PowerShell,
	coreutils,
	Google Chrome,
    Microsoft .NET,
	Microsoft .NET Core,
	Microsoft .NET Framework,
	Microsoft App-V,
	Microsoft Azure,
	Microsoft Build Tools,
	Microsoft Edge,
	Microsoft Office 2016,
	Microsoft Office,
	Microsoft OneDrive,
	Microsoft Publisher,
	Microsoft Silverlight,
	Microsoft SQL Server,
	Microsoft Teams,
	Microsoft Test Authoring and Execution Framework,
	Microsoft Visual Studio,
	Microsoft WCF Data Services,
	Microsoft Web Deploy,
	Mozilla Firefox,
	Native,
	NetSecurity,
	NetTCPIP,
	NodeJS Visual Studio Tools,
	OpenSSH,
	Opera,
	rclone,
	Remote Server Administration Tools,
	SysInternals Suite,
	Unknown,
	Windows Defender,
	Windows Package Manager,
	Windows SDK,
	Windows Subsystem for Linux
```

The script used to parse the datasets can be found here (function: parse_package): https://github.com/camsterrrr/raconteur/blob/main/api/_openai_.py.