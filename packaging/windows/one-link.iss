; ============================================================================
; One Link — Inno Setup installer script (Windows)
;
; Design goals — written down so a future "let's modernize the installer"
; pass doesn't accidentally regress them:
;
;   1. PER-USER install. PrivilegesRequired=lowest + Default install dir
;      under %LOCALAPPDATA% so the installer NEVER triggers a UAC prompt.
;      Asking ordinary users for admin rights to run a chat app is hostile;
;      we don't need admin and we won't pretend to.
;
;   2. NO third-party offers, NO newsletter checkboxes, NO "recommended
;      software" garbage, NO telemetry opt-in pre-checked, NO browser-
;      toolbar nonsense, NO EULA-of-doom. One screen, one install dir
;      picker, install button, done. The whole flow under 10 seconds.
;
;   3. Honest about what we do: install a directory of files, drop a Start
;      Menu shortcut, register an uninstaller. Nothing else. No scheduled
;      tasks, no service registration, no registry hooks beyond Inno's own
;      uninstall bookkeeping. The autostart-at-Windows-boot feature is
;      OPT-IN via the in-app settings — never enabled by the installer.
;
;   4. Reversible. Uninstall removes EVERY file we placed, including the
;      Start Menu shortcut + the autostart Run key entry if it was set.
;
;   5. Auto-launches One Link on install completion (opt-in via the final
;      "Run One Link" checkbox, which Inno shows by default — user can
;      uncheck if they just want it installed for later).
;
; The Windows ARM64 variant uses the same .iss; we override
; ArchitecturesInstallIn64BitMode via the CI invocation so the right
; payload directory ships per-arch.
; ============================================================================

#define MyAppName "One Link"
#define MyAppPublisher "One Unity"
#define MyAppURL "https://weareone-link.org"
#define MyAppExeName "one-link.exe"

; Version + payload dir get overridden by CI via /D flags so a single
; .iss script handles both x86_64 + arm64 + every version cut.
#ifndef MyAppVersion
  #define MyAppVersion "0.0.0-dev"
#endif
; VersionInfoVersion must be a strict 4-part numeric (Windows
; VS_VERSIONINFO contract). MyAppVersion may carry pre-release +
; build-metadata suffixes (``0.21.0-alpha+sha.749cd40``) that fail
; that contract. CI derives both: full for human display, numeric
; for the Windows resource header.
#ifndef MyAppNumericVersion
  #define MyAppNumericVersion "0.0.0.0"
#endif
#ifndef PayloadDir
  #define PayloadDir "..\..\dist\one-link"
#endif
#ifndef OutputBaseName
  #define OutputBaseName "one-link-setup"
#endif
#ifndef OutputDir
  #define OutputDir "..\..\dist"
#endif

[Setup]
AppId={{8F44A2E1-7A0A-4F0B-9E45-1C8C7E5C9D11}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppPublisher={#MyAppPublisher}
AppPublisherURL={#MyAppURL}
AppSupportURL={#MyAppURL}
AppUpdatesURL={#MyAppURL}/releases

; Per-user install: no UAC prompt. The whole point of "for the people,
; not corp" is that an end user can install a chat app on their own
; laptop without their IT department's permission.
PrivilegesRequired=lowest
PrivilegesRequiredOverridesAllowed=

DefaultDirName={localappdata}\Programs\OneLink
DefaultGroupName=One Link

OutputDir={#OutputDir}
OutputBaseFilename={#OutputBaseName}
Compression=lzma2/ultra64
SolidCompression=yes

; UI polish — match the dark/calm tone of the app. No splash screen,
; no animated GIF, no "ULTIMATE EDITION" banner.
WizardStyle=modern
DisableWelcomePage=yes
DisableReadyPage=yes
DisableProgramGroupPage=yes
DisableDirPage=auto
ShowLanguageDialog=no

; Identity + uninstall metadata.
UninstallDisplayName={#MyAppName}
UninstallDisplayIcon={app}\{#MyAppExeName}
SetupIconFile=..\..\src\one_link\web\assets\one-glyph.ico

; Honest version stamp visible in Add/Remove Programs. The
; resource-header VersionInfoVersion needs strict 1.2.3.4 numerics;
; AppVersion above carries the full pre-release-aware string.
VersionInfoVersion={#MyAppNumericVersion}
VersionInfoProductName={#MyAppName}
VersionInfoCompany={#MyAppPublisher}
VersionInfoDescription=Peer-to-peer chat, file sync, and live voice/video. No accounts, no servers.

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
; Desktop shortcut is OPT-IN via this checkbox, not pre-selected. Many
; users find unrequested desktop icons rude; if they want one, they ask.
Name: "desktopicon"; Description: "Create a desktop shortcut"; \
    GroupDescription: "Optional shortcuts:"; Flags: unchecked

[Files]
; The whole PyInstaller payload dir, recursive. excludes drop any stray
; build artifacts (these should never end up in the payload but defense
; in depth costs nothing).
Source: "{#PayloadDir}\*"; DestDir: "{app}"; \
    Flags: ignoreversion recursesubdirs createallsubdirs; \
    Excludes: "*.pyc,__pycache__,.git*,*.bak"

[Icons]
Name: "{group}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"; \
    WorkingDir: "{app}"
Name: "{group}\Uninstall {#MyAppName}"; Filename: "{uninstallexe}"
Name: "{userdesktop}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"; \
    WorkingDir: "{app}"; Tasks: desktopicon

[Run]
; Final-page checkbox: "Run One Link now". Checked by default; user
; can uncheck if they just installed for later.
Filename: "{app}\{#MyAppExeName}"; \
    Description: "Run {#MyAppName} now"; \
    Flags: nowait postinstall skipifsilent

[UninstallDelete]
; Belt-and-suspenders: nuke anything else we might have left in {app}
; (Inno already does this for files it placed; this catches the
; pycache / temp work files the daemon writes to its install dir,
; though the daemon prefers %LOCALAPPDATA%\Coherence\One_link\).
Type: filesandordirs; Name: "{app}\__pycache__"

[UninstallRun]
; Politely remove the HKCU Run-key entry the in-app autostart feature
; may have written. The user can re-enable autostart from the in-app
; settings after a reinstall.
Filename: "{cmd}"; Parameters: "/C reg delete ""HKCU\Software\Microsoft\Windows\CurrentVersion\Run"" /v ""One Link"" /f"; \
    Flags: runhidden; RunOnceId: "RemoveOneLinkAutoStart"
