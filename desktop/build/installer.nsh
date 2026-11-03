; Ajouts à l'installateur NSIS généré par electron-builder (fichier lu automatiquement depuis build/).

; Arrêter la fenêtre avant le moteur d'analyse : la fenêtre relance son moteur en 0,3 seconde, donc l'ordre
; inverse le fait revenir, et l'installation boucle sur "l'application ne peut pas être fermée".
; On recommence jusqu'à ce qu'aucun processus du dossier ne reste (60 secondes au plus) : c'est le critère de la
; vérification d'electron-builder qui suit, et un processus qui met du temps à disparaître (fermeture de
; Chromium, analyse en cours, antivirus) la faisait boucler sur ce message en 1.1.5. Une attente de plus de
; 10 secondes (un arrêt normal en prend 3 à 4) est notée, avec les processus en cause, dans
; %TEMP%\chiffrium-mise-a-jour.log.
!macro customInit
  nsExec::Exec `"$SYSDIR\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -C "$$dossier = '$INSTDIR'; if (-not (Test-Path $$dossier)) { exit 0 }; $$journal = Join-Path $$env:TEMP 'chiffrium-mise-a-jour.log'; $$debut = Get-Date; $$vus = @{}; do { $$restants = @(Get-CimInstance Win32_Process | ? { $$_.Path -and $$_.Path.StartsWith($$dossier, 'CurrentCultureIgnoreCase') }); $$restants | % { $$vus[$$_.ProcessId] = '{0} pid={1} {2}' -f $$_.Name, $$_.ProcessId, $$_.CommandLine }; if ($$restants.Count -eq 0) { break }; $$restants | Sort-Object { if ($$_.Name -eq '${APP_EXECUTABLE_FILENAME}') { 0 } else { 1 } } | % { Stop-Process -Id $$_.ProcessId -Force -ErrorAction SilentlyContinue }; Start-Sleep -Milliseconds 700 } while (((Get-Date) - $$debut).TotalSeconds -lt 60); $$duree = [int]((Get-Date) - $$debut).TotalSeconds; if ($$duree -gt 10) { Add-Content -Path $$journal -Value ('{0} attente de {1} s ; restants : {2} ; vus : {3}' -f (Get-Date -Format s), $$duree, (($$restants | % { $$_.Name + ' pid=' + $$_.ProcessId }) -join ', '), ($$vus.Values -join ' | ')) }; exit 0"`
  Pop $0
!macroend

; Ne pas desinstaller l'ancienne version depuis customInit : l'installateur a deja lu l'etat de
; l'installation, et la lui retirer sous les pieds le laisse attendre indefiniment (essaye en 1.0.0).

; Supprimer directement, plutot que le deplacement vers $PLUGINSDIR\old-install qu'electron-builder fait sous
; --updated : ce deplacement echoue ici (desinstalleur en code 2, rien de supprime) et bloquait toute mise a
; jour derriere un message sans rapport.
!macro customRemoveFiles
  SetOutPath $TEMP
  RMDir /r $INSTDIR
!macroend

; Mise à jour (--updated) : garder le type d'installation existant au lieu de redemander "pour qui installer".
; Les pages licence et dossier sont déjà sautées par electron-builder ; il reste la barre de progression puis
; la page de fin ("Lancer Chiffrium").
!macro customInstallMode
  ${if} ${isUpdated}
    ${if} $hasPerMachineInstallation == "1"
      StrCpy $isForceMachineInstall "1"
    ${else}
      StrCpy $isForceCurrentInstall "1"
    ${endif}
  ${endif}
!macroend

; Mise à jour : electron-builder garde le raccourci du bureau s'il existe mais ne le recrée jamais. S'il a
; disparu (constaté lors d'une mise à jour 2.3.x), on le recrée : sans lui, l'application semble désinstallée.
!macro customInstall
  ${if} ${isUpdated}
  ${andIfNot} ${isNoDesktopShortcut}
  ${andIfNot} ${FileExists} "$newDesktopLink"
    CreateShortCut "$newDesktopLink" "$appExe" "" "$appExe" 0 "" "" "${APP_DESCRIPTION}"
    ClearErrors
    WinShell::SetLnkAUMI "$newDesktopLink" "${APP_ID}"
    System::Call 'Shell32::SHChangeNotify(i 0x8000000, i 0, i 0, i 0)'
  ${endIf}
!macroend
