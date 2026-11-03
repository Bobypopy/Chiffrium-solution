; Ajouts à l'installateur NSIS généré par electron-builder (fichier lu automatiquement depuis build/).

; Arrêter l'application dans le bon ordre avant toute vérification.
;
; electron-builder considère que l'application "tourne" dès qu'un processus s'exécute depuis le dossier
; d'installation, ce qui inclut notre moteur d'analyse (resources\jre\bin\java.exe), puis tue ces processus
; en une seule passe. Or la fenêtre relance son moteur en 0,3 seconde quand il s'arrête (auto-réparation
; ajoutée en 2.3.5) : si le moteur meurt avant elle, il revient aussitôt, le contrôle suivant le retrouve, et
; l'installation boucle sur "Chiffrium ne peut pas être fermé" quel que soit le nombre de "Recommencer".
; Pendant la copie des fichiers, ce moteur ressuscité verrouille en plus le JRE, ce qui donne le même message.
;
; On arrête donc la fenêtre d'abord (plus personne pour relancer), le moteur ensuite, et on répète pour
; rattraper une relance partie juste avant. `customInit` s'exécute après initMultiUser ($INSTDIR est connu)
; et avant la section d'installation, donc avant le contrôle d'electron-builder.
!macro customInit
  nsExec::Exec `"$SYSDIR\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -C "$$dossier = '$INSTDIR'; if (-not (Test-Path $$dossier)) { exit 0 }; 1..3 | % { Get-CimInstance Win32_Process | ? { $$_.Path -and $$_.Path.StartsWith($$dossier, 'CurrentCultureIgnoreCase') } | Sort-Object { if ($$_.Name -eq '${APP_EXECUTABLE_FILENAME}') { 0 } else { 1 } } | % { Stop-Process -Id $$_.ProcessId -Force -ErrorAction SilentlyContinue }; Start-Sleep -Milliseconds 700 }; exit 0"`
  Pop $0
!macroend

; Note : une desinstallation de secours a ete tentee ici en 1.0.0, pour rattraper les versions dont le
; desinstalleur echouait sous --updated. Elle etait inutile (les versions CryptoAnalyzer ont un autre
; identifiant d'application, donc une autre cle de registre : elle ne les voyait pas) et nuisible : en
; desinstallant la version en place apres que l'installateur avait deja lu l'etat de l'installation, elle le
; laissait attendre indefiniment. Retiree en 1.0.2. Le correctif utile est customRemoveFiles, ci-dessous.

; Suppression des fichiers pendant une mise a jour.
;
; Par defaut, electron-builder deplace d'abord chaque fichier de l'installation vers $PLUGINSDIR\old-install
; (pour pouvoir revenir en arriere), mais uniquement quand le desinstalleur recoit --updated, c'est-a-dire
; exactement pendant une mise a jour. Chez nous ce chemin echoue : le desinstalleur rend 2 et ne supprime
; rien, l'installateur le relance cinq fois puis affiche "Chiffrium ne peut pas etre ferme", message qui
; n'a aucun rapport. Mesure sur la meme machine, meme desinstalleur, rien en cours d'execution :
; avec --updated -> code 2 et 10 857 fichiers intacts ; sans --updated -> code 0 et tout est supprime.
; On supprime donc directement, comme le fait une desinstallation ordinaire.
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
