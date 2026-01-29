import tkinter as tk
from tkinter import messagebox, ttk
import os
import subprocess
import ctypes
import sys
import logging

logging.basicConfig(filename='optimizer_log.txt', level=logging.INFO, 
                    format='%(asctime)s - %(levelname)s - %(message)s')

def es_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

def ejecutar_comando(comando, shell=True):
    try:
        result = subprocess.run(comando, shell=shell, check=True, capture_output=True, text=True)
        logging.info(f"Comando ejecutado: {comando}\nSalida: {result.stdout}")
        return result.stdout
    except Exception as e:
        logging.error(f"Error al ejecutar: {comando}\n{e}")
        messagebox.showerror("Error", f"No se pudo ejecutar: {comando}\n{e}")
        return None

def backup_registro(claves=['HKCU', 'HKLM']):
    backup_path = os.path.join(os.getcwd(), "backup_optimizaciones.reg")
    for clave in claves:
        comando = f'reg export {clave} "{backup_path}_{clave}.reg" /y'
        ejecutar_comando(comando)
    messagebox.showinfo("Backup", f"Backup del registro creado en:\n{os.getcwd()}")

def restaurar_backup():
    backups = [f for f in os.listdir(os.getcwd()) if f.startswith("backup_optimizaciones") and f.endswith(".reg")]
    if not backups:
        messagebox.showerror("Error", "No se encontraron backups.")
        return
    for backup in backups:
        ejecutar_comando(f'reg import "{os.path.join(os.getcwd(), backup)}"')
    messagebox.showinfo("Restauración", "¡Backups restaurados con éxito! Reinicia el sistema.")

def check_os_version():
    try:
        import platform
        return platform.version()
    except:
        return "Desconocido"

def debloat_apps(apps_to_remove):
    for app in apps_to_remove:
        comando = f'powershell -command "Get-AppxPackage *{app}* | Remove-AppxPackage"'
        ejecutar_comando(comando)

def aplicar_optimizaciones():
    if not es_admin():
        messagebox.showwarning("Permisos necesarios", "Debes ejecutar este script como administrador.")
        return
    
    if not messagebox.askyesno("Confirmar", "¿Estás seguro de aplicar estas optimizaciones? Algunas pueden afectar la estabilidad del sistema. Asegúrate de tener un backup."):
        return
    
    # --- Rendimiento general ---
    if var_animaciones.get():
        ejecutar_comando('reg add "HKCU\\Control Panel\\Desktop" /v "MenuShowDelay" /t REG_SZ /d "0" /f')
        ejecutar_comando('reg add "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\VisualEffects" /v "VisualFXSetting" /t REG_DWORD /d "2" /f')
    
    if var_autoend.get():
        ejecutar_comando('reg add "HKCU\\Control Panel\\Desktop" /v "AutoEndTasks" /t REG_SZ /d "1" /f')
    
    if var_wait.get():
        ejecutar_comando('reg add "HKCU\\Control Panel\\Desktop" /v "WaitToKillAppTimeout" /t REG_SZ /d "2000" /f')
    
    # --- Menú inicio y explorador ---
    if var_sugerencias.get():
        ejecutar_comando('reg add "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\ContentDeliveryManager" /v "SystemPaneSuggestionsEnabled" /t REG_DWORD /d "0" /f')
    
    if var_extensiones.get():
        ejecutar_comando('reg add "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced" /v "HideFileExt" /t REG_DWORD /d "0" /f')
    
    if var_archivosocultos.get():
        ejecutar_comando('reg add "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced" /v "Hidden" /t REG_DWORD /d "1" /f')
    
    # --- Red y conexión ---
    if var_tcp.get():
        ejecutar_comando('reg add "HKLM\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters" /v "TcpAckFrequency" /t REG_DWORD /d "1" /f')
        ejecutar_comando('reg add "HKLM\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters" /v "TCPNoDelay" /t REG_DWORD /d "1" /f')
        ejecutar_comando('reg add "HKLM\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters" /v "DefaultTTL" /t REG_DWORD /d "64" /f')  # TTL optimizado
    
    # --- Sistema y energía ---
    if var_hibernacion.get():
        ejecutar_comando('powercfg -h off')
    
    if var_alto_rendimiento.get():
        ejecutar_comando('powercfg /setactive SCHEME_MIN')
    
    # --- Privacidad ---
    if var_telemetria.get():
        ejecutar_comando('reg add "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\DataCollection" /v "AllowTelemetry" /t REG_DWORD /d "0" /f')
        # Bloquear hosts de telemetría
        hosts_path = r'C:\Windows\System32\drivers\etc\hosts'
        telemetry_hosts = [
            '0.0.0.0 vortex.data.microsoft.com',
            '0.0.0.0 telemetry.microsoft.com',
            '0.0.0.0 a-0001.a-msedge.net',
            # Añadir más hosts basados en investigaciones
        ]
        with open(hosts_path, 'a') as f:
            for host in telemetry_hosts:
                f.write(f'\n{host}')
        messagebox.showinfo("Privacidad", "Hosts de telemetría bloqueados.")
    
    if var_publicidad.get():
        ejecutar_comando('reg add "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\AdvertisingInfo" /v "Enabled" /t REG_DWORD /d "0" /f')
    
    if var_defender.get():
        if messagebox.askyesno("Advertencia", "Desactivar Windows Defender reduce la seguridad pero mejora el rendimiento. ¿Continuar?"):
            ejecutar_comando('reg add "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender" /v "DisableAntiSpyware" /t REG_DWORD /d "1" /f')
            ejecutar_comando('sc stop WinDefend')
            ejecutar_comando('sc config WinDefend start=disabled')
    
    if var_superfetch.get():
        ejecutar_comando('sc stop SysMain')
        ejecutar_comando('sc config SysMain start=disabled')
    
    if var_indexacion.get():
        ejecutar_comando('sc stop WSearch')
        ejecutar_comando('sc config WSearch start=disabled')
    
    if var_background_apps.get():
        ejecutar_comando('reg add "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\BackgroundAccessApplications" /v "GlobalUserDisabled" /t REG_DWORD /d "1" /f')
    
    if var_game_mode.get():
        ejecutar_comando('reg add "HKCU\\Software\\Microsoft\\GameBar" /v "AllowAutoGameMode" /t REG_DWORD /d "1" /f')
        ejecutar_comando('reg add "HKCU\\Software\\Microsoft\\GameBar" /v "AutoGameModeEnabled" /t REG_DWORD /d "1" /f')
        # Optimizaciones para gaming de repos como AtlasOS
        ejecutar_comando('reg add "HKLM\\SYSTEM\\CurrentControlSet\\Control\\GraphicsDrivers" /v "HwSchMode" /t REG_DWORD /d "2" /f')  # GPU Scheduling
    
    if var_ram.get():
        ejecutar_comando('reg add "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Memory Management" /v "ClearPageFileAtShutdown" /t REG_DWORD /d "0" /f')
        ejecutar_comando('reg add "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Memory Management" /v "LargeSystemCache" /t REG_DWORD /d "1" /f')
        # Más tweaks de RAM de guías
        ejecutar_comando('reg add "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Memory Management" /v "DisablePagingExecutive" /t REG_DWORD /d "1" /f')
    
    if var_cpu.get():
        ejecutar_comando('reg add "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Power\\PowerSettings\\238C9FA8-0AAD-41ED-83F4-97BE242C8F20\\7bc4a2f9-d8fc-4469-b07b-33eb785aaca0" /v "ValueMax" /t REG_DWORD /d "0" /f')
        # Desactivar CPU parking (de tweaks avanzados)
        ejecutar_comando('powercfg /setacvalueindex SCHEME_CURRENT SUB_PROCESSOR PROCTHROTTLING 0')
        ejecutar_comando('powercfg /setactive SCHEME_CURRENT')
    
    if var_firewall.get():
        ejecutar_comando('netsh advfirewall set allprofiles state on')
    
    if var_uac.get():
        ejecutar_comando('reg add "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System" /v "EnableLUA" /t REG_DWORD /d "1" /f')
    
    if var_bitlocker.get():
        try:
            output = ejecutar_comando('manage-bde -on C: -RecoveryPassword')
            messagebox.showinfo("Seguridad", f"BitLocker activado en unidad C:. Clave de recuperación: {output}")
        except:
            messagebox.showerror("Error", "No se pudo activar BitLocker. Asegúrate de tener TPM.")
    
    if var_dark_mode.get():
        ejecutar_comando('reg add "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Themes\\Personalize" /v "AppsUseLightTheme" /t REG_DWORD /d "0" /f')
        ejecutar_comando('reg add "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Themes\\Personalize" /v "SystemUsesLightTheme" /t REG_DWORD /d "0" /f')
    
    if var_taskbar.get():
        ejecutar_comando('reg add "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced" /v "TaskbarSmallIcons" /t REG_DWORD /d "1" /f')
        # Más tweaks de taskbar de Windows 11
        ejecutar_comando('reg add "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced" /v "TaskbarAl" /t REG_DWORD /d "0" /f')  # Alinear a la izquierda
    
    if var_debloat.get():
        apps_to_remove = [
            'Microsoft.BingWeather', 'Microsoft.GetHelp', 'Microsoft.Getstarted',
            'Microsoft.MicrosoftOfficeHub', 'Microsoft.MicrosoftSolitaireCollection',
            'Microsoft.MixedReality.Portal', 'Microsoft.Office.OneNote',
            'Microsoft.People', 'Microsoft.SkypeApp', 'Microsoft.WindowsAlarms',
            'Microsoft.WindowsCamera', 'microsoft.windowscommunicationsapps',
            'Microsoft.WindowsMaps', 'Microsoft.WindowsSoundRecorder',
            'Microsoft.Xbox.TCUI', 'Microsoft.XboxApp', 'Microsoft.XboxGameOverlay',
            'Microsoft.XboxGamingOverlay', 'Microsoft.XboxIdentityProvider',
            'Microsoft.XboxSpeechToTextOverlay', 'Microsoft.YourPhone',
            'Microsoft.ZuneMusic', 'Microsoft.ZuneVideo', 'MicrosoftTeams',
            'Clipchamp.Clipchamp', 'Microsoft.Todos',  # Añadir más basados en repos
        ]
        debloat_apps(apps_to_remove)
        # Desactivar Cortana
        ejecutar_comando('reg add "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\Windows Search" /v "AllowCortana" /t REG_DWORD /d "0" /f')
        # Remover OneDrive (opcional)
        if messagebox.askyesno("Debloating", "¿Desinstalar OneDrive?"):
            ejecutar_comando('taskkill /f /im OneDrive.exe')
            ejecutar_comando('%SystemRoot%\\SysWOW64\\OneDriveSetup.exe /uninstall')
    
    if var_gaming.get():
        # Desactivar Game DVR
        ejecutar_comando('reg add "HKCU\\System\\GameConfigStore" /v "GameDVR_Enabled" /t REG_DWORD /d "0" /f')
        ejecutar_comando('reg add "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\GameDVR" /v "AllowGameDVR" /t REG_DWORD /d "0" /f')
        # Prioridad de GPU
        ejecutar_comando('reg add "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Multimedia\\SystemProfile" /v "GPU Priority" /t REG_DWORD /d "8" /f')
        ejecutar_comando('reg add "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Multimedia\\SystemProfile" /v "Priority" /t REG_DWORD /d "6" /f')
        # Desactivar Fullscreen Optimizations globalmente
        ejecutar_comando('reg add "HKCU\\System\\GameConfigStore" /v "GameDVR_FSEBehaviorMode" /t REG_DWORD /d "2" /f')
    
    if var_clean_temp.get():
        ejecutar_comando('del /q /s %TEMP%\\*')
        ejecutar_comando('del /q /s C:\\Windows\\Temp\\*')
        messagebox.showinfo("Limpieza", "Archivos temporales eliminados.")
    
    if var_disable_services.get():
        services_to_disable = [
            'DiagTrack',  # Connected User Experiences and Telemetry
            'dmwappushservice',  # WAP Push Message Routing Service
            'lfsvc',  # Geolocation Service
            'MapsBroker',  # Downloaded Maps Manager
            'NetTcpPortSharing',  # Net.Tcp Port Sharing Service
            'RemoteAccess',  # Routing and Remote Access
            'RemoteRegistry',  # Remote Registry
            'SharedAccess',  # Internet Connection Sharing (ICS)
            'TrkWks',  # Distributed Link Tracking Client
            'WbioSrvc',  # Windows Biometric Service
            'XblAuthManager',  # Xbox Live Auth Manager
            'XblGameSave',  # Xbox Live Game Save Service
            'XboxNetApiSvc',  # Xbox Live Networking Service
        ]
        for service in services_to_disable:
            ejecutar_comando(f'sc stop {service}')
            ejecutar_comando(f'sc config {service} start=disabled')
    
    if var_check_updates.get():
        ejecutar_comando('wuauclt /detectnow')
        messagebox.showinfo("Actualizaciones", "Comprobando actualizaciones de Windows.")
    
    if '10.' not in check_os_version() and '11.' in check_os_version():
        if var_win11_tweaks.get():
            # Desactivar widgets
            ejecutar_comando('reg add "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced" /v "TaskbarDa" /t REG_DWORD /d "0" /f')
            # Desactivar chat
            ejecutar_comando('reg add "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced" /v "TaskbarMn" /t REG_DWORD /d "0" /f')
            # Menú contextual clásico
            ejecutar_comando('reg add "HKCU\\Software\\Classes\\CLSID\\{86ca1aa0-34aa-4e8b-a509-50c905bae2a2}" /v "InprocServer32" /t REG_SZ /d "" /f')
    
    messagebox.showinfo("Optimización", "¡Optimizaciones aplicadas con éxito! Reinicia el sistema para ver todos los cambios. Revisa el log en optimizer_log.txt para detalles.")

root = tk.Tk()
root.title("Windows Ultimate Optimizer 2026 - Edición Completa")
root.geometry("700x900")
root.resizable(True, True)
root.configure(bg="#f0f0f0")

os_version = check_os_version()
tk.Label(root, text=f"💻 Windows Optimizer 2026\nVersión OS: {os_version}\n@vg.z5", font=("Segoe UI", 16, "bold"), bg="#f0f0f0").pack(pady=10)

frame_backup = tk.Frame(root, bg="#f0f0f0")
frame_backup.pack(pady=5)
tk.Button(frame_backup, text="📦 Crear backup del registro", command=backup_registro, bg="#4CAF50", fg="white").pack(side="left", padx=10)
tk.Button(frame_backup, text="🔙 Restaurar backup", command=restaurar_backup, bg="#F44336", fg="white").pack(side="left", padx=10)
tk.Button(frame_backup, text="🔄 Comprobar actualizaciones", command=lambda: aplicar_optimizaciones() if var_check_updates.get() else None, bg="#FF9800", fg="white").pack(side="left", padx=10)

var_animaciones = tk.IntVar(value=1)
var_autoend = tk.IntVar(value=1)
var_wait = tk.IntVar(value=1)
var_sugerencias = tk.IntVar(value=1)
var_extensiones = tk.IntVar(value=1)
var_archivosocultos = tk.IntVar(value=1)
var_tcp = tk.IntVar(value=1)
var_hibernacion = tk.IntVar(value=1)
var_alto_rendimiento = tk.IntVar(value=1)
var_telemetria = tk.IntVar(value=1)
var_publicidad = tk.IntVar(value=1)
var_defender = tk.IntVar()
var_superfetch = tk.IntVar()
var_indexacion = tk.IntVar()
var_background_apps = tk.IntVar()
var_game_mode = tk.IntVar()
var_ram = tk.IntVar()
var_cpu = tk.IntVar()
var_firewall = tk.IntVar(value=1)
var_uac = tk.IntVar(value=1)
var_bitlocker = tk.IntVar()
var_dark_mode = tk.IntVar()
var_taskbar = tk.IntVar()
var_debloat = tk.IntVar()
var_gaming = tk.IntVar()
var_clean_temp = tk.IntVar()
var_disable_services = tk.IntVar()
var_check_updates = tk.IntVar()
var_win11_tweaks = tk.IntVar()

canvas = tk.Canvas(root, bg="#f0f0f0")
scrollbar = tk.Scrollbar(root, orient="vertical", command=canvas.yview)
scrollable_frame = tk.Frame(canvas, bg="#f0f0f0")

scrollable_frame.bind(
    "<Configure>",
    lambda e: canvas.configure(
        scrollregion=canvas.bbox("all")
    )
)

canvas.create_window((0, 0), window=scrollable_frame, anchor="nw")
canvas.configure(yscrollcommand=scrollbar.set)

canvas.pack(side="left", fill="both", expand=True)
scrollbar.pack(side="right", fill="y")

frame1 = tk.LabelFrame(scrollable_frame, text="🔧 Rendimiento General", padx=10, pady=10, bg="#f0f0f0")
frame1.pack(fill="both", expand="yes", padx=10, pady=5)
tk.Checkbutton(frame1, text="Desactivar animaciones y efectos visuales", variable=var_animaciones, bg="#f0f0f0").pack(anchor="w")
tk.Checkbutton(frame1, text="Cerrar apps automáticamente (AutoEndTasks)", variable=var_autoend, bg="#f0f0f0").pack(anchor="w")
tk.Checkbutton(frame1, text="Reducir tiempo de espera al cerrar apps", variable=var_wait, bg="#f0f0f0").pack(anchor="w")

frame2 = tk.LabelFrame(scrollable_frame, text="📂 Menú Inicio y Explorador", padx=10, pady=10, bg="#f0f0f0")
frame2.pack(fill="both", expand="yes", padx=10, pady=5)
tk.Checkbutton(frame2, text="Desactivar sugerencias y tips", variable=var_sugerencias, bg="#f0f0f0").pack(anchor="w")
tk.Checkbutton(frame2, text="Mostrar siempre extensiones de archivos", variable=var_extensiones, bg="#f0f0f0").pack(anchor="w")
tk.Checkbutton(frame2, text="Mostrar archivos ocultos", variable=var_archivosocultos, bg="#f0f0f0").pack(anchor="w")

frame3 = tk.LabelFrame(scrollable_frame, text="🌐 Red y Conexión", padx=10, pady=10, bg="#f0f0f0")
frame3.pack(fill="both", expand="yes", padx=10, pady=5)
tk.Checkbutton(frame3, text="Optimizar TCP/IP y ping", variable=var_tcp, bg="#f0f0f0").pack(anchor="w")

frame4 = tk.LabelFrame(scrollable_frame, text="⚡ Sistema y Energía", padx=10, pady=10, bg="#f0f0f0")
frame4.pack(fill="both", expand="yes", padx=10, pady=5)
tk.Checkbutton(frame4, text="Desactivar hibernación", variable=var_hibernacion, bg="#f0f0f0").pack(anchor="w")
tk.Checkbutton(frame4, text="Ajustar plan a Alto rendimiento", variable=var_alto_rendimiento, bg="#f0f0f0").pack(anchor="w")

frame5 = tk.LabelFrame(scrollable_frame, text="🔒 Privacidad", padx=10, pady=10, bg="#f0f0f0")
frame5.pack(fill="both", expand="yes", padx=10, pady=5)
tk.Checkbutton(frame5, text="Desactivar telemetría de Windows", variable=var_telemetria, bg="#f0f0f0").pack(anchor="w")
tk.Checkbutton(frame5, text="Desactivar publicidad en Windows", variable=var_publicidad, bg="#f0f0f0").pack(anchor="w")

frame6 = tk.LabelFrame(scrollable_frame, text="🚀 Optimizaciones Extremas (Rendimiento Máximo)", padx=10, pady=10, bg="#f0f0f0")
frame6.pack(fill="both", expand="yes", padx=10, pady=5)
tk.Checkbutton(frame6, text="Desactivar Windows Defender (mejora rendimiento, reduce seguridad)", variable=var_defender, bg="#f0f0f0").pack(anchor="w")
tk.Checkbutton(frame6, text="Desactivar Superfetch/Prefetch (para SSDs)", variable=var_superfetch, bg="#f0f0f0").pack(anchor="w")
tk.Checkbutton(frame6, text="Desactivar indexación de búsqueda", variable=var_indexacion, bg="#f0f0f0").pack(anchor="w")
tk.Checkbutton(frame6, text="Desactivar apps en segundo plano", variable=var_background_apps, bg="#f0f0f0").pack(anchor="w")
tk.Checkbutton(frame6, text="Activar Game Mode para priorizar juegos/apps", variable=var_game_mode, bg="#f0f0f0").pack(anchor="w")
tk.Checkbutton(frame6, text="Optimizar uso de RAM (desactivar paginación innecesaria)", variable=var_ram, bg="#f0f0f0").pack(anchor="w")
tk.Checkbutton(frame6, text="Optimizar CPU (reducir tiempo de inactividad, desparkear cores)", variable=var_cpu, bg="#f0f0f0").pack(anchor="w")

frame7 = tk.LabelFrame(scrollable_frame, text="🛡️ Seguridad Avanzada", padx=10, pady=10, bg="#f0f0f0")
frame7.pack(fill="both", expand="yes", padx=10, pady=5)
tk.Checkbutton(frame7, text="Habilitar Firewall completo", variable=var_firewall, bg="#f0f0f0").pack(anchor="w")
tk.Checkbutton(frame7, text="Habilitar UAC (Control de Cuentas de Usuario)", variable=var_uac, bg="#f0f0f0").pack(anchor="w")
tk.Checkbutton(frame7, text="Activar BitLocker (encriptación de disco)", variable=var_bitlocker, bg="#f0f0f0").pack(anchor="w")
tk.Checkbutton(frame7, text="Comprobar actualizaciones de seguridad", variable=var_check_updates, bg="#f0f0f0").pack(anchor="w")

frame8 = tk.LabelFrame(scrollable_frame, text="🎨 Usabilidad y Visuales", padx=10, pady=10, bg="#f0f0f0")
frame8.pack(fill="both", expand="yes", padx=10, pady=5)
tk.Checkbutton(frame8, text="Activar modo oscuro", variable=var_dark_mode, bg="#f0f0f0").pack(anchor="w")
tk.Checkbutton(frame8, text="Iconos pequeños en barra de tareas y alinear a izquierda", variable=var_taskbar, bg="#f0f0f0").pack(anchor="w")

frame9 = tk.LabelFrame(scrollable_frame, text="🗑️ Debloating (Remover Bloatware)", padx=10, pady=10, bg="#f0f0f0")
frame9.pack(fill="both", expand="yes", padx=10, pady=5)
tk.Checkbutton(frame9, text="Remover apps preinstaladas (Xbox, Candy Crush, etc.)", variable=var_debloat, bg="#f0f0f0").pack(anchor="w")
tk.Checkbutton(frame9, text="Desactivar servicios innecesarios (telemetría, geolocalización, etc.)", variable=var_disable_services, bg="#f0f0f0").pack(anchor="w")
tk.Checkbutton(frame9, text="Limpiar archivos temporales", variable=var_clean_temp, bg="#f0f0f0").pack(anchor="w")

frame10 = tk.LabelFrame(scrollable_frame, text="🎮 Optimizaciones para Gaming", padx=10, pady=10, bg="#f0f0f0")
frame10.pack(fill="both", expand="yes", padx=10, pady=5)
tk.Checkbutton(frame10, text="Tweaks avanzados para gaming (bajo latencia, FPS boost)", variable=var_gaming, bg="#f0f0f0").pack(anchor="w")

frame11 = tk.LabelFrame(scrollable_frame, text="🪟 Tweaks Específicos de Windows 11", padx=10, pady=10, bg="#f0f0f0")
frame11.pack(fill="both", expand="yes", padx=10, pady=5)
tk.Checkbutton(frame11, text="Desactivar widgets, chat, menú contextual nuevo", variable=var_win11_tweaks, bg="#f0f0f0").pack(anchor="w")

# Botón aplicar
tk.Button(root, text="🚀 Aplicar Optimización", command=aplicar_optimizaciones, bg="#2196F3", fg="white", font=("Segoe UI", 12, "bold")).pack(pady=20)

root.mainloop()