<h1 align="center">Baileys-Rust (baileys-rs)</h1>

<div align="center">
  <p>Implementación nativa en <b>Rust</b> del protocolo WebSocket de WhatsApp Web, basada en la arquitectura de <a href="https://github.com/WhiskeySockets/Baileys">WhiskeySockets/Baileys</a>.</p>
  <p>
    <img alt="Rust" src="https://img.shields.io/badge/Rust-2021-orange?logo=rust" />
    <img alt="Status" src="https://img.shields.io/badge/Estado-En%20Migraci%C3%B3n-yellow" />
    <img alt="Protocol" src="https://img.shields.io/badge/WhatsApp-Multi--Device-25D366?logo=whatsapp" />
  </p>
</div>

> [!WARNING]
> **Proyecto en desarrollo activo:** Este repositorio está siendo migrado progresivamente desde Baileys (TypeScript v7) a Rust puro, módulo por módulo. Algunas capas del protocolo aún se encuentran en proceso de portado.

---

## Cambios frente a Baileys normal (TypeScript / Node.js)

Baileys-Rust mantiene la misma lógica de protocolo Multi-Device vía WebSocket (sin Selenium ni Chromium), pero elimina por completo el runtime de Node.js:

| Característica | Baileys (TypeScript / Node.js) | Baileys-Rust (`baileys-rs`) |
| :--- | :--- | :--- |
| **Runtime** | Requiere Node.js / Bun + V8 | Binario nativo compilado (sin runtime externo) |
| **Consumo de RAM** | ~80 MB – 250 MB+ en reposo | ~10 MB – 30 MB estimados |
| **Dependencias** | `node_modules` pesado (cientos de paquetes) | Compilación estática en un solo ejecutable |
| **Tipado y seguridad** | Tipos en compilación; errores de `undefined` en ejecución | Seguridad de memoria y tipos estrictos (`Option`, `Result`, `enum`) |
| **Concurrencia** | Event loop monohilo de JS | Asíncrono multihilo con `tokio` |
| **Protobuf (`WAProto`)** | Archivo JS generado de varios MB | Estructuras Rust compiladas directamente desde `WAProto.proto` |
| **Despliegue en host** | Subir proyecto + instalar `npm`/`yarn` | Subir únicamente el binario compilado y ejecutarlo |

### Cambios en la estructura del proyecto
* **`WABinary`**: Los nodos binarios (`BinaryNode`) usan `enum BinaryNodeData` (`List`, `String`, `Bytes`) en lugar de uniones dinámicas de JS.
* **JIDs tipados**: `JidServer` y `FullJid` evitan manipulaciones inseguras de strings y soportan LIDs (`@lid`), grupos (`@g.us`), newsletters (`@newsletter`), bots y cuentas hosted.
* **Limpieza del repositorio**: Se eliminaron configuraciones de Node/Yarn/Jest/ESLint para trabajar directamente con `Cargo.toml` y `src/lib.rs`.

---

## Estado de la migración

| Capa | Carpeta | Estado |
| :--- | :--- | :--- |
| Tipos y JIDs (`WABinary`) | `src/WABinary/` | En progreso (`types.rs`, `jid_utils.rs` listos) |
| Codificador / Decodificador binario | `src/WABinary/` | Pendiente (`constants`, `encode`, `decode`) |
| Esquemas Protobuf (`WAProto`) | `WAProto/WAProto.proto` | Pendiente (`build.rs` + `prost`) |
| Criptografía y Noise Handshake | `src/Utils/` | Pendiente |
| Cifrado E2E (Signal + Sender Keys) | `src/Signal/` | Pendiente |
| Cliente WebSocket y Mensajería | `src/Socket/` | Pendiente |

---

## Requisitos e Instalación

### 1. Instalar Rust
* **Linux / macOS / VPS:**
  ```bash
  curl --proto '=https' --tlsv1.2 -sSf [https://sh.rustup.rs](https://sh.rustup.rs) | sh
  source "$HOME/.cargo/env"

 * Termux (Android):
   pkg update && pkg install rust git -y

2. Usar como librería en tu proyecto Rust
Agrega el repositorio en tu Cargo.toml:
[dependencies]
baileys-rs = { git = "[https://github.com/LuferOS/Baileys-Rust](https://github.com/LuferOS/Baileys-Rust)", branch = "main" }

3. Compilar y ejecutar pruebas localmente
git clone [https://github.com/LuferOS/Baileys-Rust.git](https://github.com/LuferOS/Baileys-Rust.git)
cd Baileys-Rust

# Verificar compilación rápida
cargo check

# Ejecutar pruebas unitarias
cargo test

# Compilar versión optimizada para producción
cargo build --release

El binario optimizado se generará en target/release/.
Cómo usar en un Host (Producción)
Una de las mayores ventajas de Rust es que no necesitas instalar dependencias ni código fuente en el servidor: compilas una vez y solo subes el ejecutable.
Opción 1: VPS Linux (Ubuntu / Debian) con systemd
 * Clona y compila en tu VPS (o sube el binario compilado para Linux x86_64):
   cargo build --release

 * Crea un servicio para que el bot nunca se apague y reinicie automáticamente si hay caídas:
   sudo nano /etc/systemd/system/baileys-bot.service

   Pega la configuración ajustando tus rutas:
   [Unit]
Description=Bot de WhatsApp con Baileys-Rust
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/opt/mi-bot
ExecStart=/opt/mi-bot/target/release/mi-bot
Restart=always
RestartSec=5
Environment=RUST_LOG=info

[Install]
WantedBy=multi-user.target

 * Actívalo y revisa los logs (para ver el QR o Pairing Code):
   sudo systemctl daemon-reload
sudo systemctl enable --now baileys-bot
journalctl -u baileys-bot -f

Opción 2: Hosting de Bots (Pterodactyl / Paneles compartidos)
Los paneles compartidos suelen limitar bastante la RAM (256 MB – 512 MB), donde Node.js sufre y Rust corre sobrado:
 * Si tu host tiene Egg de Rust: Conecta tu repositorio de GitHub y configura el comando de arranque a cargo run --release.
 * Si tu host solo tiene Egg genérico / Linux (sin compilar en el host):
   * Compila tu proyecto en tu PC o VPS para Linux (cargo build --release).
   * Sube únicamente el archivo binario (ej. mi-bot) al administrador de archivos del panel.
   * Dale permisos y ejecútalo en el comando de inicio del panel:
     chmod +x ./mi-bot && ./mi-bot

 * Persistencia de sesión: Asegúrate de guardar la carpeta de credenciales (ej. auth_info/) dentro del directorio persistente del servidor para no tener que volver a vincular el dispositivo al reiniciar.
Opción 3: Docker (Imagen ligera ~20 MB)
Usa compilación multi-etapa para que la imagen final no incluya el compilador de Rust:
# Etapa 1: Compilación
FROM rust:1.82-slim AS builder
WORKDIR /app
COPY . .
RUN cargo build --release

# Etapa 2: Ejecución mínima
FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y ca-certificates && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY --from=builder /app/target/release/mi-bot /app/mi-bot
VOLUME ["/app/auth_info"]
CMD ["./mi-bot"]

Construir y ejecutar:
docker build -t baileys-rust-bot .
docker run -it --restart unless-stopped -v $(pwd)/auth_info:/app/auth_info baileys-rust-bot

Opción 4: Mantener corriendo en Termux (Android)
termux-wake-lock
cargo run --release

(Usa tmux si quieres dejarlo corriendo en segundo plano sin perder la consola).
Arquitectura objetivo de uso (API proyectada)
A medida que se completen las capas de Socket y Signal, el flujo de conexión seguirá el mismo concepto de Baileys (QR, Pairing Code y manejo de eventos), pero idiomático en Rust:
 * Autenticación: Soporte para vinculación por QR Code y Pairing Code (número sin +, espacios ni guiones), guardando sesión en archivos o base de datos (SQLite / PostgreSQL).
 * Eventos: Canal asíncrono (tokio::sync::mpsc / broadcast) para connection.update, creds.update, messages.upsert, messages.update y groups.update.
 * Mensajería y Media: Envío y descarga por streaming sin cargar archivos grandes completos en RAM.
Aviso Legal (Disclaimer)
Este proyecto no está afiliado, asociado, autorizado ni respaldado por WhatsApp ni Meta. "WhatsApp" es una marca registrada de sus respectivos propietarios.
El uso de esta librería es responsabilidad exclusiva de quien la implementa. No se aprueba ni fomenta el uso para spam, mensajería masiva no solicitada ni prácticas que violen los Términos de Servicio de WhatsApp.
Créditos
 * Basado en el trabajo original de WhiskeySockets/Baileys y la documentación de ingeniería inversa de la comunidad Multi-Device.