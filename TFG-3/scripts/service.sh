#!/bin/sh

# Capturar la dirección IP y el puerto del intento de conexión
echo "Intento de conexión SSH desde $1 a puerto $2" >&2
# Simular un banner de servicio
echo "Connected to service"
# Bucle para capturar comandos
while read cmd
do
    echo "Comando recibido: $cmd" >&2
    # Simular respuesta (esto puede ser modificado para ser más realista)
    echo "Comando no reconocido"
done