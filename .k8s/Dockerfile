# Usa un'immagine base Node.js
FROM node:16-alpine

# Imposta la working directory
WORKDIR /app

# Copia i file di progetto
COPY package.json package-lock.json ./
RUN npm install

COPY . .

# Espone la porta 8080
EXPOSE 8080

# Comando per avviare il server
CMD ["node", "server.js"]
