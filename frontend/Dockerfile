# syntax=docker/dockerfile:1.7
# Étape de test : la logique front est testée à la construction de l'image.
FROM node:22-alpine AS test
WORKDIR /app
COPY package.json ./
COPY public ./public
COPY tests ./tests
RUN npm test

# Image finale : nginx non privilégié, fichiers statiques uniquement.
FROM nginxinc/nginx-unprivileged:1.27-alpine
LABEL org.opencontainers.image.title="chiffrium-frontend" \
      org.opencontainers.image.description="Interface web de Chiffrium"
ENV BACKEND_URL=http://backend:8080
COPY nginx.conf /etc/nginx/templates/default.conf.template
COPY --from=test /app/public /usr/share/nginx/html
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=3s CMD wget -qO- http://localhost:8080/healthz || exit 1
