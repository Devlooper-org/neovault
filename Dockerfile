# syntax=docker/dockerfile:1

FROM node:20-alpine AS assets
WORKDIR /app

COPY package*.json tailwind.config.js ./
COPY views ./views

RUN npm ci
RUN mkdir -p public/css && npm run build:css

FROM golang:1.25-alpine AS builder
WORKDIR /app

RUN apk add --no-cache ca-certificates tzdata

COPY go.mod go.sum ./
RUN go mod download

COPY . .
COPY --from=assets /app/public ./public

RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o neovault .

FROM alpine:3.20
WORKDIR /app

RUN apk add --no-cache ca-certificates tzdata && \
    adduser -D -h /app appuser

COPY --from=builder /app/neovault /app/neovault

EXPOSE 3000
USER appuser

CMD ["/app/neovault"]
