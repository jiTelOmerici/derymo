#!/bin/bash
# Установка 3x-ui Telegram Bot
set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

INSTALL_DIR="/opt/xui-bot"
SERVICE_NAME="xui-bot"

echo -e "${GREEN}=== Установка 3x-ui Telegram Bot ===${NC}"

# Проверяем root
if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}Запустите скрипт от root${NC}"
    exit 1
fi

# Устанавливаем зависимости
echo -e "${YELLOW}Устанавливаем зависимости...${NC}"
apt-get update -qq
apt-get install -y python3 python3-pip python3-venv curl git

# Создаём директорию
mkdir -p $INSTALL_DIR
cd $INSTALL_DIR

# Скачиваем файлы бота
echo -e "${YELLOW}Скачиваем бота...${NC}"
curl -sSL "https://raw.githubusercontent.com/jiTelOmerici/hernyakakayato/main/bot/bot.py" -o bot.py
curl -sSL "https://raw.githubusercontent.com/jiTelOmerici/hernyakakayato/main/bot/requirements.txt" -o requirements.txt

# Создаём venv
python3 -m venv venv
source venv/bin/activate
pip install -q -r requirements.txt

# Запрашиваем настройки
echo ""
echo -e "${YELLOW}=== Настройка ===${NC}"
read -p "Telegram Bot Token: " TG_TOKEN
read -p "3x-ui API Token: " API_TOKEN
read -p "Panel URL (например https://domain.com:PORT/basepath): " PANEL_URL
read -p "Ваш Telegram ID (Admin): " ADMIN_IDS
read -p "Groq API Key (Enter для пропуска): " GROQ_KEY
read -p "Subscription URL (например https://domain.com:PORT): " SUB_URL
read -p "Sub Path (например /secret123/): " SUB_PATH
read -p "Clash Path (например /clash/): " CLASH_PATH

# Создаём .env
cat > .env << ENV
TG_TOKEN=$TG_TOKEN
API_TOKEN=$API_TOKEN
PANEL_URL=$PANEL_URL
ADMIN_IDS=$ADMIN_IDS
GROQ_KEY=$GROQ_KEY
SUB_URL=$SUB_URL
SUB_PATH=$SUB_PATH
CLASH_PATH=$CLASH_PATH
ENV

chmod 600 .env

# Создаём systemd сервис
cat > /etc/systemd/system/${SERVICE_NAME}.service << SERVICE
[Unit]
Description=3x-ui Telegram Bot
After=network.target

[Service]
Type=simple
WorkingDirectory=$INSTALL_DIR
EnvironmentFile=$INSTALL_DIR/.env
ExecStart=$INSTALL_DIR/venv/bin/python3 bot.py
Restart=always
RestartSec=5
User=root

[Install]
WantedBy=multi-user.target
SERVICE

systemctl daemon-reload
systemctl enable $SERVICE_NAME
systemctl restart $SERVICE_NAME

sleep 2
if systemctl is-active --quiet $SERVICE_NAME; then
    echo -e "${GREEN}✅ Бот успешно установлен и запущен!${NC}"
    echo -e "${GREEN}Управление: systemctl start/stop/restart ${SERVICE_NAME}${NC}"
    echo -e "${GREEN}Логи: journalctl -u ${SERVICE_NAME} -f${NC}"
else
    echo -e "${RED}❌ Ошибка запуска бота. Проверьте логи:${NC}"
    journalctl -u $SERVICE_NAME --no-pager -n 20
fi
