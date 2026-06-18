#!/bin/bash
# Обновление бота
set -e
GREEN='\033[0;32m'
NC='\033[0m'
INSTALL_DIR="/opt/xui-bot"

echo -e "${GREEN}Обновляем бота...${NC}"
cd $INSTALL_DIR
curl -sSL "https://raw.githubusercontent.com/jiTelOmerici/hernyakakayato/main/bot/bot.py" -o bot.py
systemctl restart xui-bot
echo -e "${GREEN}✅ Бот обновлён!${NC}"
