#!/bin/bash

echo "🧪 测试 Docker 客户端自动检测..."
echo ""

# 启动服务器
echo "1️⃣ 启动 MCP 服务器..."
go run main.go &
SERVER_PID=$!

# 等待服务器启动
sleep 3

# 测试 code_interpreter
echo ""
echo "2️⃣ 测试 code_interpreter 工具..."
echo '{"jsonrpc":"2.0","method":"call_tool","params":{"name":"code_interpreter","arguments":{"code":"print(\"Hello from sandbox!\")\nprint(2**10)"}},"id":1}' | \
  wscat -c ws://localhost:8080/mcp -w 5 2>/dev/null

# 清理
echo ""
echo "3️⃣ 停止服务器..."
kill $SERVER_PID 2>/dev/null

echo ""
echo "✅ 测试完成！"
