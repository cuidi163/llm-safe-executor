#!/bin/bash
# test_fix.sh

echo "🧹 Cleaning up..."
pkill -f llm-safe-executor || true

echo "🚀 Starting server..."
./llm-safe-executor > server.log 2>&1 &
SERVER_PID=$!
sleep 3

echo "🧪 Sending test request..."
# 使用 ID 999 区分之前的请求
RESPONSE=$(echo '{"jsonrpc":"2.0","method":"call_tool","params":{"name":"code_interpreter","arguments":{"code":"print(\"Hello from sandbox!\")\nprint(2**10)"}},"id":999}' | wscat -c ws://localhost:8081/mcp -w 10 2>&1)

echo "📝 Response:"
echo "$RESPONSE"

echo "🛑 Stopping server..."
kill $SERVER_PID
cat server.log | grep "Error"

if echo "$RESPONSE" | grep -q "Hello from sandbox!" && echo "$RESPONSE" | grep -q "1024"; then
    echo "✅ SUCCESS: Fix verified!"
else
    echo "❌ FAILURE: Fix failed."
fi
