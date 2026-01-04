// main.go
package main

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/gorilla/websocket"
	"go.uber.org/zap"
)

var upgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool { return true },
}

type MCPRequest struct {
	JSONRPC string      `json:"jsonrpc"`
	Method  string      `json:"method"`
	Params  interface{} `json:"params,omitempty"`
	ID      interface{} `json:"id"`
}

type MCPResponse struct {
	JSONRPC string      `json:"jsonrpc"`
	Result  interface{} `json:"result,omitempty"`
	Error   *MCPError   `json:"error,omitempty"`
	ID      interface{} `json:"id"`
}

type MCPError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

func handleMCP(ws *websocket.Conn, logger *zap.Logger) {
	defer ws.Close()

	for {
		_, msg, err := ws.ReadMessage()
		if err != nil {
			if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseAbnormalClosure) {
				logger.Warn("WebSocket read error", zap.Error(err))
			}
			break
		}

		var req MCPRequest
		if err := json.Unmarshal(msg, &req); err != nil {
			logger.Error("Failed to unmarshal MCP request", zap.Error(err), zap.ByteString("raw", msg))
			continue
		}

		resp := MCPResponse{
			JSONRPC: "2.0",
			ID:      req.ID,
		}

		switch req.Method {
		case "initialize":
			resp.Result = map[string]interface{}{
				"protocolVersion": "2024-11-05",
				"capabilities":    map[string]interface{}{"tools": map[string]bool{"list": true}},
			}
		case "list_tools":
			resp.Result = []map[string]interface{}{
				{
					"name":        "search",
					"description": "Search the web using Serper API",
					"inputSchema": map[string]interface{}{
						"type": "object",
						"properties": map[string]interface{}{
							"query": map[string]string{"type": "string", "description": "Search query"},
						},
						"required": []string{"query"},
					},
				},
				{
					"name":        "code_interpreter",
					"description": "Execute Python code in a secure sandbox",
					"inputSchema": map[string]interface{}{
						"type": "object",
						"properties": map[string]interface{}{
							"code": map[string]string{"type": "string", "description": "Python code to execute"},
						},
						"required": []string{"code"},
					},
				},
			}
		default:
			resp.Error = &MCPError{Code: -32601, Message: "Method not found: " + req.Method}
		}

		out, _ := json.Marshal(resp)
		if err := ws.WriteMessage(websocket.TextMessage, out); err != nil {
			logger.Error("Failed to write response", zap.Error(err))
			break
		}
	}
}

func main() {
	logger, _ := zap.NewProduction()
	defer logger.Sync()

	http.HandleFunc("/mcp", func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			logger.Error("WebSocket upgrade failed", zap.Error(err))
			return
		}
		go handleMCP(conn, logger)
	})

	// Health check
	http.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	})

	server := &http.Server{
		Addr:    ":8080",
		Handler: nil,
	}

	// Graceful shutdown
	done := make(chan bool, 1)
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		<-quit
		logger.Info("Shutting down server...")
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		server.Shutdown(ctx)
		done <- true
	}()

	logger.Info("MCP Server started", zap.String("addr", ":8080"))
	if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		logger.Fatal("Server failed", zap.Error(err))
	}

	<-done
	logger.Info("Server stopped")
}
