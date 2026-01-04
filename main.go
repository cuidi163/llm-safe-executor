// main.go (Day 2 版本)
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
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

// 新增：call_tool 的参数结构
type CallToolParams struct {
	Name string                 `json:"name"`
	Args map[string]interface{} `json:"arguments"`
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

// 新增：Serper API 响应结构
type SerperResponse struct {
	Organic []struct {
		Title   string `json:"title"`
		Link    string `json:"link"`
		Snippet string `json:"snippet"`
	} `json:"organic"`
}

// 新增：执行 search 工具
func searchTool(query string, logger *zap.Logger) (interface{}, error) {
	apiKey := os.Getenv("SERPER_API_KEY")
	if apiKey == "" {
		return nil, fmt.Errorf("SERPER_API_KEY environment variable not set")
	}

	url := "https://google.serper.dev/search"
	payload := map[string]string{"q": query}
	body, _ := json.Marshal(payload)

	req, err := http.NewRequest("POST", url, bytes.NewBuffer(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("X-API-KEY", apiKey)
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		logger.Error("Serper API request failed", zap.Error(err))
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		logger.Error("Serper API returned non-200", zap.Int("status", resp.StatusCode), zap.ByteString("body", body))
		return nil, fmt.Errorf("serper api error: %d", resp.StatusCode)
	}

	var serperResp SerperResponse
	if err := json.NewDecoder(resp.Body).Decode(&serperResp); err != nil {
		return nil, err
	}

	// 只返回前 3 个结果（节省 token）
	results := []map[string]string{}
	for i, item := range serperResp.Organic {
		if i >= 3 {
			break
		}
		results = append(results, map[string]string{
			"title":   item.Title,
			"link":    item.Link,
			"snippet": item.Snippet,
		})
	}

	return map[string]interface{}{
		"results": results,
	}, nil
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
				"capabilities":    map[string]interface{}{"tools": map[string]bool{"list": true, "call": true}},
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
		case "call_tool":
			// 解析 call_tool 参数
			paramsBytes, _ := json.Marshal(req.Params)
			var callParams CallToolParams
			if err := json.Unmarshal(paramsBytes, &callParams); err != nil {
				resp.Error = &MCPError{Code: -32602, Message: "Invalid params for call_tool"}
				break
			}

			var result interface{}
			var execErr error

			switch callParams.Name {
			case "search":
				query, ok := callParams.Args["query"].(string)
				if !ok || query == "" {
					execErr = fmt.Errorf("missing 'query' argument")
				} else {
					result, execErr = searchTool(query, logger)
				}
			default:
				execErr = fmt.Errorf("tool not found: %s", callParams.Name)
			}

			if execErr != nil {
				resp.Error = &MCPError{Code: -32000, Message: execErr.Error()}
			} else {
				resp.Result = result
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

	http.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	})

	server := &http.Server{
		Addr:    ":8080",
		Handler: nil,
	}

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
