// main.go - Day 4: Robustness & Observability
package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/image"
	"github.com/docker/docker/client"
	"github.com/docker/docker/pkg/stdcopy"
	"github.com/gorilla/websocket"
	"go.uber.org/zap"
)

var upgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool { return true },
}

// ====== Metrics (Day 4) ======
var (
	totalRequests    int64
	failedRequests   int64
	codeExecDuration float64
	searchDuration   float64
	metricsMutex     sync.RWMutex
)

type MCPRequest struct {
	JSONRPC string      `json:"jsonrpc"`
	Method  string      `json:"method"`
	Params  interface{} `json:"params,omitempty"`
	ID      interface{} `json:"id"`
}

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

type SerperResponse struct {
	Organic []struct {
		Title   string `json:"title"`
		Link    string `json:"link"`
		Snippet string `json:"snippet"`
	} `json:"organic"`
}

// createDockerClient 尝试以多种方式创建 Docker 客户端
func createDockerClient() (*client.Client, error) {
	cli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err == nil {
		_, err = cli.Ping(context.Background())
		if err == nil {
			return cli, nil
		}
		cli.Close()
	}

	var potentialHosts []string
	if runtime.GOOS == "darwin" {
		homeDir, err := os.UserHomeDir()
		if err == nil {
			orbstackSocket := fmt.Sprintf("unix://%s/.orbstack/run/docker.sock", homeDir)
			potentialHosts = append(potentialHosts, orbstackSocket)
		}
	}
	potentialHosts = append(potentialHosts, "unix:///var/run/docker.sock")

	var lastErr error
	for _, host := range potentialHosts {
		cli, err := client.NewClientWithOpts(client.WithHost(host), client.WithAPIVersionNegotiation())
		if err == nil {
			_, err = cli.Ping(context.Background())
			if err == nil {
				return cli, nil
			}
			cli.Close()
		}
		lastErr = err
	}

	if lastErr != nil {
		return nil, fmt.Errorf("failed to create docker client after trying multiple hosts: %w", lastErr)
	}
	return nil, fmt.Errorf("failed to create docker client: no suitable host found")
}

func ensureImageExists(ctx context.Context, cli *client.Client, imageName string, logger *zap.Logger) error {
	_, _, err := cli.ImageInspectWithRaw(ctx, imageName)
	if err == nil {
		return nil
	}

	logger.Info("Pulling Docker image", zap.String("image", imageName))
	reader, err := cli.ImagePull(ctx, imageName, image.PullOptions{})
	if err != nil {
		return fmt.Errorf("failed to pull image: %w", err)
	}
	defer reader.Close()

	_, err = io.Copy(io.Discard, reader)
	if err != nil {
		return fmt.Errorf("failed to read pull progress: %w", err)
	}

	logger.Info("Successfully pulled Docker image", zap.String("image", imageName))
	return nil
}

// executePythonInSandbox 执行 Python 代码（带资源限制和超时）
func executePythonInSandbox(code string, logger *zap.Logger) (string, error) {
	ctx := context.Background()

	cli, err := createDockerClient()
	if err != nil {
		return "", fmt.Errorf("failed to create docker client: %w", err)
	}
	defer cli.Close()

	// 缩进代码以适配 try 块
	indentedCode := ""
	lines := strings.Split(code, "\n")
	for _, line := range lines {
		indentedCode += "    " + line + "\n"
	}

	script := fmt.Sprintf(`
import sys
import traceback

try:
%s
except Exception as e:
    print("ERROR:", str(e), file=sys.stderr)
    traceback.print_exc(file=sys.stderr)
`, indentedCode)

	encodedScript := base64.StdEncoding.EncodeToString([]byte(script))
	// 注意：容器内是 Linux，base64 -d 完全兼容
	shellCmd := fmt.Sprintf("echo %s | base64 -d > /tmp/script.py && python /tmp/script.py", encodedScript)

	containerConfig := &container.Config{
		Image:        "python:3.11-slim",
		Cmd:          []string{"sh", "-c", shellCmd},
		AttachStdout: true,
		AttachStderr: true,
		Tty:          false,
	}

	hostConfig := &container.HostConfig{
		NetworkMode:    "none",
		ReadonlyRootfs: true,
		CapDrop:        []string{"ALL"},
		Resources: container.Resources{
			Memory:   128 * 1024 * 1024, // 128MB
			NanoCPUs: 500000000,         // 0.5 CPU
		},
		AutoRemove: true,
		Tmpfs: map[string]string{
			"/tmp": "rw,noexec,nosuid,size=10m",
		},
	}

	imageName := "python:3.11-slim"
	if err := ensureImageExists(ctx, cli, imageName, logger); err != nil {
		return "", fmt.Errorf("failed to ensure image exists: %w", err)
	}

	resp, err := cli.ContainerCreate(ctx, containerConfig, hostConfig, nil, nil, "")
	if err != nil {
		return "", fmt.Errorf("failed to create container: %w", err)
	}

	if err := cli.ContainerStart(ctx, resp.ID, container.StartOptions{}); err != nil {
		cli.ContainerRemove(ctx, resp.ID, container.RemoveOptions{Force: true})
		return "", fmt.Errorf("failed to start container: %w", err)
	}

	waitCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	statusCh, errCh := cli.ContainerWait(waitCtx, resp.ID, container.WaitConditionNotRunning)
	select {
	case err := <-errCh:
		cli.ContainerRemove(ctx, resp.ID, container.RemoveOptions{Force: true})
		return "", fmt.Errorf("container wait error: %w", err)
	case <-statusCh:
		// OK
	case <-waitCtx.Done():
		logger.Warn("Container execution timed out", zap.String("containerID", resp.ID))
		cli.ContainerRemove(ctx, resp.ID, container.RemoveOptions{Force: true})
		return "", fmt.Errorf("execution timed out after 5 seconds")
	}

	out, err := cli.ContainerLogs(ctx, resp.ID, container.LogsOptions{
		ShowStdout: true,
		ShowStderr: true,
	})
	if err != nil {
		return "", fmt.Errorf("failed to get logs: %w", err)
	}

	var stdoutBuf, stderrBuf bytes.Buffer
	_, err = stdcopy.StdCopy(&stdoutBuf, &stderrBuf, out)
	if err != nil {
		return "", fmt.Errorf("failed to decode logs: %w", err)
	}

	output := strings.TrimSpace(stdoutBuf.String())
	errors := strings.TrimSpace(stderrBuf.String())

	// 最终清理（AutoRemove 可能失败）
	cli.ContainerRemove(ctx, resp.ID, container.RemoveOptions{Force: true})

	if errors != "" {
		return fmt.Sprintf("Execution failed:\n%s", errors), nil
	}
	if output == "" {
		return "No output", nil
	}
	return output, nil
}

// ====== searchTool with retry (Day 4) ======
const maxRetries = 2
const retryDelay = 500 * time.Millisecond

func searchTool(query string, logger *zap.Logger) (interface{}, error) {
	apiKey := os.Getenv("SERPER_API_KEY")
	if apiKey == "" {
		return nil, fmt.Errorf("SERPER_API_KEY environment variable not set")
	}

	url := "https://google.serper.dev/search"
	payload := map[string]string{"q": query}
	body, _ := json.Marshal(payload)

	var lastErr error
	for attempt := 0; attempt <= maxRetries; attempt++ {
		if attempt > 0 {
			logger.Warn("Retrying Serper API call", zap.String("query", query), zap.Int("attempt", attempt))
			time.Sleep(retryDelay)
		}

		req, err := http.NewRequest("POST", url, bytes.NewBuffer(body))
		if err != nil {
			lastErr = err
			continue
		}
		req.Header.Set("X-API-KEY", apiKey)
		req.Header.Set("Content-Type", "application/json")

		client := &http.Client{Timeout: 10 * time.Second}
		resp, err := client.Do(req)
		if err != nil {
			lastErr = err
			logger.Warn("Serper API request failed", zap.Error(err), zap.Int("attempt", attempt))
			continue
		}

		if resp.StatusCode == http.StatusOK {
			defer resp.Body.Close()
			var serperResp SerperResponse
			if err := json.NewDecoder(resp.Body).Decode(&serperResp); err != nil {
				lastErr = err
				continue
			}

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

			return map[string]interface{}{"results": results}, nil
		} else {
			bodyBytes, _ := io.ReadAll(resp.Body)
			resp.Body.Close() // 关闭以便重试
			lastErr = fmt.Errorf("serper api returned %d: %s", resp.StatusCode, string(bodyBytes))
			logger.Warn("Serper API non-200 response",
				zap.Int("status", resp.StatusCode),
				zap.ByteString("body", bodyBytes),
				zap.Int("attempt", attempt))
		}
	}

	return nil, fmt.Errorf("search failed after %d retries: %w", maxRetries+1, lastErr)
}

// ====== MCP Handler with Metrics (Day 4) ======
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

		atomic.AddInt64(&totalRequests, 1)

		var req MCPRequest
		if err := json.Unmarshal(msg, &req); err != nil {
			atomic.AddInt64(&failedRequests, 1)
			logger.Error("Failed to unmarshal MCP request", zap.Error(err), zap.ByteString("raw", msg))
			continue
		}

		resp := MCPResponse{
			JSONRPC: "2.0",
			ID:      req.ID,
		}

		var hasError bool
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
					"description": "Execute Python code in a secure Docker sandbox",
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
			paramsBytes, _ := json.Marshal(req.Params)
			var callParams CallToolParams
			if err := json.Unmarshal(paramsBytes, &callParams); err != nil {
				hasError = true
				resp.Error = &MCPError{Code: -32602, Message: "Invalid params for call_tool"}
			} else {
				var result interface{}
				var execErr error

				start := time.Now()
				switch callParams.Name {
				case "search":
					query, ok := callParams.Args["query"].(string)
					if !ok || query == "" {
						execErr = fmt.Errorf("missing 'query' argument")
					} else {
						result, execErr = searchTool(query, logger)
					}
					metricsMutex.Lock()
					searchDuration += time.Since(start).Seconds()
					metricsMutex.Unlock()
				case "code_interpreter":
					code, ok := callParams.Args["code"].(string)
					if !ok || code == "" {
						execErr = fmt.Errorf("missing 'code' argument")
					} else {
						output, err := executePythonInSandbox(code, logger)
						if err != nil {
							execErr = fmt.Errorf("sandbox execution failed: %w", err)
						} else {
							result = map[string]string{"output": output}
						}
					}
					metricsMutex.Lock()
					codeExecDuration += time.Since(start).Seconds()
					metricsMutex.Unlock()
				default:
					execErr = fmt.Errorf("tool not found: %s", callParams.Name)
				}

				if execErr != nil {
					hasError = true
					resp.Error = &MCPError{Code: -32000, Message: execErr.Error()}
				} else {
					resp.Result = result
				}
			}
		default:
			hasError = true
			resp.Error = &MCPError{Code: -32601, Message: "Method not found: " + req.Method}
		}

		if hasError {
			atomic.AddInt64(&failedRequests, 1)
		}

		out, _ := json.Marshal(resp)
		if err := ws.WriteMessage(websocket.TextMessage, out); err != nil {
			logger.Error("Failed to write response", zap.Error(err))
			break
		}
	}
}

// ====== Main ======
func main() {
	logger, _ := zap.NewProduction()
	defer logger.Sync()

	// WebSocket endpoint
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

	// Metrics endpoint (Day 4)
	http.HandleFunc("/metrics", func(w http.ResponseWriter, r *http.Request) {
		total := atomic.LoadInt64(&totalRequests)
		failed := atomic.LoadInt64(&failedRequests)
		success := total - failed

		w.Header().Set("Content-Type", "text/plain; version=0.0.4")
		fmt.Fprintf(w, "# HELP mcp_total_requests Total number of MCP requests\n")
		fmt.Fprintf(w, "# TYPE mcp_total_requests counter\n")
		fmt.Fprintf(w, "mcp_total_requests %d\n", total)

		fmt.Fprintf(w, "# HELP mcp_failed_requests Number of failed MCP requests\n")
		fmt.Fprintf(w, "# TYPE mcp_failed_requests counter\n")
		fmt.Fprintf(w, "mcp_failed_requests %d\n", failed)

		fmt.Fprintf(w, "# HELP mcp_success_requests Number of successful MCP requests\n")
		fmt.Fprintf(w, "# TYPE mcp_success_requests counter\n")
		fmt.Fprintf(w, "mcp_success_requests %d\n", success)

		metricsMutex.RLock()
		fmt.Fprintf(w, "# HELP mcp_code_exec_duration_seconds Total duration of code interpreter executions\n")
		fmt.Fprintf(w, "# TYPE mcp_code_exec_duration_seconds counter\n")
		fmt.Fprintf(w, "mcp_code_exec_duration_seconds %f\n", codeExecDuration)

		fmt.Fprintf(w, "# HELP mcp_search_duration_seconds Total duration of search tool executions\n")
		fmt.Fprintf(w, "# TYPE mcp_search_duration_seconds counter\n")
		fmt.Fprintf(w, "mcp_search_duration_seconds %f\n", searchDuration)
		metricsMutex.RUnlock()
	})

	server := &http.Server{
		Addr:    ":8081",
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

	logger.Info("MCP Server started", zap.String("addr", ":8081"))
	if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		logger.Fatal("Server failed", zap.Error(err))
	}

	<-done
	logger.Info("Server stopped")
}
