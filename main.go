// main.go (Day 3 版本)
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

// createDockerClient 尝试以多种方式创建 Docker 客户端，优先使用环境变量，然后尝试 OrbStack、Docker Desktop 和标准路径。
func createDockerClient() (*client.Client, error) {
	// 1. 优先尝试从环境变量创建客户端 (DOCKER_HOST)
	cli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err == nil {
		// 尝试 Ping Docker daemon 确认连接可用
		_, err = cli.Ping(context.Background())
		if err == nil {
			return cli, nil
		}
		cli.Close() // 如果 Ping 失败，关闭客户端
	}

	// 2. 如果环境变量失败，尝试其他常见路径
	var potentialHosts []string

	// OrbStack (macOS)
	if runtime.GOOS == "darwin" {
		homeDir, err := os.UserHomeDir()
		if err == nil {
			orbstackSocket := fmt.Sprintf("unix://%s/.orbstack/run/docker.sock", homeDir)
			potentialHosts = append(potentialHosts, orbstackSocket)
		}
	}

	// Docker Desktop (macOS/Windows WSL2) 和标准 Linux 路径
	potentialHosts = append(potentialHosts,
		"unix:///var/run/docker.sock",
	)

	var lastErr error
	for _, host := range potentialHosts {
		cli, err := client.NewClientWithOpts(client.WithHost(host), client.WithAPIVersionNegotiation())
		if err == nil {
			// 尝试 Ping Docker daemon 确认连接可用
			_, err = cli.Ping(context.Background())
			if err == nil {
				return cli, nil
			}
			cli.Close() // 如果 Ping 失败，关闭客户端
		}
		lastErr = err // 记录最后一个错误
	}

	if lastErr != nil {
		return nil, fmt.Errorf("failed to create docker client after trying multiple hosts: %w", lastErr)
	}
	return nil, fmt.Errorf("failed to create docker client: no suitable host found")
}

// ensureImageExists 确保指定的 Docker 镜像存在，如果不存在则自动拉取
func ensureImageExists(ctx context.Context, cli *client.Client, imageName string, logger *zap.Logger) error {
	// 检查镜像是否已存在
	_, _, err := cli.ImageInspectWithRaw(ctx, imageName)
	if err == nil {
		// 镜像已存在
		return nil
	}

	// 镜像不存在，开始拉取
	logger.Info("Pulling Docker image", zap.String("image", imageName))
	reader, err := cli.ImagePull(ctx, imageName, image.PullOptions{})
	if err != nil {
		return fmt.Errorf("failed to pull image: %w", err)
	}
	defer reader.Close()

	// 读取拉取进度（避免阻塞）
	_, err = io.Copy(io.Discard, reader)
	if err != nil {
		return fmt.Errorf("failed to read pull progress: %w", err)
	}

	logger.Info("Successfully pulled Docker image", zap.String("image", imageName))
	return nil
}

// ====== 新增：Docker 沙箱执行 Python ======
func executePythonInSandbox(code string, logger *zap.Logger) (string, error) {
	ctx := context.Background()

	// 创建 Docker 客户端，支持多种环境
	cli, err := createDockerClient()
	if err != nil {
		return "", fmt.Errorf("failed to create docker client: %w", err)
	}
	defer cli.Close()

	// 构建执行脚本：将用户代码写入 /tmp/script.py
	script := fmt.Sprintf(`
import sys
import traceback

try:
%s
except Exception as e:
    print("ERROR:", str(e), file=sys.stderr)
    traceback.print_exc(file=sys.stderr)
`, indentCode(code))

	// 对脚本进行 Base64 编码，避免 Shell 转义问题
	encodedScript := base64.StdEncoding.EncodeToString([]byte(script))
	// 构建 Shell 命令：解码 -> 写入 /tmp -> 执行
	shellCmd := fmt.Sprintf("echo %s | base64 -d > /tmp/script.py && python /tmp/script.py", encodedScript)

	// 创建临时容器配置
	containerConfig := &container.Config{
		Image:        "python:3.11-slim", // 轻量镜像
		Cmd:          []string{"sh", "-c", shellCmd},
		AttachStdout: true,
		AttachStderr: true,
		Tty:          false,
	}

	hostConfig := &container.HostConfig{
		NetworkMode:    "none",          // 禁用网络
		ReadonlyRootfs: true,            // ✅ 恢复只读根文件系统
		CapDrop:        []string{"ALL"}, // 移除所有特权，作为安全补偿
		Resources: container.Resources{
			Memory:   128 * 1024 * 1024, // 128MB
			NanoCPUs: 500000000,         // 0.5 CPU
		},
		AutoRemove: true, // 自动删除容器
		// 挂载 tmpfs 到 /tmp，使其在只读文件系统中可写
		Tmpfs: map[string]string{
			"/tmp": "rw,noexec,nosuid,size=10m",
		},
	}

	// 确保镜像存在（自动拉取）
	imageName := "python:3.11-slim"
	if err := ensureImageExists(ctx, cli, imageName, logger); err != nil {
		return "", fmt.Errorf("failed to ensure image exists: %w", err)
	}

	// 创建容器
	resp, err := cli.ContainerCreate(ctx, containerConfig, hostConfig, nil, nil, "")
	if err != nil {
		return "", fmt.Errorf("failed to create container: %w", err)
	}

	// 启动容器
	if err := cli.ContainerStart(ctx, resp.ID, container.StartOptions{}); err != nil {
		cli.ContainerRemove(ctx, resp.ID, container.RemoveOptions{Force: true})
		return "", fmt.Errorf("failed to start container: %w", err)
	}

	// 等待完成（带超时）
	waitCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	statusCh, errCh := cli.ContainerWait(waitCtx, resp.ID, container.WaitConditionNotRunning)
	select {
	case err := <-errCh:
		if err != nil {
			return "", fmt.Errorf("container wait error: %w", err)
		}
	case <-statusCh:
		// 正常退出或超时
	}

	// 获取日志
	out, err := cli.ContainerLogs(ctx, resp.ID, container.LogsOptions{
		ShowStdout: true,
		ShowStderr: true,
	})
	if err != nil {
		return "", fmt.Errorf("failed to get logs: %w", err)
	}

	// 解析 stdout/stderr（Docker 使用 multiplexed 格式）
	var stdoutBuf, stderrBuf bytes.Buffer
	_, err = stdcopy.StdCopy(&stdoutBuf, &stderrBuf, out)
	if err != nil {
		return "", fmt.Errorf("failed to decode logs: %w", err)
	}

	output := strings.TrimSpace(stdoutBuf.String())
	errors := strings.TrimSpace(stderrBuf.String())

	// 强制删除容器（双重保险）
	cli.ContainerRemove(ctx, resp.ID, container.RemoveOptions{Force: true})

	// 如果有错误，返回错误信息
	if errors != "" {
		return fmt.Sprintf("Execution failed:\n%s", errors), nil
	}

	if output == "" {
		return "No output", nil
	}
	return output, nil
}

// 辅助：缩进用户代码（Python 对缩进敏感）
func indentCode(code string) string {
	lines := strings.Split(code, "\n")
	for i, line := range lines {
		lines[i] = "\t" + line
	}
	return strings.Join(lines, "\n")
}

// ====== 原有 searchTool 函数（略作优化） ======
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

// ====== MCP 处理逻辑 ======
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

// ====== Main ======
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
