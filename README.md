# llm-safe-executor

[![Go](https://img.shields.io/badge/Go-1.21+-00ADD8?logo=go)](https://golang.org)
[![MCP](https://img.shields.io/badge/MCP-Compatible-brightgreen)](https://modelcontextprotocol.io)

A secure, lightweight, and production-ready **Tool Execution Engine** for LLM Agents, compliant with the [Model Context Protocol (MCP)](https://modelcontextprotocol.io).

> 🔒 Designed for AI Infra: Sandboxed execution, observability, and enterprise security from day one.

## ✨ Features

- ✅ **MCP Protocol Support**: Works with TRAE, Cursor, Continue.dev, and LangGraph
- 🛡️ **Security First**: Future support for Docker sandboxing (`code_interpreter`)
- 📊 **Production Ready**: Health checks, structured logging, graceful shutdown
- ⚡ **High Performance**: Built in Go for low latency and high concurrency

## 🚀 Quick Start

```bash
go run main.go