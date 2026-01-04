# llm-safe-executor

[![Go](https://img.shields.io/badge/Go-1.21%2B-00ADD8?logo=go)](https://golang.org)
[![MCP](https://img.shields.io/badge/MCP-Compatible-brightgreen)](https://modelcontextprotocol.io)

A secure, lightweight, and production-ready **Tool Execution Engine** for LLM Agents, compliant with the [Model Context Protocol (MCP)](https://modelcontextprotocol.io).

> 🔒 Designed for AI Infra: Sandboxed execution, observability, and enterprise security from day one.

## ✨ Features

- ✅ **MCP Protocol Support**: Works with TRAE, Cursor, Continue.dev, and LangGraph
- 🔍 **Real `search` Tool**: Integrates with Serper API for web search
- 🛡️ **Security First**: Future support for Docker sandboxing (`code_interpreter`)
- 📊 **Production Ready**: Health checks, structured logging, graceful shutdown
- ⚡ **High Performance**: Built in Go for low latency and high concurrency

## 🎯 Why This Project?

Most Agent demos use Python and ignore **security**, **observability**, and **scalability**.  
This project demonstrates how to build the **infrastructure layer** that powers real-world LLM applications — the part that AI companies actually hire Golang engineers to build.

Unlike toy projects, this runtime is designed to be:
- Deployable in Kubernetes
- Safe for executing untrusted code (coming in Day 3)
- Observable via standard metrics
- Compatible with industry-standard protocols (MCP)

## 🚀 Quick Start

### 1. Get a Serper API Key (Free)
- Go to [https://serper.dev](https://serper.dev)
- Sign up for a free account
- Copy your API key

### 2. Run the Server
```bash
# Set your API key
export SERPER_API_KEY=your_actual_api_key_here

# Run
go run main.go