Server starts on http://localhost:8080.

3. Test with wscat

Install wscat:

Bash

编辑



npm install -g wscat
Connect:

Bash

编辑



wscat -c ws://localhost:8080/mcp
Initialize & List Tools

Json

编辑



{"jsonrpc":"2.0","method":"initialize","id":1}
{"jsonrpc":"2.0","method":"list_tools","id":2}
