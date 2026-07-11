"""
Python stdio <-> SSE 转换器原型
行为：
- 启动时 GET http://127.0.0.1:9877/sse 拿 SSE 流 + sessionId
- 读 stdin 的 JSON-RPC 请求 → POST 到 /message?sessionId=xxx
- 读 SSE 流里 event: message 数据 → 写 stdout
- 读 SSE 流里 event: endpoint → 更新 endpoint 路径（兼容 mcp-proxy.jar 那种拼接）
"""
import sys, json, threading, urllib.request, urllib.error

SSE_URL = 'http://127.0.0.1:9877/sse'

def sse_to_stdout(sess_id_box, stop_event):
    """读 SSE 流，把 message 事件写 stdout"""
    try:
        req = urllib.request.Request(SSE_URL)
        with urllib.request.urlopen(req, timeout=None) as resp:
            print(f'[bridge-py] SSE connected, content-type={resp.headers.get("Content-Type")}', file=sys.stderr, flush=True)
            for line in resp:
                if stop_event.is_set():
                    break
                text = line.decode('utf-8', errors='ignore').rstrip()
                if not text: continue
                if text.startswith('event: '):
                    sess_id_box['event'] = text[7:].strip()
                elif text.startswith('data: '):
                    sess_id_box['data'] = text[6:]
                    if sess_id_box.get('event') == 'endpoint':
                        # 解析 endpoint 路径
                        ep = sess_id_box['data'].strip()
                        # 如果是绝对 URL，转为相对路径
                        if '://' in ep:
                            from urllib.parse import urlparse
                            p = urlparse(ep)
                            sess_id_box['endpoint'] = p.path + ('?' + p.query if p.query else '')
                        else:
                            sess_id_box['endpoint'] = ep
                        print(f'[bridge-py] endpoint: {sess_id_box["endpoint"]}', file=sys.stderr, flush=True)
                    elif sess_id_box.get('event') == 'message':
                        # 写 stdout 给 ZCode
                        sys.stdout.write(sess_id_box['data'] + '\n')
                        sys.stdout.flush()
    except Exception as e:
        print(f'[bridge-py] SSE error: {e}', file=sys.stderr, flush=True)

def main():
    sess_id_box = {}
    stop_event = threading.Event()
    # 启动 SSE 读线程
    t = threading.Thread(target=sse_to_stdout, args=(sess_id_box, stop_event), daemon=True)
    t.start()
    # 等 SSE 流建立（拿到 endpoint 路径）
    import time
    for _ in range(50):  # 5 秒超时
        if 'endpoint' in sess_id_box:
            break
        time.sleep(0.1)
    if 'endpoint' not in sess_id_box:
        print('[bridge-py] SSE failed to provide endpoint', file=sys.stderr, flush=True)
        return
    ep = sess_id_box['endpoint']
    print(f'[bridge-py] ready, endpoint={ep}', file=sys.stderr, flush=True)
    # 主循环：stdin -> POST endpoint
    for line in sys.stdin:
        msg = line.strip()
        if not msg: continue
        try:
            data = msg.encode()
            req = urllib.request.Request(
                f'http://127.0.0.1:9877{ep}',
                data=data,
                method='POST',
                headers={'Content-Type': 'application/json', 'Accept': 'application/json, text/event-stream'}
            )
            with urllib.request.urlopen(req, timeout=10) as resp:
                # 202 Accepted, response 在 SSE 流里
                pass
        except Exception as e:
            print(f'[bridge-py] POST error: {e}', file=sys.stderr, flush=True)
            err = {'jsonrpc': '2.0', 'id': None, 'error': {'code': -32603, 'message': str(e)}}
            sys.stdout.write(json.dumps(err) + '\n')
            sys.stdout.flush()

if __name__ == '__main__':
    main()
