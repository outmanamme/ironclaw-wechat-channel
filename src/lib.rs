// ── 签名验证 ──────────────────────────────────────────────────────────

/// 验证企业微信回调签名（SHA1）。
///
/// 算法：将 token/timestamp/nonce/(可选)msg_encrypt 按字典序排序后拼接，SHA1 哈希。
fn verify_signature(
    token: &str,
    timestamp: &str,
    nonce: &str,
    msg_encrypt: Option<&str>,
    expected: &str,
) -> bool {
    use sha1::{Digest, Sha1};
    let mut parts: Vec<&str> = vec![token, timestamp, nonce];
    if let Some(enc) = msg_encrypt {
        parts.push(enc);
    }
    parts.sort_unstable();
    let combined = parts.join("");
    let mut h = Sha1::new();
    h.update(combined.as_bytes());
    hex::encode(h.finalize()) == expected
}

// ── XML 解析 ──────────────────────────────────────────────────────────

struct WxMessage {
    from_user: String,
    to_user: String,
    msg_type: String,
    content: String,
    msg_id: String,
}

/// 解析企业微信明文模式消息 XML。
fn parse_wx_message(xml: &str) -> Result<WxMessage, String> {
    Ok(WxMessage {
        from_user: extract_cdata(xml, "FromUserName")
            .ok_or("缺少 FromUserName")?,
        to_user: extract_cdata(xml, "ToUserName").unwrap_or_default(),
        msg_type: extract_cdata(xml, "MsgType").ok_or("缺少 MsgType")?,
        content: extract_cdata(xml, "Content").unwrap_or_default(),
        msg_id: extract_text(xml, "MsgId").unwrap_or_default(),
    })
}

fn extract_cdata(xml: &str, tag: &str) -> Option<String> {
    let open = format!("<{}>", tag);
    let close = format!("</{}>", tag);
    let start = xml.find(&open)? + open.len();
    let end = xml[start..].find(&close)? + start;
    let raw = &xml[start..end];
    if raw.starts_with("<![CDATA[") && raw.ends_with("]]>") {
        Some(raw[9..raw.len() - 3].to_string())
    } else {
        Some(raw.to_string())
    }
}

fn extract_text(xml: &str, tag: &str) -> Option<String> {
    let open = format!("<{}>", tag);
    let close = format!("</{}>", tag);
    let start = xml.find(&open)? + open.len();
    let end = xml[start..].find(&close)? + start;
    Some(xml[start..end].to_string())
}

// ── 查询参数解析 ──────────────────────────────────────────────────────

/// 从 JSON query 对象提取指定参数值。
fn query_param_from_json(query_json: &str, key: &str) -> Option<String> {
    let parsed: serde_json::Value = serde_json::from_str(query_json).ok()?;
    parsed.get(key)?.as_str().map(String::from)
}

wit_bindgen::generate!({
    world: "sandboxed-channel",
    path: "wit/channel.wit",
});

use exports::near::agent::channel::{
    AgentResponse, ChannelConfig, Guest, HttpEndpointConfig,
    IncomingHttpRequest, OutgoingHttpResponse, StatusUpdate,
};
use near::agent::channel_host::{self, EmittedMessage};
use serde::Deserialize;

// ── 持久化 key（workspace_write/read） ───────────────────────────────
const TOKEN_KEY: &str = "access_token";
const TOKEN_EXPIRY_KEY: &str = "access_token_expiry_ms";
const CONFIG_CORP_ID_KEY: &str = "corp_id";
const CONFIG_AGENT_ID_KEY: &str = "agent_id";
const CONFIG_TOKEN_KEY: &str = "wx_token";
const CONFIG_ALLOW_FROM_KEY: &str = "allow_from_json";

const QYAPI_BASE: &str = "https://qyapi.weixin.qq.com/cgi-bin";
/// 提前 5 分钟刷新 token（单位：毫秒）
const TOKEN_REFRESH_BUFFER_MS: u64 = 5 * 60 * 1000;

// ── 配置结构 ──────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
struct WechatWorkConfig {
    corp_id: String,
    agent_id: i64,
    /// 企业微信回调验证 Token（非 access_token）
    wx_token: String,
    /// 允许接收消息的用户 ID 列表，空 = 拒绝所有
    #[serde(default)]
    allow_from: Vec<String>,
}

// ── 企业微信 API 响应结构 ─────────────────────────────────────────────

#[derive(Debug, Deserialize)]
struct TokenApiResponse {
    errcode: Option<i64>,
    errmsg: Option<String>,
    access_token: Option<String>,
    expires_in: Option<u64>,
}

#[derive(Debug, Deserialize)]
struct SendApiResponse {
    errcode: i64,
    errmsg: String,
}

// ── 主体实现 ──────────────────────────────────────────────────────────

struct WechatWorkChannel;

impl Guest for WechatWorkChannel {
    /// 初始化：解析 config，持久化到 workspace，返回 HTTP 路由配置。
    fn on_start(config_json: String) -> Result<ChannelConfig, String> {
        channel_host::log(
            channel_host::LogLevel::Debug,
            &format!("[wechat-work] on_start config: {}", config_json),
        );

        let config: WechatWorkConfig = serde_json::from_str(&config_json)
            .map_err(|e| format!("配置解析失败: {}", e))?;

        // 持久化配置供后续回调使用（WASM 无共享状态，每次回调是新实例）
        channel_host::workspace_write(CONFIG_CORP_ID_KEY, &config.corp_id)
            .map_err(|e| format!("写入 corp_id 失败: {}", e))?;
        channel_host::workspace_write(CONFIG_AGENT_ID_KEY, &config.agent_id.to_string())
            .map_err(|e| format!("写入 agent_id 失败: {}", e))?;
        channel_host::workspace_write(CONFIG_TOKEN_KEY, &config.wx_token)
            .map_err(|e| format!("写入 wx_token 失败: {}", e))?;

        let allow_from_json = serde_json::to_string(&config.allow_from)
            .unwrap_or_else(|_| "[]".to_string());
        channel_host::workspace_write(CONFIG_ALLOW_FROM_KEY, &allow_from_json)
            .map_err(|e| format!("写入 allow_from 失败: {}", e))?;

        channel_host::log(
            channel_host::LogLevel::Info,
            &format!(
                "[wechat-work] 初始化成功 corp_id={} agent_id={} allow_from_count={}",
                config.corp_id,
                config.agent_id,
                config.allow_from.len()
            ),
        );

        if config.allow_from.is_empty() {
            channel_host::log(
                channel_host::LogLevel::Warn,
                "[wechat-work] allow_from 为空 — 所有消息将被拒绝！请在 capabilities.json 的 config.allow_from 中添加用户 ID",
            );
        }

        Ok(ChannelConfig {
            display_name: "企业微信".to_string(),
            http_endpoints: vec![HttpEndpointConfig {
                path: "/webhook/wechat-work".to_string(),
                methods: vec!["GET".to_string(), "POST".to_string()],
                require_secret: false,
            }],
            poll: None,
        })
    }

    /// 处理企业微信 HTTP 回调（GET=URL验证，POST=消息）。
    fn on_http_request(req: IncomingHttpRequest) -> OutgoingHttpResponse {
        channel_host::log(
            channel_host::LogLevel::Debug,
            &format!(
                "[wechat-work] on_http_request method={} query_json={}",
                req.method, req.query_json
            ),
        );

        match req.method.as_str() {
            "GET" => handle_verify(&req),
            "POST" => handle_message(&req),
            _ => {
                channel_host::log(
                    channel_host::LogLevel::Warn,
                    &format!("[wechat-work] 未知 HTTP 方法: {}", req.method),
                );
                text_response(405, "Method Not Allowed")
            }
        }
    }

    fn on_poll() {
        // 企业微信走 webhook 推送，不需要轮询
    }

    /// 发送 Agent 回复给企业微信用户。
    fn on_respond(response: AgentResponse) -> Result<(), String> {
        channel_host::log(
            channel_host::LogLevel::Info,
            &format!(
                "[wechat-work] on_respond message_id={} content_len={}",
                response.message_id,
                response.content.len()
            ),
        );

        // 从 metadata 取 touser
        let touser = serde_json::from_str::<serde_json::Value>(&response.metadata_json)
            .ok()
            .and_then(|v| v["wechat_work_from_user"].as_str().map(String::from))
            .unwrap_or_else(|| {
                channel_host::log(
                    channel_host::LogLevel::Warn,
                    "[wechat-work] metadata 中无 wechat_work_from_user，使用空字符串",
                );
                String::new()
            });

        send_text_message(&touser, &response.content)
    }

    fn on_status(_update: StatusUpdate) {
        // 企业微信不支持"正在输入"状态
    }

    fn on_broadcast(user_id: String, response: AgentResponse) -> Result<(), String> {
        channel_host::log(
            channel_host::LogLevel::Info,
            &format!("[wechat-work] on_broadcast user_id={}", user_id),
        );
        send_text_message(&user_id, &response.content)
    }

    fn on_shutdown() {
        channel_host::log(channel_host::LogLevel::Info, "[wechat-work] 关闭");
    }
}

// ── GET 处理：URL 验证 ────────────────────────────────────────────────

fn handle_verify(req: &IncomingHttpRequest) -> OutgoingHttpResponse {
    let msg_signature = query_param_from_json(&req.query_json, "msg_signature")
        .unwrap_or_else(|| query_param_from_json(&req.query_json, "signature").unwrap_or_default());
    let timestamp = query_param_from_json(&req.query_json, "timestamp").unwrap_or_default();
    let nonce = query_param_from_json(&req.query_json, "nonce").unwrap_or_default();
    let echostr = query_param_from_json(&req.query_json, "echostr").unwrap_or_default();

    channel_host::log(
        channel_host::LogLevel::Info,
        &format!(
            "[wechat-work] URL 验证请求 timestamp={} nonce={}",
            timestamp, nonce
        ),
    );

    let wx_token = match channel_host::workspace_read(CONFIG_TOKEN_KEY) {
        Some(t) => t,
        None => {
            channel_host::log(
                channel_host::LogLevel::Error,
                "[wechat-work] wx_token 未配置，URL 验证失败",
            );
            return text_response(500, "token not configured");
        }
    };

    if wx_token.is_empty() {
        channel_host::log(
            channel_host::LogLevel::Error,
            "[wechat-work] wx_token 为空，URL 验证失败",
        );
        return text_response(500, "token not configured");
    }

    if verify_signature(&wx_token, &timestamp, &nonce, None, &msg_signature) {
        channel_host::log(
            channel_host::LogLevel::Info,
            "[wechat-work] URL 验证通过，返回 echostr",
        );
        text_response(200, &echostr)
    } else {
        channel_host::log(
            channel_host::LogLevel::Error,
            "[wechat-work] URL 验证签名不匹配！请检查 capabilities.json 中 config.wx_token 与企业微信后台 Token 是否一致",
        );
        text_response(403, "signature mismatch")
    }
}

// ── POST 处理：接收消息 ───────────────────────────────────────────────

fn handle_message(req: &IncomingHttpRequest) -> OutgoingHttpResponse {
    let body = match String::from_utf8(req.body.clone()) {
        Ok(s) => s,
        Err(e) => {
            channel_host::log(
                channel_host::LogLevel::Error,
                &format!("[wechat-work] 请求体 UTF-8 解码失败: {}", e),
            );
            return text_response(400, "invalid body");
        }
    };

    channel_host::log(
        channel_host::LogLevel::Debug,
        &format!("[wechat-work] 收到消息回调，原始 XML: {}", body),
    );

    // 验证签名
    let msg_signature = query_param_from_json(&req.query_json, "msg_signature")
        .unwrap_or_else(|| query_param_from_json(&req.query_json, "signature").unwrap_or_default());
    let timestamp = query_param_from_json(&req.query_json, "timestamp").unwrap_or_default();
    let nonce = query_param_from_json(&req.query_json, "nonce").unwrap_or_default();

    if !msg_signature.is_empty() {
        let wx_token = match channel_host::workspace_read(CONFIG_TOKEN_KEY) {
            Some(t) => t,
            None => {
                channel_host::log(
                    channel_host::LogLevel::Error,
                    "[wechat-work] wx_token 未配置，无法验证签名",
                );
                return text_response(200, "ok");
            }
        };
        if !verify_signature(&wx_token, &timestamp, &nonce, None, &msg_signature) {
            channel_host::log(
                channel_host::LogLevel::Error,
                "[wechat-work] 消息签名验证失败，忽略",
            );
            return text_response(200, "ok");
        }
    }

    // 解析 XML
    let msg = match parse_wx_message(&body) {
        Ok(m) => m,
        Err(e) => {
            channel_host::log(
                channel_host::LogLevel::Error,
                &format!("[wechat-work] XML 解析失败: {} 原始: {}", e, body),
            );
            return text_response(200, "ok");
        }
    };

    channel_host::log(
        channel_host::LogLevel::Info,
        &format!(
            "[wechat-work] 收到消息 from={} type={} content={}",
            msg.from_user, msg.msg_type, msg.content
        ),
    );

    // 检查白名单
    let allow_from: Vec<String> = channel_host::workspace_read(CONFIG_ALLOW_FROM_KEY)
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default();

    if !allow_from.is_empty() && !allow_from.contains(&msg.from_user) {
        channel_host::log(
            channel_host::LogLevel::Warn,
            &format!(
                "[wechat-work] 用户 {} 不在 allow_from 白名单，忽略消息",
                msg.from_user
            ),
        );
        return text_response(200, "ok");
    }

    // 只处理文本消息
    if msg.msg_type != "text" {
        channel_host::log(
            channel_host::LogLevel::Debug,
            &format!("[wechat-work] 非文本消息 type={}，忽略", msg.msg_type),
        );
        return text_response(200, "ok");
    }

    // 构造 metadata（用于 on_respond 时知道回复给谁）
    let metadata = serde_json::json!({
        "wechat_work_from_user": msg.from_user,
        "wechat_work_to_user": msg.to_user,
        "wechat_work_msg_id": msg.msg_id,
    });

    let emitted = EmittedMessage {
        user_id: msg.from_user.clone(),
        user_name: None,
        content: msg.content,
        thread_id: None,
        metadata_json: metadata.to_string(),
        attachments: vec![],
    };

    channel_host::emit_message(&emitted);

    text_response(200, "ok")
}

// ── 发送消息（含详细日志） ────────────────────────────────────────────

/// 获取有效的 access_token（自动刷新，缓存到 workspace）。
fn get_access_token() -> Result<String, String> {
    let now_ms = channel_host::now_millis();

    // 检查缓存
    let cached_token = channel_host::workspace_read(TOKEN_KEY).unwrap_or_default();
    let expiry_ms: u64 = channel_host::workspace_read(TOKEN_EXPIRY_KEY)
        .unwrap_or_default()
        .parse()
        .unwrap_or(0);

    if !cached_token.is_empty() && now_ms + TOKEN_REFRESH_BUFFER_MS < expiry_ms {
        channel_host::log(
            channel_host::LogLevel::Debug,
            &format!(
                "[wechat-work] access_token 命中缓存，剩余约 {} 秒",
                (expiry_ms - now_ms) / 1000
            ),
        );
        return Ok(cached_token);
    }

    // 刷新 token
    let corp_id = channel_host::workspace_read(CONFIG_CORP_ID_KEY).unwrap_or_default();

    channel_host::log(
        channel_host::LogLevel::Info,
        &format!("[wechat-work] 刷新 access_token corp_id={}", corp_id),
    );

    // secret 由 host 通过 credential injection 注入
    let url = format!(
        "{}/gettoken?corpid={}&corpsecret={{{{wechat_work_secret}}}}",
        QYAPI_BASE, corp_id
    );

    let headers = serde_json::json!({"Content-Type": "application/json"}).to_string();
    let resp = channel_host::http_request("GET", &url, &headers, None, None)
        .map_err(|e| format!("gettoken HTTP 请求失败: {}", e))?;

    let body_str = String::from_utf8_lossy(&resp.body).to_string();

    channel_host::log(
        channel_host::LogLevel::Info,
        &format!(
            "[wechat-work] gettoken 响应 http_status={} body={}",
            resp.status, body_str
        ),
    );

    let parsed: TokenApiResponse = serde_json::from_str(&body_str)
        .map_err(|e| format!("gettoken 响应解析失败: {} 原始: {}", e, body_str))?;

    if let Some(errcode) = parsed.errcode {
        if errcode != 0 {
            let errmsg = parsed.errmsg.unwrap_or_default();
            channel_host::log(
                channel_host::LogLevel::Error,
                &format!(
                    "[wechat-work] 获取 access_token 失败 errcode={} errmsg={}\n\
                    错误码含义见：https://developer.work.weixin.qq.com/document/path/90313",
                    errcode, errmsg
                ),
            );
            return Err(format!("gettoken 失败 errcode={} errmsg={}", errcode, errmsg));
        }
    }

    let token = parsed.access_token
        .ok_or_else(|| format!("gettoken 响应无 access_token 字段，原始: {}", body_str))?;
    let expires_in = parsed.expires_in.unwrap_or(7200);

    // 缓存 token
    let expiry = now_ms + expires_in * 1000;
    let _ = channel_host::workspace_write(TOKEN_KEY, &token);
    let _ = channel_host::workspace_write(TOKEN_EXPIRY_KEY, &expiry.to_string());

    channel_host::log(
        channel_host::LogLevel::Info,
        &format!("[wechat-work] access_token 刷新成功，有效期 {} 秒", expires_in),
    );

    Ok(token)
}

/// 发送文本消息给企业微信用户。
fn send_text_message(touser: &str, content: &str) -> Result<(), String> {
    let token = get_access_token()?;

    let agent_id: i64 = channel_host::workspace_read(CONFIG_AGENT_ID_KEY)
        .unwrap_or_default()
        .parse()
        .unwrap_or(0);

    let body = serde_json::json!({
        "touser": touser,
        "msgtype": "text",
        "agentid": agent_id,
        "text": { "content": content }
    });
    let body_str = body.to_string();

    channel_host::log(
        channel_host::LogLevel::Debug,
        &format!(
            "[wechat-work] 发送消息 touser={} agent_id={} content_len={}",
            touser, agent_id, content.len()
        ),
    );

    let url = format!("{}/message/send?access_token={}", QYAPI_BASE, token);
    let headers = serde_json::json!({"Content-Type": "application/json"}).to_string();

    let resp = channel_host::http_request(
        "POST",
        &url,
        &headers,
        Some(body_str.as_bytes()),
        None,
    )
    .map_err(|e| format!("发送消息 HTTP 请求失败: {}", e))?;

    let resp_str = String::from_utf8_lossy(&resp.body).to_string();

    // 打印完整响应体（HTTP 200 不代表成功！）
    channel_host::log(
        channel_host::LogLevel::Info,
        &format!(
            "[wechat-work] 发送消息 API 响应 http_status={} body={}\n\
            （注意：HTTP 200 不代表成功，需检查 errcode）",
            resp.status, resp_str
        ),
    );

    let parsed: SendApiResponse = serde_json::from_str(&resp_str)
        .map_err(|e| format!("响应解析失败: {} 原始: {}", e, resp_str))?;

    if parsed.errcode != 0 {
        // 打印 ERROR + curl 命令，方便调试
        channel_host::log(
            channel_host::LogLevel::Error,
            &format!(
                "[wechat-work] 发送消息失败！\n\
                errcode={} errmsg={}\n\
                touser={} agent_id={}\n\
                \n\
                错误码含义：https://developer.work.weixin.qq.com/document/path/90313\n\
                \n\
                手动复现（替换 ACCESS_TOKEN）：\n\
                curl -X POST 'https://qyapi.weixin.qq.com/cgi-bin/message/send?access_token=ACCESS_TOKEN' \\\n\
                  -H 'Content-Type: application/json' \\\n\
                  -d '{}'",
                parsed.errcode, parsed.errmsg,
                touser, agent_id,
                body_str
            ),
        );
        return Err(format!(
            "发送失败 errcode={} errmsg={}",
            parsed.errcode, parsed.errmsg
        ));
    }

    channel_host::log(
        channel_host::LogLevel::Info,
        &format!("[wechat-work] 消息发送成功 touser={}", touser),
    );
    Ok(())
}

// ── HTTP 响应辅助 ─────────────────────────────────────────────────────

fn text_response(status: u16, body: &str) -> OutgoingHttpResponse {
    OutgoingHttpResponse {
        status,
        headers_json: r#"{"Content-Type": "text/plain"}"#.to_string(),
        body: body.as_bytes().to_vec(),
    }
}

export!(WechatWorkChannel);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_cdata() {
        let xml = r#"<xml><FromUserName><![CDATA[lisi]]></FromUserName></xml>"#;
        assert_eq!(extract_cdata(xml, "FromUserName"), Some("lisi".to_string()));
    }

    #[test]
    fn test_extract_text() {
        let xml = r#"<xml><MsgId>9876543210</MsgId></xml>"#;
        assert_eq!(extract_text(xml, "MsgId"), Some("9876543210".to_string()));
    }

    #[test]
    fn test_parse_wx_message() {
        let xml = r#"<xml>
            <ToUserName><![CDATA[ww123]]></ToUserName>
            <FromUserName><![CDATA[zhangsan]]></FromUserName>
            <MsgType><![CDATA[text]]></MsgType>
            <Content><![CDATA[你好]]></Content>
            <MsgId>1234</MsgId>
        </xml>"#;
        let msg = parse_wx_message(xml).unwrap();
        assert_eq!(msg.from_user, "zhangsan");
        assert_eq!(msg.msg_type, "text");
        assert_eq!(msg.content, "你好");
    }

    #[test]
    fn test_query_param_from_json() {
        let q = r#"{"msg_signature":"abc","timestamp":"123","nonce":"xyz","echostr":"hello"}"#;
        assert_eq!(query_param_from_json(q, "timestamp"), Some("123".to_string()));
        assert_eq!(query_param_from_json(q, "echostr"), Some("hello".to_string()));
        assert_eq!(query_param_from_json(q, "missing"), None);
    }

    #[test]
    fn test_verify_signature_sorts() {
        use sha1::{Digest, Sha1};
        let token = "testtoken";
        let ts = "1234567890";
        let nonce = "abcnonce";
        let mut parts = vec![token, ts, nonce];
        parts.sort_unstable();
        let combined = parts.join("");
        let mut h = Sha1::new();
        h.update(combined.as_bytes());
        let expected = hex::encode(h.finalize());
        assert!(verify_signature(token, ts, nonce, None, &expected));
    }
}
