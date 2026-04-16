use std::fmt::Write;

use revm_inspectors::tracing::{types::CallTraceNode, CallTraceArena};

/// Simple trace renderer that formats traces as human-readable text
pub struct TraceRenderer {
    /// Whether to include gas usage information
    include_gas: bool,
    /// Whether to include return data
    include_return_data: bool,
    /// Maximum depth to render (None = unlimited)
    max_depth: Option<usize>,
}

impl TraceRenderer {
    /// Create a new trace renderer with default settings
    pub fn new() -> Self {
        Self { include_gas: true, include_return_data: true, max_depth: None }
    }

    /// Render a trace arena as formatted text
    pub fn render_arena(&self, arena: &CallTraceArena) -> String {
        let mut output = String::new();
        if !arena.nodes().is_empty() {
            self.render_node(&mut output, arena, 0, 0);
        }
        output
    }

    /// Render a single node and its children
    fn render_node(
        &self,
        output: &mut String,
        arena: &CallTraceArena,
        node_index: usize,
        depth: usize,
    ) {
        // Check max depth
        if let Some(max_depth) = self.max_depth {
            if depth >= max_depth {
                return;
            }
        }

        let nodes = arena.nodes();
        if node_index >= nodes.len() {
            return;
        }

        let node = &nodes[node_index];

        // Write indentation
        let indent = "  ".repeat(depth);
        let _ = write!(output, "{}", indent);

        // Render the trace
        self.render_trace(output, node, depth == 0);

        // Render children
        for &child_index in &node.children {
            self.render_node(output, arena, child_index, depth + 1);
        }
    }

    /// Render a single trace line
    fn render_trace(&self, output: &mut String, node: &CallTraceNode, _is_root: bool) {
        let trace = &node.trace;

        // Get the decoded trace if available
        let decoded = trace
            .decoded
            .as_ref()
            .map(|d| d.as_ref());

        // Address and label
        let address_str = if let Some(decoded) = decoded {
            if let Some(label) = &decoded.label {
                format!("{}[{}]", label, trace.address)
            } else {
                format!("{}", trace.address)
            }
        } else {
            format!("{}", trace.address)
        };

        // Call signature
        let call_str = if let Some(decoded) = decoded {
            if let Some(call_data) = &decoded.call_data {
                if call_data.args.is_empty() {
                    call_data.signature.clone()
                } else {
                    format!(
                        "{}({})",
                        call_data
                            .signature
                            .split('(')
                            .next()
                            .unwrap_or(&call_data.signature),
                        call_data.args.join(", ")
                    )
                }
            } else if trace.data.is_empty() {
                "()".to_string()
            } else {
                format!("0x{}", hex::encode(&trace.data))
            }
        } else if trace.data.is_empty() {
            "()".to_string()
        } else {
            format!("0x{}", hex::encode(&trace.data))
        };

        // Build the line
        let _ = write!(output, "[{}] {}::{}", trace.depth, address_str, call_str);

        // Add gas info if requested
        if self.include_gas {
            let _ = write!(output, " [gas: {}]", trace.gas_used);
        }

        // Add success/failure indicator
        if trace.success {
            let _ = write!(output, " ✓");
        } else {
            let _ = write!(output, " ✗");
        }

        let _ = writeln!(output);

        // Add return data if requested and available (on a new line with indentation)
        if self.include_return_data {
            if let Some(decoded) = decoded {
                if let Some(return_data) = &decoded.return_data {
                    let return_indent = "  ".repeat(trace.depth + 1);
                    let _ = writeln!(output, "{}→ {}", return_indent, return_data);
                }
            } else if !trace.output.is_empty() {
                let return_indent = "  ".repeat(trace.depth + 1);
                let _ = writeln!(output, "{}→ 0x{}", return_indent, hex::encode(&trace.output));
            }
        }

        // Render logs for this trace
        for log in &node.logs {
            self.render_log(output, log);
        }
    }

    /// Render a log entry
    fn render_log(&self, output: &mut String, log: &revm_inspectors::tracing::types::CallLog) {
        let indent = "    "; // Extra indentation for logs
        let _ = write!(output, "{}├─ ", indent);

        if let Some(decoded) = &log.decoded {
            if let Some(name) = &decoded.name {
                let _ = write!(output, "emit {}(", name);
                if let Some(params) = &decoded.params {
                    let param_strs: Vec<String> = params
                        .iter()
                        .map(|(name, value)| format!("{}: {}", name, value))
                        .collect();
                    let _ = write!(output, "{}", param_strs.join(", "));
                }
                let _ = write!(output, ")");
            } else {
                let _ = write!(output, "emit <unknown>");
            }
        } else {
            // Raw log data
            if !log.raw_log.topics().is_empty() {
                let _ =
                    write!(output, "emit 0x{}", hex::encode(log.raw_log.topics()[0].as_slice()));
                if log.raw_log.topics().len() > 1 {
                    let _ = write!(output, " (+ {} topics)", log.raw_log.topics().len() - 1);
                }
            } else {
                let _ = write!(output, "emit <no topics>");
            }
        }

        let _ = writeln!(output);
    }
}

impl Default for TraceRenderer {
    fn default() -> Self {
        Self::new()
    }
}

/// Utility function to render a trace arena as a formatted string
pub fn render_trace_arena(arena: &CallTraceArena) -> String {
    TraceRenderer::new().render_arena(arena)
}
