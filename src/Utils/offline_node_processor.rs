use crate::wa_binary::BinaryNode;
use std::collections::{HashMap, VecDeque};
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use tokio::sync::Mutex;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum OfflineNodeType {
    Message,
    Call,
    Receipt,
    Notification,
}

pub type OfflineNodeHandler = Arc<
    dyn Fn(BinaryNode) -> Pin<Box<dyn Future<Output = Result<(), String>> + Send>> + Send + Sync,
>;

pub type IsWsOpenFn = Arc<dyn Fn() -> bool + Send + Sync>;
pub type OnUnexpectedErrorFn = Arc<dyn Fn(String, String) + Send + Sync>;

struct QueueState {
    nodes: VecDeque<(OfflineNodeType, BinaryNode)>,
    is_processing: bool,
}

#[derive(Clone)]
pub struct OfflineNodeProcessor {
    handlers: Arc<HashMap<OfflineNodeType, OfflineNodeHandler>>,
    is_ws_open: IsWsOpenFn,
    on_unexpected_error: OnUnexpectedErrorFn,
    batch_size: usize,
    state: Arc<Mutex<QueueState>>,
}

impl OfflineNodeProcessor {
    pub fn new(
        handlers: HashMap<OfflineNodeType, OfflineNodeHandler>,
        is_ws_open: IsWsOpenFn,
        on_unexpected_error: OnUnexpectedErrorFn,
        batch_size: usize,
    ) -> Self {
        Self {
            handlers: Arc::new(handlers),
            is_ws_open,
            on_unexpected_error,
            batch_size: batch_size.max(1),
            state: Arc::new(Mutex::new(QueueState {
                nodes: VecDeque::new(),
                is_processing: false,
            })),
        }
    }

    pub async fn enqueue(&self, node_type: OfflineNodeType, node: BinaryNode) {
        let should_spawn = {
            let mut st = self.state.lock().await;
            st.nodes.push_back((node_type, node));
            if st.is_processing {
                false
            } else {
                st.is_processing = true;
                true
            }
        };

        if !should_spawn {
            return;
        }

        let processor = self.clone();
        tokio::spawn(async move {
            let mut processed_in_batch = 0usize;

            loop {
                if !(processor.is_ws_open)() {
                    let mut st = processor.state.lock().await;
                    st.is_processing = false;
                    break;
                }

                let next_item = {
                    let mut st = processor.state.lock().await;
                    match st.nodes.pop_front() {
                        Some(item) => Some(item),
                        None => {
                            st.is_processing = false;
                            None
                        }
                    }
                };

                let Some((kind, node)) = next_item else {
                    break;
                };

                if let Some(handler) = processor.handlers.get(&kind) {
                    if let Err(err) = (handler)(node).await {
                        (processor.on_unexpected_error)(
                            err,
                            format!("processing offline {:?}", kind),
                        );
                    }
                } else {
                    (processor.on_unexpected_error)(
                        format!("unknown offline node type: {:?}", kind),
                        "processing offline node".to_string(),
                    );
                }

                processed_in_batch += 1;
                if processed_in_batch >= processor.batch_size {
                    processed_in_batch = 0;
                    tokio::task::yield_now().await;
                }
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wa_binary::BinaryNodeAttributes;
    use std::sync::Mutex as StdMutex;
    use std::time::Duration;

    #[tokio::test]
    async fn test_offline_node_processor_order_and_error_isolation() {
        let processed = Arc::new(StdMutex::new(Vec::<String>::new()));
        let errors = Arc::new(StdMutex::new(Vec::<String>::new()));

        let processed_ref = Arc::clone(&processed);
        let msg_handler: OfflineNodeHandler = Arc::new(move |node: BinaryNode| {
            let p = Arc::clone(&processed_ref);
            Box::pin(async move {
                let id = node.attrs.get("id").cloned().unwrap_or_default();
                if id == "BAD" {
                    return Err("boom".to_string());
                }
                p.lock().unwrap().push(id);
                Ok(())
            })
        });

        let mut handlers = HashMap::new();
        handlers.insert(OfflineNodeType::Message, msg_handler);

        let errors_ref = Arc::clone(&errors);
        let processor = OfflineNodeProcessor::new(
            handlers,
            Arc::new(|| true),
            Arc::new(move |err, _| {
                errors_ref.lock().unwrap().push(err);
            }),
            2,
        );

        for id in ["1", "BAD", "2", "3"] {
            processor
                .enqueue(
                    OfflineNodeType::Message,
                    BinaryNode {
                        tag: "message".to_string(),
                        attrs: BinaryNodeAttributes::from([("id".to_string(), id.to_string())]),
                        content: None,
                    },
                )
                .await;
        }

        tokio::time::sleep(Duration::from_millis(50)).await;
        assert_eq!(*processed.lock().unwrap(), vec!["1", "2", "3"]);
        assert_eq!(*errors.lock().unwrap(), vec!["boom"]);
    }
}
