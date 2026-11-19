#[derive(Debug, Clone, PartialEq)]
pub enum WamValue {
    Null,
    Bool(bool),
    Int(i64),
    Float(f64),
    String(String),
}

#[derive(Debug, Clone, PartialEq)]
pub struct WamEventInput {
    pub name: String,
    pub props: Vec<(String, WamValue)>,
    pub globals: Vec<(String, WamValue)>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct BinaryInfo {
    pub protocol_version: u8,
    pub sequence: u16,
    pub events: Vec<WamEventInput>,
    pub buffer: Vec<Vec<u8>>,
}

impl Default for BinaryInfo {
    fn default() -> Self {
        Self {
            protocol_version: 5,
            sequence: 0,
            events: Vec::new(),
            buffer: Vec::new(),
        }
    }
}

impl BinaryInfo {
    pub fn new(sequence: u16, events: Vec<WamEventInput>) -> Self {
        Self {
            protocol_version: 5,
            sequence,
            events,
            buffer: Vec::new(),
        }
    }
}
