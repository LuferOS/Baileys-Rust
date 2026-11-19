use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DayOfWeekBusiness {
    Sun,
    Mon,
    Tue,
    Wed,
    Thu,
    Fri,
    Sat,
}

impl DayOfWeekBusiness {
    pub fn as_str(&self) -> &'static str {
        match self {
            DayOfWeekBusiness::Sun => "sun",
            DayOfWeekBusiness::Mon => "mon",
            DayOfWeekBusiness::Tue => "tue",
            DayOfWeekBusiness::Wed => "wed",
            DayOfWeekBusiness::Thu => "thu",
            DayOfWeekBusiness::Fri => "fri",
            DayOfWeekBusiness::Sat => "sat",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum HoursDay {
    SpecificHours {
        day: DayOfWeekBusiness,
        open_time_in_minutes: String,
        close_time_in_minutes: String,
    },
    Open24h {
        day: DayOfWeekBusiness,
    },
    AppointmentOnly {
        day: DayOfWeekBusiness,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BusinessHours {
    pub timezone: String,
    pub days: Vec<HoursDay>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct UpdateBusinessProfileProps {
    pub address: Option<String>,
    pub websites: Option<Vec<String>>,
    pub email: Option<String>,
    pub description: Option<String>,
    pub hours: Option<BusinessHours>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CatalogStatus {
    pub status: String,
    pub can_appeal: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CatalogCollection {
    pub id: String,
    pub name: String,
    pub products: Vec<Product>,
    pub status: CatalogStatus,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ProductBase {
    pub name: String,
    pub retailer_id: Option<String>,
    pub url: Option<String>,
    pub description: String,
    pub price: f64,
    pub currency: String,
    pub is_hidden: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ProductCreate {
    pub name: String,
    pub retailer_id: Option<String>,
    pub url: Option<String>,
    pub description: String,
    pub price: f64,
    pub currency: String,
    pub is_hidden: Option<bool>,
    pub origin_country_code: Option<String>,
    pub image_urls: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ProductUpdate {
    pub name: String,
    pub retailer_id: Option<String>,
    pub url: Option<String>,
    pub description: String,
    pub price: f64,
    pub currency: String,
    pub is_hidden: Option<bool>,
    pub image_urls: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Product {
    pub id: String,
    pub name: String,
    pub retailer_id: Option<String>,
    pub url: Option<String>,
    pub description: String,
    pub price: f64,
    pub currency: String,
    pub is_hidden: bool,
    pub image_urls: HashMap<String, String>,
    pub review_status: HashMap<String, String>,
    pub availability: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct OrderPrice {
    pub currency: String,
    pub total: f64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct OrderProduct {
    pub id: String,
    pub image_url: String,
    pub name: String,
    pub quantity: u32,
    pub currency: String,
    pub price: f64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct OrderDetails {
    pub price: OrderPrice,
    pub products: Vec<OrderProduct>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct GetCatalogOptions {
    pub cursor: Option<String>,
    pub limit: Option<u32>,
    pub jid: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CatalogPage {
    pub products: Vec<Product>,
    pub next_page_cursor: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CollectionsResult {
    pub collections: Vec<CatalogCollection>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProductDeleteResult {
    pub deleted: u32,
}
