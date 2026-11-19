use crate::types::{
    CatalogCollection, CatalogPage, CatalogStatus, CollectionsResult, OrderDetails, OrderPrice,
    OrderProduct, Product, ProductCreate, ProductUpdate,
};
use crate::wa_binary::{
    get_binary_node_child, get_binary_node_child_string, get_binary_node_children, BinaryNode,
    BinaryNodeAttributes, BinaryNodeData,
};
use std::collections::HashMap;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum BusinessUtilsError {
    #[error("expected image url to be non-empty")]
    EmptyImageUrl,
}

pub fn parse_catalog_node(node: &BinaryNode) -> CatalogPage {
    let catalog_node = get_binary_node_child(Some(node), "product_catalog");
    let products = get_binary_node_children(catalog_node, "product")
        .into_iter()
        .map(parse_product_node)
        .collect();
    let paging = get_binary_node_child(catalog_node, "paging");
    let next_page_cursor = get_binary_node_child_string(paging, "after");

    CatalogPage {
        products,
        next_page_cursor,
    }
}

pub fn parse_collections_node(node: &BinaryNode) -> CollectionsResult {
    let collections_node = get_binary_node_child(Some(node), "collections");
    let collections = get_binary_node_children(collections_node, "collection")
        .into_iter()
        .map(|collection_node| {
            let id = get_binary_node_child_string(Some(collection_node), "id").unwrap_or_default();
            let name =
                get_binary_node_child_string(Some(collection_node), "name").unwrap_or_default();
            let products = get_binary_node_children(Some(collection_node), "product")
                .into_iter()
                .map(parse_product_node)
                .collect();

            CatalogCollection {
                id,
                name,
                products,
                status: parse_status_info(Some(collection_node)),
            }
        })
        .collect();

    CollectionsResult { collections }
}

pub fn parse_order_details_node(node: &BinaryNode) -> OrderDetails {
    let order_node = get_binary_node_child(Some(node), "order");
    let products = get_binary_node_children(order_node, "product")
        .into_iter()
        .map(|product_node| {
            let image_node = get_binary_node_child(Some(product_node), "image");
            OrderProduct {
                id: get_binary_node_child_string(Some(product_node), "id").unwrap_or_default(),
                name: get_binary_node_child_string(Some(product_node), "name").unwrap_or_default(),
                image_url: get_binary_node_child_string(image_node, "url").unwrap_or_default(),
                price: get_binary_node_child_string(Some(product_node), "price")
                    .and_then(|v| v.parse::<f64>().ok())
                    .unwrap_or(0.0),
                currency: get_binary_node_child_string(Some(product_node), "currency")
                    .unwrap_or_default(),
                quantity: get_binary_node_child_string(Some(product_node), "quantity")
                    .and_then(|v| v.parse::<u32>().ok())
                    .unwrap_or(0),
            }
        })
        .collect();

    let price_node = get_binary_node_child(order_node, "price");
    let price = OrderPrice {
        total: get_binary_node_child_string(price_node, "total")
            .and_then(|v| v.parse::<f64>().ok())
            .unwrap_or(0.0),
        currency: get_binary_node_child_string(price_node, "currency").unwrap_or_default(),
    };

    OrderDetails { price, products }
}

fn build_product_node(
    product_id: Option<&str>,
    name: &str,
    description: &str,
    retailer_id: Option<&str>,
    image_urls: &[String],
    price: f64,
    currency: &str,
    is_hidden: Option<bool>,
    origin_country_code: Option<Option<&str>>,
) -> Result<BinaryNode, BusinessUtilsError> {
    let mut attrs = BinaryNodeAttributes::new();
    let mut content = Vec::new();

    if let Some(id) = product_id {
        content.push(BinaryNode {
            tag: "id".to_string(),
            attrs: BinaryNodeAttributes::new(),
            content: Some(BinaryNodeData::Bytes(id.as_bytes().to_vec())),
        });
    }

    content.push(BinaryNode {
        tag: "name".to_string(),
        attrs: BinaryNodeAttributes::new(),
        content: Some(BinaryNodeData::Bytes(name.as_bytes().to_vec())),
    });

    content.push(BinaryNode {
        tag: "description".to_string(),
        attrs: BinaryNodeAttributes::new(),
        content: Some(BinaryNodeData::Bytes(description.as_bytes().to_vec())),
    });

    if let Some(rid) = retailer_id {
        content.push(BinaryNode {
            tag: "retailer_id".to_string(),
            attrs: BinaryNodeAttributes::new(),
            content: Some(BinaryNodeData::Bytes(rid.as_bytes().to_vec())),
        });
    }

    if !image_urls.is_empty() {
        let mut img_nodes = Vec::with_capacity(image_urls.len());
        for url in image_urls {
            if url.is_empty() {
                return Err(BusinessUtilsError::EmptyImageUrl);
            }
            img_nodes.push(BinaryNode {
                tag: "image".to_string(),
                attrs: BinaryNodeAttributes::new(),
                content: Some(BinaryNodeData::List(vec![BinaryNode {
                    tag: "url".to_string(),
                    attrs: BinaryNodeAttributes::new(),
                    content: Some(BinaryNodeData::Bytes(url.as_bytes().to_vec())),
                }])),
            });
        }
        content.push(BinaryNode {
            tag: "media".to_string(),
            attrs: BinaryNodeAttributes::new(),
            content: Some(BinaryNodeData::List(img_nodes)),
        });
    }

    content.push(BinaryNode {
        tag: "price".to_string(),
        attrs: BinaryNodeAttributes::new(),
        content: Some(BinaryNodeData::Bytes(price.to_string().into_bytes())),
    });

    content.push(BinaryNode {
        tag: "currency".to_string(),
        attrs: BinaryNodeAttributes::new(),
        content: Some(BinaryNodeData::Bytes(currency.as_bytes().to_vec())),
    });

    if let Some(country_opt) = origin_country_code {
        match country_opt {
            None => {
                attrs.insert(
                    "compliance_category".to_string(),
                    "COUNTRY_ORIGIN_EXEMPT".to_string(),
                );
            }
            Some(code) => {
                content.push(BinaryNode {
                    tag: "compliance_info".to_string(),
                    attrs: BinaryNodeAttributes::new(),
                    content: Some(BinaryNodeData::List(vec![BinaryNode {
                        tag: "country_code_origin".to_string(),
                        attrs: BinaryNodeAttributes::new(),
                        content: Some(BinaryNodeData::Bytes(code.as_bytes().to_vec())),
                    }])),
                });
            }
        }
    }

    if let Some(hidden) = is_hidden {
        attrs.insert("is_hidden".to_string(), hidden.to_string());
    }

    Ok(BinaryNode {
        tag: "product".to_string(),
        attrs,
        content: Some(BinaryNodeData::List(content)),
    })
}

pub fn to_product_node_create(product: &ProductCreate) -> Result<BinaryNode, BusinessUtilsError> {
    build_product_node(
        None,
        &product.name,
        &product.description,
        product.retailer_id.as_deref(),
        &product.image_urls,
        product.price,
        &product.currency,
        Some(product.is_hidden.unwrap_or(false)),
        Some(product.origin_country_code.as_deref()),
    )
}

pub fn to_product_node_update(
    product_id: &str,
    product: &ProductUpdate,
) -> Result<BinaryNode, BusinessUtilsError> {
    build_product_node(
        Some(product_id),
        &product.name,
        &product.description,
        product.retailer_id.as_deref(),
        &product.image_urls,
        product.price,
        &product.currency,
        product.is_hidden,
        None,
    )
}

pub fn parse_product_node(product_node: &BinaryNode) -> Product {
    let is_hidden = product_node.attrs.get("is_hidden").map(|s| s.as_str()) == Some("true");
    let id = get_binary_node_child_string(Some(product_node), "id").unwrap_or_default();
    let media_node = get_binary_node_child(Some(product_node), "media");
    let status_info_node = get_binary_node_child(Some(product_node), "status_info");

    let mut review_status = HashMap::new();
    if let Some(status) = get_binary_node_child_string(status_info_node, "status") {
        review_status.insert("whatsapp".to_string(), status);
    }

    Product {
        id,
        image_urls: parse_image_urls(media_node),
        review_status,
        availability: "in stock".to_string(),
        name: get_binary_node_child_string(Some(product_node), "name").unwrap_or_default(),
        retailer_id: get_binary_node_child_string(Some(product_node), "retailer_id"),
        url: get_binary_node_child_string(Some(product_node), "url"),
        description: get_binary_node_child_string(Some(product_node), "description")
            .unwrap_or_default(),
        price: get_binary_node_child_string(Some(product_node), "price")
            .and_then(|v| v.parse::<f64>().ok())
            .unwrap_or(0.0),
        currency: get_binary_node_child_string(Some(product_node), "currency").unwrap_or_default(),
        is_hidden,
    }
}

fn parse_image_urls(media_node: Option<&BinaryNode>) -> HashMap<String, String> {
    let img_node = get_binary_node_child(media_node, "image");
    let mut map = HashMap::new();
    if let Some(req) = get_binary_node_child_string(img_node, "request_image_url") {
        map.insert("requested".to_string(), req);
    }
    if let Some(orig) = get_binary_node_child_string(img_node, "original_image_url") {
        map.insert("original".to_string(), orig);
    }
    map
}

fn parse_status_info(media_node: Option<&BinaryNode>) -> CatalogStatus {
    let node = get_binary_node_child(media_node, "status_info");
    CatalogStatus {
        status: get_binary_node_child_string(node, "status").unwrap_or_default(),
        can_appeal: get_binary_node_child_string(node, "can_appeal").as_deref() == Some("true"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn text_node(tag: &str, value: &str) -> BinaryNode {
        BinaryNode {
            tag: tag.to_string(),
            attrs: BinaryNodeAttributes::new(),
            content: Some(BinaryNodeData::String(value.to_string())),
        }
    }

    #[test]
    fn test_parse_catalog_and_product_nodes() {
        let product = BinaryNode {
            tag: "product".to_string(),
            attrs: BinaryNodeAttributes::from([("is_hidden".to_string(), "false".to_string())]),
            content: Some(BinaryNodeData::List(vec![
                text_node("id", "PROD1"),
                text_node("name", "Licencia Pro"),
                text_node("description", "Acceso anual"),
                text_node("price", "50000"),
                text_node("currency", "COP"),
                BinaryNode {
                    tag: "media".to_string(),
                    attrs: BinaryNodeAttributes::new(),
                    content: Some(BinaryNodeData::List(vec![BinaryNode {
                        tag: "image".to_string(),
                        attrs: BinaryNodeAttributes::new(),
                        content: Some(BinaryNodeData::List(vec![
                            text_node("request_image_url", "https://mmg.whatsapp.net/req.jpg"),
                            text_node("original_image_url", "https://mmg.whatsapp.net/orig.jpg"),
                        ])),
                    }])),
                },
                BinaryNode {
                    tag: "status_info".to_string(),
                    attrs: BinaryNodeAttributes::new(),
                    content: Some(BinaryNodeData::List(vec![text_node("status", "APPROVED")])),
                },
            ])),
        };

        let catalog_iq = BinaryNode {
            tag: "iq".to_string(),
            attrs: BinaryNodeAttributes::new(),
            content: Some(BinaryNodeData::List(vec![BinaryNode {
                tag: "product_catalog".to_string(),
                attrs: BinaryNodeAttributes::new(),
                content: Some(BinaryNodeData::List(vec![
                    product,
                    BinaryNode {
                        tag: "paging".to_string(),
                        attrs: BinaryNodeAttributes::new(),
                        content: Some(BinaryNodeData::List(vec![text_node("after", "CUR_2")])),
                    },
                ])),
            }])),
        };

        let page = parse_catalog_node(&catalog_iq);
        assert_eq!(page.products.len(), 1);
        assert_eq!(page.products[0].id, "PROD1");
        assert_eq!(page.products[0].price, 50000.0);
        assert_eq!(
            page.products[0].review_status.get("whatsapp").map(|s| s.as_str()),
            Some("APPROVED")
        );
        assert_eq!(page.next_page_cursor.as_deref(), Some("CUR_2"));
    }

    #[test]
    fn test_to_product_node_create_and_order_details() {
        let create = ProductCreate {
            name: "Plan Mensual".to_string(),
            retailer_id: Some("SKU-1".to_string()),
            url: None,
            description: "Streaming".to_string(),
            price: 15000.0,
            currency: "COP".to_string(),
            is_hidden: Some(false),
            origin_country_code: None,
            image_urls: vec!["https://mmg.whatsapp.net/a.jpg".to_string()],
        };
        let node = to_product_node_create(&create).unwrap();
        assert_eq!(
            node.attrs.get("compliance_category").map(|s| s.as_str()),
            Some("COUNTRY_ORIGIN_EXEMPT")
        );
        assert_eq!(node.attrs.get("is_hidden").map(|s| s.as_str()), Some("false"));

        let order_iq = BinaryNode {
            tag: "iq".to_string(),
            attrs: BinaryNodeAttributes::new(),
            content: Some(BinaryNodeData::List(vec![BinaryNode {
                tag: "order".to_string(),
                attrs: BinaryNodeAttributes::new(),
                content: Some(BinaryNodeData::List(vec![
                    BinaryNode {
                        tag: "product".to_string(),
                        attrs: BinaryNodeAttributes::new(),
                        content: Some(BinaryNodeData::List(vec![
                            text_node("id", "P1"),
                            text_node("name", "Item"),
                            text_node("price", "10000"),
                            text_node("currency", "COP"),
                            text_node("quantity", "2"),
                            BinaryNode {
                                tag: "image".to_string(),
                                attrs: BinaryNodeAttributes::new(),
                                content: Some(BinaryNodeData::List(vec![text_node(
                                    "url",
                                    "https://mmg.whatsapp.net/item.jpg",
                                )])),
                            },
                        ])),
                    },
                    BinaryNode {
                        tag: "price".to_string(),
                        attrs: BinaryNodeAttributes::new(),
                        content: Some(BinaryNodeData::List(vec![
                            text_node("total", "20000"),
                            text_node("currency", "COP"),
                        ])),
                    },
                ])),
            }])),
        };

        let order = parse_order_details_node(&order_iq);
        assert_eq!(order.price.total, 20000.0);
        assert_eq!(order.products.len(), 1);
        assert_eq!(order.products[0].quantity, 2);
    }
}
