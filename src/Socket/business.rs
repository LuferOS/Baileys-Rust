use super::socket::{SocketError, WaSocket};
use crate::types::{
    CatalogPage, CollectionsResult, GetCatalogOptions, HoursDay, OrderDetails, Product,
    ProductCreate, ProductDeleteResult, ProductUpdate, UpdateBusinessProfileProps,
};
use crate::utils::{
    parse_catalog_node, parse_collections_node, parse_order_details_node, parse_product_node,
    to_product_node_create, to_product_node_update, BusinessUtilsError,
};
use crate::wa_binary::{
    get_binary_node_child, jid_normalized_user, BinaryNode, BinaryNodeAttributes, BinaryNodeData,
    S_WHATSAPP_NET,
};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum BusinessError {
    #[error("socket error: {0}")]
    Socket(#[from] SocketError),
    #[error("business utils error: {0}")]
    Utils(#[from] BusinessUtilsError),
    #[error("not authenticated: missing own jid")]
    NotAuthenticated,
    #[error("missing product node in server response")]
    MissingProductNode,
}

impl WaSocket {
    pub async fn update_business_profile(
        &self,
        args: &UpdateBusinessProfileProps,
    ) -> Result<BinaryNode, BusinessError> {
        let mut nodes = Vec::new();

        if let Some(ref address) = args.address {
            nodes.push(BinaryNode {
                tag: "address".to_string(),
                attrs: BinaryNodeAttributes::new(),
                content: Some(BinaryNodeData::String(address.clone())),
            });
        }

        if let Some(ref email) = args.email {
            nodes.push(BinaryNode {
                tag: "email".to_string(),
                attrs: BinaryNodeAttributes::new(),
                content: Some(BinaryNodeData::String(email.clone())),
            });
        }

        if let Some(ref description) = args.description {
            nodes.push(BinaryNode {
                tag: "description".to_string(),
                attrs: BinaryNodeAttributes::new(),
                content: Some(BinaryNodeData::String(description.clone())),
            });
        }

        if let Some(ref websites) = args.websites {
            for website in websites {
                nodes.push(BinaryNode {
                    tag: "website".to_string(),
                    attrs: BinaryNodeAttributes::new(),
                    content: Some(BinaryNodeData::String(website.clone())),
                });
            }
        }

        if let Some(ref hours) = args.hours {
            let day_nodes: Vec<BinaryNode> = hours
                .days
                .iter()
                .map(|day_cfg| {
                    let attrs = match day_cfg {
                        HoursDay::SpecificHours {
                            day,
                            open_time_in_minutes,
                            close_time_in_minutes,
                        } => BinaryNodeAttributes::from([
                            ("day_of_week".to_string(), day.as_str().to_string()),
                            ("mode".to_string(), "specific_hours".to_string()),
                            ("open_time".to_string(), open_time_in_minutes.clone()),
                            ("close_time".to_string(), close_time_in_minutes.clone()),
                        ]),
                        HoursDay::Open24h { day } => BinaryNodeAttributes::from([
                            ("day_of_week".to_string(), day.as_str().to_string()),
                            ("mode".to_string(), "open_24h".to_string()),
                        ]),
                        HoursDay::AppointmentOnly { day } => BinaryNodeAttributes::from([
                            ("day_of_week".to_string(), day.as_str().to_string()),
                            ("mode".to_string(), "appointment_only".to_string()),
                        ]),
                    };
                    BinaryNode {
                        tag: "business_hours_config".to_string(),
                        attrs,
                        content: None,
                    }
                })
                .collect();

            nodes.push(BinaryNode {
                tag: "business_hours".to_string(),
                attrs: BinaryNodeAttributes::from([("timezone".to_string(), hours.timezone.clone())]),
                content: Some(BinaryNodeData::List(day_nodes)),
            });
        }

        let result = self
            .query(
                BinaryNode {
                    tag: "iq".to_string(),
                    attrs: BinaryNodeAttributes::from([
                        ("to".to_string(), S_WHATSAPP_NET.to_string()),
                        ("type".to_string(), "set".to_string()),
                        ("xmlns".to_string(), "w:biz".to_string()),
                    ]),
                    content: Some(BinaryNodeData::List(vec![BinaryNode {
                        tag: "business_profile".to_string(),
                        attrs: BinaryNodeAttributes::from([
                            ("v".to_string(), "3".to_string()),
                            ("mutation_type".to_string(), "delta".to_string()),
                        ]),
                        content: Some(BinaryNodeData::List(nodes)),
                    }])),
                },
                None,
            )
            .await?;

        Ok(result)
    }

    pub async fn update_cover_photo_metadata(
        &self,
        fbid: &str,
        token: &str,
        ts: u64,
    ) -> Result<String, BusinessError> {
        self.query(
            BinaryNode {
                tag: "iq".to_string(),
                attrs: BinaryNodeAttributes::from([
                    ("to".to_string(), S_WHATSAPP_NET.to_string()),
                    ("type".to_string(), "set".to_string()),
                    ("xmlns".to_string(), "w:biz".to_string()),
                ]),
                content: Some(BinaryNodeData::List(vec![BinaryNode {
                    tag: "business_profile".to_string(),
                    attrs: BinaryNodeAttributes::from([
                        ("v".to_string(), "3".to_string()),
                        ("mutation_type".to_string(), "delta".to_string()),
                    ]),
                    content: Some(BinaryNodeData::List(vec![BinaryNode {
                        tag: "cover_photo".to_string(),
                        attrs: BinaryNodeAttributes::from([
                            ("id".to_string(), fbid.to_string()),
                            ("op".to_string(), "update".to_string()),
                            ("token".to_string(), token.to_string()),
                            ("ts".to_string(), ts.to_string()),
                        ]),
                        content: None,
                    }])),
                }])),
            },
            None,
        )
        .await?;

        Ok(fbid.to_string())
    }

    pub async fn remove_cover_photo(&self, id: &str) -> Result<BinaryNode, BusinessError> {
        let result = self
            .query(
                BinaryNode {
                    tag: "iq".to_string(),
                    attrs: BinaryNodeAttributes::from([
                        ("to".to_string(), S_WHATSAPP_NET.to_string()),
                        ("type".to_string(), "set".to_string()),
                        ("xmlns".to_string(), "w:biz".to_string()),
                    ]),
                    content: Some(BinaryNodeData::List(vec![BinaryNode {
                        tag: "business_profile".to_string(),
                        attrs: BinaryNodeAttributes::from([
                            ("v".to_string(), "3".to_string()),
                            ("mutation_type".to_string(), "delta".to_string()),
                        ]),
                        content: Some(BinaryNodeData::List(vec![BinaryNode {
                            tag: "cover_photo".to_string(),
                            attrs: BinaryNodeAttributes::from([
                                ("op".to_string(), "delete".to_string()),
                                ("id".to_string(), id.to_string()),
                            ]),
                            content: None,
                        }])),
                    }])),
                },
                None,
            )
            .await?;

        Ok(result)
    }

    pub async fn get_catalog(
        &self,
        opts: GetCatalogOptions,
    ) -> Result<CatalogPage, BusinessError> {
        let raw_jid = match opts.jid {
            Some(j) => j,
            None => self
                .creds()
                .await
                .me
                .map(|m| m.id)
                .ok_or(BusinessError::NotAuthenticated)?,
        };
        let jid = jid_normalized_user(Some(&raw_jid));
        let limit = opts.limit.unwrap_or(10);

        let mut query_params = vec![
            BinaryNode {
                tag: "limit".to_string(),
                attrs: BinaryNodeAttributes::new(),
                content: Some(BinaryNodeData::Bytes(limit.to_string().into_bytes())),
            },
            BinaryNode {
                tag: "width".to_string(),
                attrs: BinaryNodeAttributes::new(),
                content: Some(BinaryNodeData::Bytes(b"100".to_vec())),
            },
            BinaryNode {
                tag: "height".to_string(),
                attrs: BinaryNodeAttributes::new(),
                content: Some(BinaryNodeData::Bytes(b"100".to_vec())),
            },
        ];

        if let Some(cursor) = opts.cursor {
            query_params.push(BinaryNode {
                tag: "after".to_string(),
                attrs: BinaryNodeAttributes::new(),
                content: Some(BinaryNodeData::String(cursor)),
            });
        }

        let result = self
            .query(
                BinaryNode {
                    tag: "iq".to_string(),
                    attrs: BinaryNodeAttributes::from([
                        ("to".to_string(), S_WHATSAPP_NET.to_string()),
                        ("type".to_string(), "get".to_string()),
                        ("xmlns".to_string(), "w:biz:catalog".to_string()),
                    ]),
                    content: Some(BinaryNodeData::List(vec![BinaryNode {
                        tag: "product_catalog".to_string(),
                        attrs: BinaryNodeAttributes::from([
                            ("jid".to_string(), jid),
                            ("allow_shop_source".to_string(), "true".to_string()),
                        ]),
                        content: Some(BinaryNodeData::List(query_params)),
                    }])),
                },
                None,
            )
            .await?;

        Ok(parse_catalog_node(&result))
    }

    pub async fn get_collections(
        &self,
        jid: Option<&str>,
        limit: Option<u32>,
    ) -> Result<CollectionsResult, BusinessError> {
        let raw_jid = match jid {
            Some(j) => j.to_string(),
            None => self
                .creds()
                .await
                .me
                .map(|m| m.id)
                .ok_or(BusinessError::NotAuthenticated)?,
        };
        let norm_jid = jid_normalized_user(Some(&raw_jid));
        let limit_bytes = limit.unwrap_or(51).to_string().into_bytes();

        let result = self
            .query(
                BinaryNode {
                    tag: "iq".to_string(),
                    attrs: BinaryNodeAttributes::from([
                        ("to".to_string(), S_WHATSAPP_NET.to_string()),
                        ("type".to_string(), "get".to_string()),
                        ("xmlns".to_string(), "w:biz:catalog".to_string()),
                        ("smax_id".to_string(), "35".to_string()),
                    ]),
                    content: Some(BinaryNodeData::List(vec![BinaryNode {
                        tag: "collections".to_string(),
                        attrs: BinaryNodeAttributes::from([("biz_jid".to_string(), norm_jid)]),
                        content: Some(BinaryNodeData::List(vec![
                            BinaryNode {
                                tag: "collection_limit".to_string(),
                                attrs: BinaryNodeAttributes::new(),
                                content: Some(BinaryNodeData::Bytes(limit_bytes.clone())),
                            },
                            BinaryNode {
                                tag: "item_limit".to_string(),
                                attrs: BinaryNodeAttributes::new(),
                                content: Some(BinaryNodeData::Bytes(limit_bytes)),
                            },
                            BinaryNode {
                                tag: "width".to_string(),
                                attrs: BinaryNodeAttributes::new(),
                                content: Some(BinaryNodeData::Bytes(b"100".to_vec())),
                            },
                            BinaryNode {
                                tag: "height".to_string(),
                                attrs: BinaryNodeAttributes::new(),
                                content: Some(BinaryNodeData::Bytes(b"100".to_vec())),
                            },
                        ])),
                    }])),
                },
                None,
            )
            .await?;

        Ok(parse_collections_node(&result))
    }

    pub async fn get_order_details(
        &self,
        order_id: &str,
        token_base64: &str,
    ) -> Result<OrderDetails, BusinessError> {
        let result = self
            .query(
                BinaryNode {
                    tag: "iq".to_string(),
                    attrs: BinaryNodeAttributes::from([
                        ("to".to_string(), S_WHATSAPP_NET.to_string()),
                        ("type".to_string(), "get".to_string()),
                        ("xmlns".to_string(), "fb:thrift_iq".to_string()),
                        ("smax_id".to_string(), "5".to_string()),
                    ]),
                    content: Some(BinaryNodeData::List(vec![BinaryNode {
                        tag: "order".to_string(),
                        attrs: BinaryNodeAttributes::from([
                            ("op".to_string(), "get".to_string()),
                            ("id".to_string(), order_id.to_string()),
                        ]),
                        content: Some(BinaryNodeData::List(vec![
                            BinaryNode {
                                tag: "image_dimensions".to_string(),
                                attrs: BinaryNodeAttributes::new(),
                                content: Some(BinaryNodeData::List(vec![
                                    BinaryNode {
                                        tag: "width".to_string(),
                                        attrs: BinaryNodeAttributes::new(),
                                        content: Some(BinaryNodeData::Bytes(b"100".to_vec())),
                                    },
                                    BinaryNode {
                                        tag: "height".to_string(),
                                        attrs: BinaryNodeAttributes::new(),
                                        content: Some(BinaryNodeData::Bytes(b"100".to_vec())),
                                    },
                                ])),
                            },
                            BinaryNode {
                                tag: "token".to_string(),
                                attrs: BinaryNodeAttributes::new(),
                                content: Some(BinaryNodeData::Bytes(
                                    token_base64.as_bytes().to_vec(),
                                )),
                            },
                        ])),
                    }])),
                },
                None,
            )
            .await?;

        Ok(parse_order_details_node(&result))
    }

    pub async fn product_update(
        &self,
        product_id: &str,
        update: &ProductUpdate,
    ) -> Result<Product, BusinessError> {
        let edit_node = to_product_node_update(product_id, update)?;
        let result = self
            .query(
                BinaryNode {
                    tag: "iq".to_string(),
                    attrs: BinaryNodeAttributes::from([
                        ("to".to_string(), S_WHATSAPP_NET.to_string()),
                        ("type".to_string(), "set".to_string()),
                        ("xmlns".to_string(), "w:biz:catalog".to_string()),
                    ]),
                    content: Some(BinaryNodeData::List(vec![BinaryNode {
                        tag: "product_catalog_edit".to_string(),
                        attrs: BinaryNodeAttributes::from([("v".to_string(), "1".to_string())]),
                        content: Some(BinaryNodeData::List(vec![
                            edit_node,
                            BinaryNode {
                                tag: "width".to_string(),
                                attrs: BinaryNodeAttributes::new(),
                                content: Some(BinaryNodeData::String("100".to_string())),
                            },
                            BinaryNode {
                                tag: "height".to_string(),
                                attrs: BinaryNodeAttributes::new(),
                                content: Some(BinaryNodeData::String("100".to_string())),
                            },
                        ])),
                    }])),
                },
                None,
            )
            .await?;

        let edit_res = get_binary_node_child(Some(&result), "product_catalog_edit");
        let product_node =
            get_binary_node_child(edit_res, "product").ok_or(BusinessError::MissingProductNode)?;
        Ok(parse_product_node(product_node))
    }

    pub async fn product_create(&self, create: &ProductCreate) -> Result<Product, BusinessError> {
        let create_node = to_product_node_create(create)?;
        let result = self
            .query(
                BinaryNode {
                    tag: "iq".to_string(),
                    attrs: BinaryNodeAttributes::from([
                        ("to".to_string(), S_WHATSAPP_NET.to_string()),
                        ("type".to_string(), "set".to_string()),
                        ("xmlns".to_string(), "w:biz:catalog".to_string()),
                    ]),
                    content: Some(BinaryNodeData::List(vec![BinaryNode {
                        tag: "product_catalog_add".to_string(),
                        attrs: BinaryNodeAttributes::from([("v".to_string(), "1".to_string())]),
                        content: Some(BinaryNodeData::List(vec![
                            create_node,
                            BinaryNode {
                                tag: "width".to_string(),
                                attrs: BinaryNodeAttributes::new(),
                                content: Some(BinaryNodeData::String("100".to_string())),
                            },
                            BinaryNode {
                                tag: "height".to_string(),
                                attrs: BinaryNodeAttributes::new(),
                                content: Some(BinaryNodeData::String("100".to_string())),
                            },
                        ])),
                    }])),
                },
                None,
            )
            .await?;

        let add_res = get_binary_node_child(Some(&result), "product_catalog_add");
        let product_node =
            get_binary_node_child(add_res, "product").ok_or(BusinessError::MissingProductNode)?;
        Ok(parse_product_node(product_node))
    }

    pub async fn product_delete(
        &self,
        product_ids: &[String],
    ) -> Result<ProductDeleteResult, BusinessError> {
        let product_nodes: Vec<BinaryNode> = product_ids
            .iter()
            .map(|id| BinaryNode {
                tag: "product".to_string(),
                attrs: BinaryNodeAttributes::new(),
                content: Some(BinaryNodeData::List(vec![BinaryNode {
                    tag: "id".to_string(),
                    attrs: BinaryNodeAttributes::new(),
                    content: Some(BinaryNodeData::Bytes(id.as_bytes().to_vec())),
                }])),
            })
            .collect();

        let result = self
            .query(
                BinaryNode {
                    tag: "iq".to_string(),
                    attrs: BinaryNodeAttributes::from([
                        ("to".to_string(), S_WHATSAPP_NET.to_string()),
                        ("type".to_string(), "set".to_string()),
                        ("xmlns".to_string(), "w:biz:catalog".to_string()),
                    ]),
                    content: Some(BinaryNodeData::List(vec![BinaryNode {
                        tag: "product_catalog_delete".to_string(),
                        attrs: BinaryNodeAttributes::from([("v".to_string(), "1".to_string())]),
                        content: Some(BinaryNodeData::List(product_nodes)),
                    }])),
                },
                None,
            )
            .await?;

        let del_node = get_binary_node_child(Some(&result), "product_catalog_delete");
        let deleted = del_node
            .and_then(|n| n.attrs.get("deleted_count"))
            .and_then(|v| v.parse::<u32>().ok())
            .unwrap_or(0);

        Ok(ProductDeleteResult { deleted })
    }
}
