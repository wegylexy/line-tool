use crate::schema::Schema;
use serde_json::{json, Map, Value};

/// Maps SQLite declared types to OpenAPI 3.1 JSON Schema types.
fn sqlite_type_to_openapi(decl_type: &str, col_name: &str) -> (Value, Option<&'static str>) {
    let ty = decl_type.to_ascii_uppercase();
    let lower_col = col_name.to_ascii_lowercase();

    if ty.contains("INT") {
        if lower_col.starts_with("is")
            || lower_col.starts_with("has")
            || ty.contains("BOOL")
            || lower_col == "favorite"
            || lower_col == "registered"
        {
            (
                json!({ "type": ["boolean", "integer"] }),
                Some("boolean (0/1 or true/false)"),
            )
        } else if lower_col.contains("time")
            || lower_col.contains("date")
            || lower_col.ends_with("ms")
        {
            (
                json!({ "type": "integer", "format": "int64" }),
                Some("Unix epoch milliseconds timestamp"),
            )
        } else {
            (json!({ "type": "integer" }), None)
        }
    } else if ty.contains("REAL") || ty.contains("FLOA") || ty.contains("DOUB") {
        (json!({ "type": "number", "format": "double" }), None)
    } else if ty.contains("BLOB") {
        (
            json!({ "type": "string", "description": "Blob format (e.g. <blob:Nbytes>)" }),
            None,
        )
    } else {
        (json!({ "type": "string" }), None)
    }
}

/// Generates a full OpenAPI 3.1 specification dynamically from the introspected database schema.
pub fn generate_openapi_spec(schema: &Schema) -> Value {
    let mut tags = Vec::new();
    let mut paths = Map::new();
    let mut schemas = Map::new();

    let mut table_keys: Vec<&String> = schema.tables.keys().collect();
    table_keys.sort();

    for table_key in table_keys {
        let table_info = &schema.tables[table_key];
        tags.push(json!({
            "name": table_key,
            "description": format!("Operations on SQLite table `{}`", table_info.real_name)
        }));

        // Build Row schema for this table
        let mut row_properties = Map::new();
        let mut sorted_cols: Vec<(&String, &crate::schema::ColumnInfo)> =
            table_info.columns.iter().collect();
        sorted_cols.sort_by_key(|(k, _)| *k);

        for (col_key, col_info) in &sorted_cols {
            let (openapi_type, doc_hint) = sqlite_type_to_openapi(&col_info.decl_type, col_key);
            let mut prop_obj = openapi_type;
            if let Some(desc) = doc_hint {
                if let Some(obj) = prop_obj.as_object_mut() {
                    obj.insert("description".to_string(), json!(desc));
                }
            }
            row_properties.insert(col_key.to_string(), prop_obj);
        }

        let table_row_schema_name = format!("{table_key}Row");
        schemas.insert(
            table_row_schema_name.clone(),
            json!({
                "type": "object",
                "properties": row_properties,
                "description": format!("Record structure from table `{}`", table_info.real_name)
            }),
        );

        let table_response_schema_name = format!("{table_key}Response");
        schemas.insert(
            table_response_schema_name.clone(),
            json!({
                "type": "object",
                "properties": {
                    "rows": {
                        "type": "array",
                        "items": {
                            "$ref": format!("#/components/schemas/{table_row_schema_name}")
                        }
                    },
                    "next_cursor": {
                        "type": ["string", "null"],
                        "description": "Forward keyset cursor for the next page, or null if no further pages."
                    }
                },
                "required": ["rows", "next_cursor"]
            }),
        );

        // Build query parameters for GET /{table_key}
        let mut parameters = Vec::new();

        // 1. Reserved parameters
        let mut sort_options: Vec<String> = Vec::new();
        for col_key in &sorted_cols {
            sort_options.push(format!("-{}", col_key.0));
            sort_options.push(col_key.0.to_string());
        }

        parameters.push(json!({
            "name": "$sort",
            "in": "query",
            "required": false,
            "style": "form",
            "explode": false,
            "schema": {
                "oneOf": [
                    {
                        "type": "string",
                        "enum": sort_options,
                        "description": "Single column sort (ascending or descending with `-`)"
                    },
                    {
                        "type": "array",
                        "items": {
                            "type": "string",
                            "enum": sort_options
                        },
                        "description": "Multi-column sort order (serialized as comma-separated list)"
                    },
                    {
                        "type": "string",
                        "description": "Custom comma-separated column sort string"
                    }
                ],
                "example": format!("-{}", sorted_cols.first().map(|(k, _)| k.as_str()).unwrap_or("id"))
            },
            "description": "Sort order. Prefix with `-` for descending. In UI, choose column(s) from enum or enter comma-separated list."
        }));

        parameters.push(json!({
            "name": "$limit",
            "in": "query",
            "required": false,
            "schema": {
                "type": "integer",
                "minimum": 1,
                "maximum": 100,
                "default": 20
            },
            "description": "Maximum number of rows to return (1-100, default 20)."
        }));

        parameters.push(json!({
            "name": "$cursor",
            "in": "query",
            "required": false,
            "schema": {
                "type": "string"
            },
            "description": "Keyset pagination cursor returned from the previous page's `next_cursor`."
        }));

        // 2. Scaffold parameters for each column
        for (col_key, col_info) in &sorted_cols {
            let ty_upper = col_info.decl_type.to_ascii_uppercase();
            let is_int = ty_upper.contains("INT");
            let is_real =
                ty_upper.contains("REAL") || ty_upper.contains("FLOA") || ty_upper.contains("DOUB");
            let is_text = !is_int && !is_real && !ty_upper.contains("BLOB");
            let is_temporal = is_int
                && (col_key.to_ascii_lowercase().contains("time")
                    || col_key.to_ascii_lowercase().contains("date")
                    || col_key.ends_with("ms"));
            let is_bool = is_int
                && (col_key.starts_with("is")
                    || col_key.starts_with("has")
                    || ty_upper.contains("BOOL")
                    || *col_key == "favorite"
                    || *col_key == "registered");

            // Base Exact Match (=)
            let base_type = if is_bool {
                json!({ "type": "boolean" })
            } else if is_int {
                json!({ "type": "integer" })
            } else if is_real {
                json!({ "type": "number" })
            } else {
                json!({ "type": "string" })
            };

            parameters.push(json!({
                "name": col_key,
                "in": "query",
                "required": false,
                "schema": base_type,
                "description": format!("Exact match (`{col_key} = value`{})", if is_bool { ". In CLI/URL, `?{flag}` or `?!{flag}` are also accepted" } else { "" })
            }));

            // Not Equal (!=)
            parameters.push(json!({
                "name": format!("{col_key}!"),
                "in": "query",
                "required": false,
                "schema": if is_int { json!({"type": "integer"}) } else { json!({"type": "string"}) },
                "description": format!("Not equal (`{col_key} != value`)")
            }));

            // Greater than or equal (>=)
            parameters.push(json!({
                "name": format!("{col_key}>"),
                "in": "query",
                "required": false,
                "schema": if is_int { json!({"type": "integer"}) } else { json!({"type": "string"}) },
                "description": format!("Greater than or equal (`{col_key} >= value`)")
            }));

            // Less than or equal (<=)
            parameters.push(json!({
                "name": format!("{col_key}<"),
                "in": "query",
                "required": false,
                "schema": if is_int { json!({"type": "integer"}) } else { json!({"type": "string"}) },
                "description": format!("Less than or equal (`{col_key} <= value`)")
            }));

            // Strictly greater than (>) - Scalar/Form friendly alias >!=
            parameters.push(json!({
                "name": format!("{col_key}>!"),
                "in": "query",
                "required": false,
                "schema": if is_int { json!({"type": "integer"}) } else { json!({"type": "string"}) },
                "description": format!("Strictly greater than (`{col_key} > value`). Serialized as `{col_key}>!=value` for OpenAPI form compatibility.")
            }));

            // Strictly less than (<) - Scalar/Form friendly alias <!=
            parameters.push(json!({
                "name": format!("{col_key}<!"),
                "in": "query",
                "required": false,
                "schema": if is_int { json!({"type": "integer"}) } else { json!({"type": "string"}) },
                "description": format!("Strictly less than (`{col_key} < value`). Serialized as `{col_key}<!=value` for OpenAPI form compatibility.")
            }));

            // Text string matches (^=, *=, $=)
            if is_text {
                parameters.push(json!({
                    "name": format!("{col_key}^"),
                    "in": "query",
                    "required": false,
                    "schema": { "type": "string" },
                    "description": format!("Starts with (`{col_key} ^= value` -> `LIKE 'value%'`)")
                }));
                parameters.push(json!({
                    "name": format!("{col_key}*"),
                    "in": "query",
                    "required": false,
                    "schema": { "type": "string" },
                    "description": format!("Substring contains (`{col_key} *= value` -> `LIKE '%value%'`)")
                }));
                parameters.push(json!({
                    "name": format!("{col_key}$"),
                    "in": "query",
                    "required": false,
                    "schema": { "type": "string" },
                    "description": format!("Ends with (`{col_key} $= value` -> `LIKE '%value'`)")
                }));
            }

            // Temporal date parsing ($date filters)
            if is_temporal {
                parameters.push(json!({
                    "name": format!("{col_key}$date"),
                    "in": "query",
                    "required": false,
                    "schema": { "type": "string", "example": "2026-08-18" },
                    "description": format!("ISO calendar day date range match (`{col_key}$date=YYYY-MM-DD`). Automatically maps to start/end epoch ms.")
                }));
                parameters.push(json!({
                    "name": format!("{col_key}$date>"),
                    "in": "query",
                    "required": false,
                    "schema": { "type": "string", "example": "2026-08-18" },
                    "description": format!("After day start (`{col_key}$date>=YYYY-MM-DD`)")
                }));
                parameters.push(json!({
                    "name": format!("{col_key}$date<"),
                    "in": "query",
                    "required": false,
                    "schema": { "type": "string", "example": "2026-08-18" },
                    "description": format!("Before day end (`{col_key}$date<=YYYY-MM-DD`)")
                }));
                parameters.push(json!({
                    "name": format!("{col_key}$date>!"),
                    "in": "query",
                    "required": false,
                    "schema": { "type": "string", "example": "2026-08-18" },
                    "description": format!("Strictly after next day start (`{col_key}$date>YYYY-MM-DD`)")
                }));
                parameters.push(json!({
                    "name": format!("{col_key}$date<!"),
                    "in": "query",
                    "required": false,
                    "schema": { "type": "string", "example": "2026-08-18" },
                    "description": format!("Strictly before day start (`{col_key}$date<YYYY-MM-DD`)")
                }));
            }
        }

        // Endpoint GET /{table_key}
        let pk_info = if table_info.primary_key.is_empty() {
            "implicit `rowid`".to_string()
        } else {
            table_info.primary_key.join(", ")
        };

        let path_item = json!({
            "get": {
                "tags": [table_key],
                "summary": format!("Query {}", table_key),
                "description": format!("Query records from table `{}` (Primary Key: `{}`). Supports dynamic filtering, regex-style matching, date expansion, sorting, and keyset pagination.", table_info.real_name, pk_info),
                "operationId": format!("query_{table_key}"),
                "parameters": parameters,
                "responses": {
                    "200": {
                        "description": "Successful query response",
                        "headers": {
                            "Link": {
                                "schema": { "type": "string" },
                                "description": "RFC 5988 Link header for forward keyset pagination (`rel=\"next\"`)"
                            }
                        },
                        "content": {
                            "application/json": {
                                "schema": {
                                    "$ref": format!("#/components/schemas/{table_response_schema_name}")
                                }
                            }
                        }
                    },
                    "400": {
                        "description": "Invalid query filter, unknown column, or invalid limit/cursor",
                        "content": {
                            "application/json": {
                                "schema": {
                                    "$ref": "#/components/schemas/ErrorResponse"
                                }
                            }
                        }
                    },
                    "404": {
                        "description": "Table not found",
                        "content": {
                            "application/json": {
                                "schema": {
                                    "$ref": "#/components/schemas/ErrorResponse"
                                }
                            }
                        }
                    },
                    "500": {
                        "description": "Internal server / database error",
                        "content": {
                            "application/json": {
                                "schema": {
                                    "$ref": "#/components/schemas/ErrorResponse"
                                }
                            }
                        }
                    }
                }
            }
        });

        paths.insert(format!("/{table_key}"), path_item);
    }

    schemas.insert(
        "ErrorResponse".to_string(),
        json!({
            "type": "object",
            "properties": {
                "error": {
                    "type": "string"
                }
            },
            "required": ["error"]
        }),
    );

    json!({
        "openapi": "3.1.0",
        "info": {
            "title": "LINE Database REST API",
            "version": "0.1.0",
            "description": "Dynamic REST API and reflection interface over decrypted LINE encrypted SQLite database (.edb). Supports multi-column keyset pagination, date expansions, rich filters, and live automatic hot-reloads."
        },
        "tags": tags,
        "paths": paths,
        "components": {
            "schemas": schemas
        }
    })
}

/// Generates a standalone HTML page embedding the Scalar API Reference UI.
pub fn generate_scalar_html(openapi_url: &str) -> String {
    format!(
        r#"<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>LINE Database API Reference</title>
    <link rel="icon" type="image/svg+xml" href="data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 100 100'><text y='.9em' font-size='90'>💬</text></svg>">
    <style>
      body {{
        margin: 0;
        padding: 0;
        background-color: #0b0f19;
      }}
    </style>
  </head>
  <body>
    <script
      id="api-reference"
      data-url="{openapi_url}"
      data-configuration='{{"theme":"purple","layout":"modern","hideModels":false,"showSidebar":true}}'
      src="https://cdn.jsdelivr.net/npm/@scalar/api-reference"
    ></script>
  </body>
</html>"#
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::schema::{ColumnInfo, TableInfo};
    use std::collections::HashMap;

    #[test]
    fn test_generate_openapi_spec() {
        let mut tables = HashMap::new();
        let mut columns = HashMap::new();
        columns.insert(
            "id".to_string(),
            ColumnInfo {
                real_name: "_id".to_string(),
                decl_type: "INTEGER".to_string(),
            },
        );
        columns.insert(
            "text".to_string(),
            ColumnInfo {
                real_name: "_text".to_string(),
                decl_type: "TEXT".to_string(),
            },
        );
        columns.insert(
            "createdTime".to_string(),
            ColumnInfo {
                real_name: "_createdTime".to_string(),
                decl_type: "INTEGER".to_string(),
            },
        );
        columns.insert(
            "isArchived".to_string(),
            ColumnInfo {
                real_name: "_isArchived".to_string(),
                decl_type: "INTEGER".to_string(),
            },
        );

        tables.insert(
            "message".to_string(),
            TableInfo {
                real_name: "_message".to_string(),
                columns,
                primary_key: vec!["id".to_string()],
            },
        );

        let schema = Schema { tables };
        let spec = generate_openapi_spec(&schema);

        assert_eq!(spec["openapi"], "3.1.0");
        assert!(spec["paths"]["/message"]["get"].is_object());
        assert!(spec["components"]["schemas"]["messageRow"].is_object());

        let params = spec["paths"]["/message"]["get"]["parameters"]
            .as_array()
            .unwrap();
        let param_names: Vec<&str> = params.iter().map(|p| p["name"].as_str().unwrap()).collect();

        assert!(param_names.contains(&"$sort"));
        assert!(param_names.contains(&"$limit"));
        assert!(param_names.contains(&"$cursor"));
        assert!(param_names.contains(&"id"));
        assert!(param_names.contains(&"id>!"));
        assert!(param_names.contains(&"text*"));
        assert!(param_names.contains(&"createdTime$date"));
        assert!(param_names.contains(&"isArchived"));
    }
}
