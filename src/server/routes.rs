//! The route table of the service: each module gives its routes, and the server registers them one time.
//!
//! A pattern that ends with `/` is a subtree (`/api/jobs/`); another pattern is an exact path; `/` takes each other
//! path. The longest pattern that matches wins. `/s3` and `/-/` come before the other routes, with the path as the
//! client sent it: an object key is opaque.

use crate::common::http::Route;

/// The route table: each route of each module.
pub fn table() -> Vec<Route> {
    let mut routes = Vec::with_capacity(64);
    routes.extend(super::own_routes());
    routes.extend(crate::archive::routes());
    routes.extend(crate::lifecycle::routes());
    routes.extend(crate::bucket::routes());
    routes.extend(crate::uploads::routes());
    routes.extend(crate::jobs::routes());
    routes.extend(crate::pv_docs::routes());
    routes.extend(crate::pv_data::routes());
    routes.extend(crate::pv_structured::routes());
    routes.extend(crate::pv_media::routes());
    routes.extend(crate::access::routes());
    routes
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use crate::common::http::RouteAccess;

    use super::*;

    #[test]
    fn the_table_has_each_route_one_time_with_its_kind_of_access() {
        let table = table();
        let kinds: BTreeMap<&str, RouteAccess> = table.iter().map(|route| (route.pattern, route.access)).collect();
        assert_eq!(kinds.len(), table.len(), "a pattern is in the table two times");
        assert_eq!(table.len(), 53);
        let exempt: Vec<&str> = table
            .iter()
            .filter(|route| route.access == RouteAccess::Exempt)
            .map(|route| route.pattern)
            .collect();
        assert_eq!(exempt, vec!["/healthz", "/.well-known/procurauth/actions"]);
        for pattern in ["/", "/-/", "/api/build", "/api/jobs"] {
            assert_eq!(kinds.get(pattern), Some(&RouteAccess::TokenOnly), "{pattern}");
        }
        assert!(table.iter().all(|route| route.access != RouteAccess::Denied));
    }
}
