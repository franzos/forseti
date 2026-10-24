//! Null the pointers other people's data keeps to a deleted identity. The
//! rows stay; only the reference to the person goes.

use diesel::prelude::*;

use crate::db::{DbPool, lower};
use crate::db_interact;
use crate::schema::{
    host_enrollments, oauth_client_metadata, org_allowed_domains, org_teams, organization_invites,
    organization_members, organizations, resource_registry, saml_connections,
};

/// Set every reference to `identity_id` to NULL in one transaction. Columns
/// that store an admin email instead of an id also match any of `emails`,
/// compared lowercased. Returns the number of rows changed; idempotent.
pub async fn null_references(
    db: &DbPool,
    identity_id: &str,
    emails: &[String],
) -> anyhow::Result<usize> {
    let id = identity_id.to_string();
    let emails: Vec<String> = emails.iter().map(|e| e.to_lowercase()).collect();
    let changed = db_interact!(db, |conn| {
        conn.transaction::<usize, diesel::result::Error, _>(|c| {
            let mut n = 0;
            n += diesel::update(organizations::table.filter(organizations::created_by.eq(&id)))
                .set(organizations::created_by.eq::<Option<String>>(None))
                .execute(c)?;
            n += diesel::update(org_teams::table.filter(org_teams::created_by.eq(&id)))
                .set(org_teams::created_by.eq::<Option<String>>(None))
                .execute(c)?;
            n += diesel::update(
                organization_members::table.filter(organization_members::added_by.eq(&id)),
            )
            .set(organization_members::added_by.eq::<Option<String>>(None))
            .execute(c)?;
            n += diesel::update(
                org_allowed_domains::table.filter(org_allowed_domains::added_by.eq(&id)),
            )
            .set(org_allowed_domains::added_by.eq::<Option<String>>(None))
            .execute(c)?;
            n += diesel::update(
                organization_invites::table.filter(organization_invites::invited_by.eq(&id)),
            )
            .set(organization_invites::invited_by.eq::<Option<String>>(None))
            .execute(c)?;
            n += diesel::update(
                organization_invites::table.filter(organization_invites::accepted_by.eq(&id)),
            )
            .set(organization_invites::accepted_by.eq::<Option<String>>(None))
            .execute(c)?;
            n += diesel::update(
                saml_connections::table.filter(saml_connections::created_by.eq(&id)),
            )
            .set(saml_connections::created_by.eq::<Option<String>>(None))
            .execute(c)?;
            n += diesel::update(
                host_enrollments::table.filter(
                    host_enrollments::created_by
                        .eq(&id)
                        .or(lower(host_enrollments::created_by).eq_any(&emails)),
                ),
            )
            .set(host_enrollments::created_by.eq::<Option<String>>(None))
            .execute(c)?;
            n += diesel::update(
                resource_registry::table.filter(
                    resource_registry::created_by
                        .eq(&id)
                        .or(lower(resource_registry::created_by).eq_any(&emails)),
                ),
            )
            .set(resource_registry::created_by.eq::<Option<String>>(None))
            .execute(c)?;
            n += diesel::update(
                oauth_client_metadata::table.filter(
                    oauth_client_metadata::verified_by
                        .eq(&id)
                        .or(lower(oauth_client_metadata::verified_by).eq_any(&emails)),
                ),
            )
            .set(oauth_client_metadata::verified_by.eq::<Option<String>>(None))
            .execute(c)?;
            n += diesel::update(
                oauth_client_metadata::table.filter(
                    oauth_client_metadata::verification_revoked_by
                        .eq(&id)
                        .or(lower(oauth_client_metadata::verification_revoked_by).eq_any(&emails)),
                ),
            )
            .set(oauth_client_metadata::verification_revoked_by.eq::<Option<String>>(None))
            .execute(c)?;
            Ok(n)
        })
    })?;
    Ok(changed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::orgs::db::test_pool;
    use crate::orgs::{Role, db as orgs_db, domains, teams};
    use crate::resource_registry::{NewResource, insert as insert_resource};

    const GONE: &str = "id-gone";
    const GONE_EMAIL: &str = "Gone@Example.com";
    const KEPT: &str = "id-kept";
    const KEPT_EMAIL: &str = "kept@example.com";

    #[derive(Debug, PartialEq)]
    struct Refs {
        org: Option<String>,
        team: Option<String>,
        member: Option<String>,
        domain: Option<String>,
        invited_by: Option<String>,
        accepted_by: Option<String>,
        saml: Option<String>,
        host: Option<String>,
        resource: Option<String>,
        verified_by: Option<String>,
        revoked_by: Option<String>,
    }

    async fn seed(db: &DbPool, who: &str, email: &str) {
        let now = chrono::Utc::now().to_rfc3339();
        let org = format!("org-{who}");
        orgs_db::create_org(db, &org, &org, &org, Some(who))
            .await
            .unwrap();
        teams::create_team(db, &org, "team", Some(who))
            .await
            .unwrap();
        orgs_db::add_member_race_safe(db, "someone", &org, Role::Member)
            .await
            .unwrap();
        domains::add_pending_domain(db, &org, &format!("{who}.example"), "dns", "tok", Some(who))
            .await
            .unwrap();
        orgs_db::insert_invite(
            db,
            &format!("tok-{who}"),
            &org,
            "x@example.com",
            Role::Member,
            Some(who),
            7,
        )
        .await
        .unwrap();
        crate::posix::db::insert_host(
            db,
            &format!("host-{who}"),
            &format!("{who}.host"),
            "h",
            &org,
            false,
            Some(email),
        )
        .await
        .unwrap();
        insert_resource(
            db,
            NewResource {
                resource: format!("https://{who}.example/mcp"),
                display_name: who.to_string(),
                org_id: org.clone(),
                created_by: email.to_string(),
            },
        )
        .await
        .unwrap();
        crate::oauth_client_metadata::mark_verified(db, &format!("client-{who}"), email, "admin")
            .await
            .unwrap();
        crate::oauth_client_metadata::mark_unverified(db, &format!("client-{who}"), email, "admin")
            .await
            .unwrap();
        let (who, org, now) = (who.to_string(), org.clone(), now.clone());
        let seeded: anyhow::Result<()> = async {
            db_interact!(db, |conn| {
                diesel::update(
                    organization_members::table.filter(organization_members::org_id.eq(&org)),
                )
                .set(organization_members::added_by.eq(Some(&who)))
                .execute(conn)?;
                diesel::update(
                    organization_invites::table.filter(organization_invites::org_id.eq(&org)),
                )
                .set(organization_invites::accepted_by.eq(Some(&who)))
                .execute(conn)?;
                diesel::insert_into(saml_connections::table)
                    .values((
                        saml_connections::org_id.eq(&org),
                        saml_connections::enabled.eq(1),
                        saml_connections::display_name.eq("idp"),
                        saml_connections::created_by.eq(Some(&who)),
                        saml_connections::created_at.eq(&now),
                        saml_connections::updated_at.eq(&now),
                    ))
                    .execute(conn)
            })?;
            Ok(())
        }
        .await;
        seeded.unwrap();
    }

    async fn refs(db: &DbPool, who: &str) -> Refs {
        let org = format!("org-{who}");
        let who = who.to_string();
        let out: anyhow::Result<Refs> = async {
            Ok(db_interact!(db, |conn| {
                let org_ = organizations::table
                    .filter(organizations::id.eq(&org))
                    .select(organizations::created_by)
                    .first::<Option<String>>(conn)?;
                let team = org_teams::table
                    .filter(org_teams::org_id.eq(&org))
                    .select(org_teams::created_by)
                    .first::<Option<String>>(conn)?;
                let member = organization_members::table
                    .filter(organization_members::org_id.eq(&org))
                    .select(organization_members::added_by)
                    .first::<Option<String>>(conn)?;
                let domain = org_allowed_domains::table
                    .filter(org_allowed_domains::org_id.eq(&org))
                    .select(org_allowed_domains::added_by)
                    .first::<Option<String>>(conn)?;
                let (invited_by, accepted_by) = organization_invites::table
                    .filter(organization_invites::org_id.eq(&org))
                    .select((
                        organization_invites::invited_by,
                        organization_invites::accepted_by,
                    ))
                    .first::<(Option<String>, Option<String>)>(conn)?;
                let saml = saml_connections::table
                    .filter(saml_connections::org_id.eq(&org))
                    .select(saml_connections::created_by)
                    .first::<Option<String>>(conn)?;
                let host = host_enrollments::table
                    .filter(host_enrollments::id.eq(format!("host-{who}")))
                    .select(host_enrollments::created_by)
                    .first::<Option<String>>(conn)?;
                let resource = resource_registry::table
                    .filter(resource_registry::org_id.eq(&org))
                    .select(resource_registry::created_by)
                    .first::<Option<String>>(conn)?;
                let (verified_by, revoked_by) = oauth_client_metadata::table
                    .filter(oauth_client_metadata::client_id.eq(format!("client-{who}")))
                    .select((
                        oauth_client_metadata::verified_by,
                        oauth_client_metadata::verification_revoked_by,
                    ))
                    .first::<(Option<String>, Option<String>)>(conn)?;
                Ok::<_, diesel::result::Error>(Refs {
                    org: org_,
                    team,
                    member,
                    domain,
                    invited_by,
                    accepted_by,
                    saml,
                    host,
                    resource,
                    verified_by,
                    revoked_by,
                })
            })?)
        }
        .await;
        out.unwrap()
    }

    fn all(id: &str, email: &str) -> Refs {
        let id = Some(id.to_string());
        let email = Some(email.to_string());
        Refs {
            org: id.clone(),
            team: id.clone(),
            member: id.clone(),
            domain: id.clone(),
            invited_by: id.clone(),
            accepted_by: id.clone(),
            saml: id,
            host: email.clone(),
            resource: email.clone(),
            verified_by: email.clone(),
            revoked_by: email,
        }
    }

    fn none() -> Refs {
        Refs {
            org: None,
            team: None,
            member: None,
            domain: None,
            invited_by: None,
            accepted_by: None,
            saml: None,
            host: None,
            resource: None,
            verified_by: None,
            revoked_by: None,
        }
    }

    #[tokio::test]
    async fn nulls_every_reference_and_leaves_other_identities_alone() {
        let db = test_pool().await;
        seed(&db, GONE, GONE_EMAIL).await;
        seed(&db, KEPT, KEPT_EMAIL).await;
        assert_eq!(refs(&db, GONE).await, all(GONE, GONE_EMAIL));

        let n = null_references(&db, GONE, &[GONE_EMAIL.to_lowercase()])
            .await
            .unwrap();
        assert_eq!(n, 11);
        assert_eq!(refs(&db, GONE).await, none());
        assert_eq!(refs(&db, KEPT).await, all(KEPT, KEPT_EMAIL));

        assert_eq!(
            null_references(&db, GONE, &[GONE_EMAIL.to_lowercase()])
                .await
                .unwrap(),
            0
        );
    }

    #[tokio::test]
    async fn without_emails_only_id_references_are_nulled() {
        let db = test_pool().await;
        seed(&db, GONE, GONE_EMAIL).await;
        let n = null_references(&db, GONE, &[]).await.unwrap();
        assert_eq!(n, 7);
        let left = refs(&db, GONE).await;
        assert_eq!(left.org, None);
        assert_eq!(left.saml, None);
        assert_eq!(left.host.as_deref(), Some(GONE_EMAIL));
        assert_eq!(left.resource.as_deref(), Some(GONE_EMAIL));
        assert_eq!(left.verified_by.as_deref(), Some(GONE_EMAIL));
        assert_eq!(left.revoked_by.as_deref(), Some(GONE_EMAIL));
    }
}
