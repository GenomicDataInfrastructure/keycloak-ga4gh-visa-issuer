--
-- SPDX-FileCopyrightText: 2026 PNED G.I.E.
-- SPDX-License-Identifier: Apache-2.0
-- PostgreSQL database dump
--

\restrict Z6HgIX3IUbNXHTglkzQNMUWXtLxNBu0YLdaWfF4M47KPTWfhVu7KRdaN2CnYFaZ

-- Dumped from database version 17.10 (Debian 17.10-1.pgdg13+1)
-- Dumped by pg_dump version 17.10 (Debian 17.10-1.pgdg13+1)

SET statement_timeout = 0;
SET lock_timeout = 0;
SET idle_in_transaction_session_timeout = 0;
SET transaction_timeout = 0;
SET client_encoding = 'UTF8';
SET standard_conforming_strings = on;
SELECT pg_catalog.set_config('search_path', '', false);
SET check_function_bodies = false;
SET xmloption = content;
SET client_min_messages = warning;
SET row_security = off;

SET default_tablespace = '';

SET default_table_access_method = heap;

--
-- Name: admin_event_entity; Type: TABLE; Schema: public; Owner: keycloak
--

CREATE TABLE public.admin_event_entity (
    id character varying(36) NOT NULL,
    admin_event_time bigint,
    realm_id character varying(255),
    operation_type character varying(255),
    auth_realm_id character varying(255),
    auth_client_id character varying(255),
    auth_user_id character varying(255),
    ip_address character varying(255),
    resource_path character varying(2550),
    representation text,
    error character varying(255),
    resource_type character varying(64),
    details_json text
);


ALTER TABLE public.admin_event_entity OWNER TO keycloak;

--
-- Name: associated_policy; Type: TABLE; Schema: public; Owner: keycloak
--

CREATE TABLE public.associated_policy (
    policy_id character varying(36) NOT NULL,
    associated_policy_id character varying(36) NOT NULL
);


ALTER TABLE public.associated_policy OWNER TO keycloak;

--
-- Name: authentication_execution; Type: TABLE; Schema: public; Owner: keycloak
--

CREATE TABLE public.authentication_execution (
    id character varying(36) NOT NULL,
    alias character varying(255),
    authenticator character varying(36),
    realm_id character varying(36),
    flow_id character varying(36),
    requirement integer,
    priority integer,
    authenticator_flow boolean DEFAULT false NOT NULL,
    auth_flow_id character varying(36),
    auth_config character varying(36)
);


ALTER TABLE public.authentication_execution OWNER TO keycloak;

--
-- Name: authentication_flow; Type: TABLE; Schema: public; Owner: keycloak
--

CREATE TABLE public.authentication_flow (
    id character varying(36) NOT NULL,
    alias character varying(255),
    description character varying(255),
    realm_id character varying(36),
    provider_id character varying(36) DEFAULT 'basic-flow'::character varying NOT NULL,
    top_level boolean DEFAULT false NOT NULL,
    built_in boolean DEFAULT false NOT NULL
);


ALTER TABLE public.authentication_flow OWNER TO keycloak;

--
-- Name: authenticator_config; Type: TABLE; Schema: public; Owner: keycloak
--

CREATE TABLE public.authenticator_config (
    id character varying(36) NOT NULL,
    alias character varying(255),
    realm_id character varying(36)
);


ALTER TABLE public.authenticator_config OWNER TO keycloak;

--
-- Name: authenticator_config_entry; Type: TABLE; Schema: public; Owner: keycloak
--

CREATE TABLE public.authenticator_config_entry (
    authenticator_id character varying(36) NOT NULL,
    value text,
    name character varying(255) NOT NULL
);


ALTER TABLE public.authenticator_config_entry OWNER TO keycloak;

--
-- Name: broker_link; Type: TABLE; Schema: public; Owner: keycloak
--

CREATE TABLE public.broker_link (
    identity_provider character varying(255) NOT NULL,
    storage_provider_id character varying(255),
    realm_id character varying(36) NOT NULL,
    broker_user_id character varying(255),
    broker_username character varying(255),
    token text,
    user_id character varying(255) NOT NULL
);


ALTER TABLE public.broker_link OWNER TO keycloak;

--
-- Name: client; Type: TABLE; Schema: public; Owner: keycloak
--

CREATE TABLE public.client (
    id character varying(36) NOT NULL,
    enabled boolean DEFAULT false NOT NULL,
    full_scope_allowed boolean DEFAULT false NOT NULL,
    client_id character varying(255),
    not_before integer,
    public_client boolean DEFAULT false NOT NULL,
    secret character varying(255),
    base_url character varying(255),
    bearer_only boolean DEFAULT false NOT NULL,
    management_url character varying(255),
    surrogate_auth_required boolean DEFAULT false NOT NULL,
    realm_id character varying(36),
    protocol character varying(255),
    node_rereg_timeout integer DEFAULT 0,
    frontchannel_logout boolean DEFAULT false NOT NULL,
    consent_required boolean DEFAULT false NOT NULL,
    name character varying(255),
    service_accounts_enabled boolean DEFAULT false NOT NULL,
    client_authenticator_type character varying(255),
    root_url character varying(255),
    description character varying(255),
    registration_token character varying(255),
    standard_flow_enabled boolean DEFAULT true NOT NULL,
    implicit_flow_enabled boolean DEFAULT false NOT NULL,
    direct_access_grants_enabled boolean DEFAULT false NOT NULL,
    always_display_in_console boolean DEFAULT false NOT NULL
);


ALTER TABLE public.client OWNER TO keycloak;

--
-- Name: client_attributes; Type: TABLE; Schema: public; Owner: keycloak
--

CREATE TABLE public.client_attributes (
    client_id character varying(36) NOT NULL,
    name character varying(255) NOT NULL,
    value text
);


ALTER TABLE public.client_attributes OWNER TO keycloak;

--
-- Name: client_auth_flow_bindings; Type: TABLE; Schema: public; Owner: keycloak
--

CREATE TABLE public.client_auth_flow_bindings (
    client_id character varying(36) NOT NULL,
    flow_id character varying(36),
    binding_name character varying(255) NOT NULL
);


ALTER TABLE public.client_auth_flow_bindings OWNER TO keycloak;

--
-- Name: client_initial_access; Type: TABLE; Schema: public; Owner: keycloak
--

CREATE TABLE public.client_initial_access (
    id character varying(36) NOT NULL,
    realm_id character varying(36) NOT NULL,
    "timestamp" integer,
    expiration integer,
    count integer,
    remaining_count integer
);


ALTER TABLE public.client_initial_access OWNER TO keycloak;

--
-- Name: client_node_registrations; Type: TABLE; Schema: public; Owner: keycloak
--

CREATE TABLE public.client_node_registrations (
    client_id character varying(36) NOT NULL,
    value integer,
    name character varying(255) NOT NULL
);


ALTER TABLE public.client_node_registrations OWNER TO keycloak;

--
-- Name: client_scope; Type: TABLE; Schema: public; Owner: keycloak
--

CREATE TABLE public.client_scope (
    id character varying(36) NOT NULL,
    name character varying(255),
    realm_id character varying(36),
    description character varying(255),
    protocol character varying(255)
);


ALTER TABLE public.client_scope OWNER TO keycloak;

--
-- Name: client_scope_attributes; Type: TABLE; Schema: public; Owner: keycloak
--

CREATE TABLE public.client_scope_attributes (
    scope_id character varying(36) NOT NULL,
    value character varying(2048),
    name character varying(255) NOT NULL
);


ALTER TABLE public.client_scope_attributes OWNER TO keycloak;

--
-- Name: client_scope_client; Type: TABLE; Schema: public; Owner: keycloak
--

CREATE TABLE public.client_scope_client (
    client_id character varying(255) NOT NULL,
    scope_id character varying(255) NOT NULL,
    default_scope boolean DEFAULT false NOT NULL
);


ALTER TABLE public.client_scope_client OWNER TO keycloak;

--
-- Name: client_scope_role_mapping; Type: TABLE; Schema: public; Owner: keycloak
--

CREATE TABLE public.client_scope_role_mapping (
    scope_id character varying(36) NOT NULL,
    role_id character varying(36) NOT NULL
);


ALTER TABLE public.client_scope_role_mapping OWNER TO keycloak;

--
-- Name: component; Type: TABLE; Schema: public; Owner: keycloak
--

CREATE TABLE public.component (
    id character varying(36) NOT NULL,
    name character varying(255),
    parent_id character varying(36),
    provider_id character varying(36),
    provider_type character varying(255),
    realm_id character varying(36),
    sub_type character varying(255)
);


ALTER TABLE public.component OWNER TO keycloak;

--
-- Name: component_config; Type: TABLE; Schema: public; Owner: keycloak
--

CREATE TABLE public.component_config (
    id character varying(36) NOT NULL,
    component_id character varying(36) NOT NULL,
    name character varying(255) NOT NULL,
    value text
);


ALTER TABLE public.component_config OWNER TO keycloak;

--
-- Name: composite_role; Type: TABLE; Schema: public; Owner: keycloak
--

CREATE TABLE public.composite_role (
    composite character varying(36) NOT NULL,
    child_role character varying(36) NOT NULL
);


ALTER TABLE public.composite_role OWNER TO keycloak;

--
-- Name: credential; Type: TABLE; Schema: public; Owner: keycloak
--

CREATE TABLE public.credential (
    id character varying(36) NOT NULL,
    salt bytea,
    type character varying(255),
    user_id character varying(36),
    created_date bigint,
    user_label character varying(255),
    secret_data text,
    credential_data text,
    priority integer,
    version integer DEFAULT 0
);


ALTER TABLE public.credential OWNER TO keycloak;

--
-- Name: databasechangelog; Type: TABLE; Schema: public; Owner: keycloak
--

CREATE TABLE public.databasechangelog (
    id character varying(255) NOT NULL,
    author character varying(255) NOT NULL,
    filename character varying(255) NOT NULL,
    dateexecuted timestamp without time zone NOT NULL,
    orderexecuted integer NOT NULL,
    exectype character varying(10) NOT NULL,
    md5sum character varying(35),
    description character varying(255),
    comments character varying(255),
    tag character varying(255),
    liquibase character varying(20),
    contexts character varying(255),
    labels character varying(255),
    deployment_id character varying(10)
);


ALTER TABLE public.databasechangelog OWNER TO keycloak;

--
-- Name: databasechangeloglock; Type: TABLE; Schema: public; Owner: keycloak
--

CREATE TABLE public.databasechangeloglock (
    id integer NOT NULL,
    locked boolean NOT NULL,
    lockgranted timestamp without time zone,
    lockedby character varying(255)
);


ALTER TABLE public.databasechangeloglock OWNER TO keycloak;

--
-- Name: default_client_scope; Type: TABLE; Schema: public; Owner: keycloak
--

CREATE TABLE public.default_client_scope (
    realm_id character varying(36) NOT NULL,
    scope_id character varying(36) NOT NULL,
    default_scope boolean DEFAULT false NOT NULL
);


ALTER TABLE public.default_client_scope OWNER TO keycloak;

--
-- Name: event_entity; Type: TABLE; Schema: public; Owner: keycloak
--

CREATE TABLE public.event_entity (
    id character varying(36) NOT NULL,
    client_id character varying(255),
    details_json character varying(2550),
    error character varying(255),
    ip_address character varying(255),
    realm_id character varying(255),
    session_id character varying(255),
    event_time bigint,
    type character varying(255),
    user_id character varying(255),
    details_json_long_value text
);


ALTER TABLE public.event_entity OWNER TO keycloak;

--
-- Name: fed_user_attribute; Type: TABLE; Schema: public; Owner: keycloak
--

CREATE TABLE public.fed_user_attribute (
    id character varying(36) NOT NULL,
    name character varying(255) NOT NULL,
    user_id character varying(255) NOT NULL,
    realm_id character varying(36) NOT NULL,
    storage_provider_id character varying(36),
    value character varying(2024),
    long_value_hash bytea,
    long_value_hash_lower_case bytea,
    long_value text
);


ALTER TABLE public.fed_user_attribute OWNER TO keycloak;

--
-- Name: fed_user_consent; Type: TABLE; Schema: public; Owner: keycloak
--

CREATE TABLE public.fed_user_consent (
    id character varying(36) NOT NULL,
    client_id character varying(255),
    user_id character varying(255) NOT NULL,
    realm_id character varying(36) NOT NULL,
    storage_provider_id character varying(36),
    created_date bigint,
    last_updated_date bigint,
    client_storage_provider character varying(36),
    external_client_id character varying(255)
);


ALTER TABLE public.fed_user_consent OWNER TO keycloak;

--
-- Name: fed_user_consent_cl_scope; Type: TABLE; Schema: public; Owner: keycloak
--

CREATE TABLE public.fed_user_consent_cl_scope (
    user_consent_id character varying(36) NOT NULL,
    scope_id character varying(36) NOT NULL
);


ALTER TABLE public.fed_user_consent_cl_scope OWNER TO keycloak;

--
-- Name: fed_user_credential; Type: TABLE; Schema: public; Owner: keycloak
--

CREATE TABLE public.fed_user_credential (
    id character varying(36) NOT NULL,
    salt bytea,
    type character varying(255),
    created_date bigint,
    user_id character varying(255) NOT NULL,
    realm_id character varying(36) NOT NULL,
    storage_provider_id character varying(36),
    user_label character varying(255),
    secret_data text,
    credential_data text,
    priority integer
);


ALTER TABLE public.fed_user_credential OWNER TO keycloak;

--
-- Name: fed_user_group_membership; Type: TABLE; Schema: public; Owner: keycloak
--

CREATE TABLE public.fed_user_group_membership (
    group_id character varying(36) NOT NULL,
    user_id character varying(255) NOT NULL,
    realm_id character varying(36) NOT NULL,
    storage_provider_id character varying(36)
);


ALTER TABLE public.fed_user_group_membership OWNER TO keycloak;

--
-- Name: fed_user_required_action; Type: TABLE; Schema: public; Owner: keycloak
--

CREATE TABLE public.fed_user_required_action (
    required_action character varying(255) DEFAULT ' '::character varying NOT NULL,
    user_id character varying(255) NOT NULL,
    realm_id character varying(36) NOT NULL,
    storage_provider_id character varying(36)
);


ALTER TABLE public.fed_user_required_action OWNER TO keycloak;

--
-- Name: fed_user_role_mapping; Type: TABLE; Schema: public; Owner: keycloak
--

CREATE TABLE public.fed_user_role_mapping (
    role_id character varying(36) NOT NULL,
    user_id character varying(255) NOT NULL,
    realm_id character varying(36) NOT NULL,
    storage_provider_id character varying(36)
);


ALTER TABLE public.fed_user_role_mapping OWNER TO keycloak;

--
-- Name: federated_identity; Type: TABLE; Schema: public; Owner: keycloak
--

CREATE TABLE public.federated_identity (
    identity_provider character varying(255) NOT NULL,
    realm_id character varying(36),
    federated_user_id character varying(255),
    federated_username character varying(255),
    token text,
    user_id character varying(36) NOT NULL
);


ALTER TABLE public.federated_identity OWNER TO keycloak;

--
-- Name: federated_user; Type: TABLE; Schema: public; Owner: keycloak
--

CREATE TABLE public.federated_user (
    id character varying(255) NOT NULL,
    storage_provider_id character varying(255),
    realm_id character varying(36) NOT NULL
);


ALTER TABLE public.federated_user OWNER TO keycloak;

--
-- Name: group_attribute; Type: TABLE; Schema: public; Owner: keycloak
--

CREATE TABLE public.group_attribute (
    id character varying(36) DEFAULT 'sybase-needs-something-here'::character varying NOT NULL,
    name character varying(255) NOT NULL,
    value character varying(255),
    group_id character varying(36) NOT NULL
);


ALTER TABLE public.group_attribute OWNER TO keycloak;

--
-- Name: group_role_mapping; Type: TABLE; Schema: public; Owner: keycloak
--

CREATE TABLE public.group_role_mapping (
    role_id character varying(36) NOT NULL,
    group_id character varying(36) NOT NULL
);


ALTER TABLE public.group_role_mapping OWNER TO keycloak;

--
-- Name: identity_provider; Type: TABLE; Schema: public; Owner: keycloak
--

CREATE TABLE public.identity_provider (
    internal_id character varying(36) NOT NULL,
    enabled boolean DEFAULT false NOT NULL,
    provider_alias character varying(255),
    provider_id character varying(255),
    store_token boolean,
    authenticate_by_default boolean,
    realm_id character varying(36),
    add_token_role boolean,
    trust_email boolean,
    first_broker_login_flow_id character varying(36),
    post_broker_login_flow_id character varying(36),
    provider_display_name character varying(255),
    link_only boolean,
    organization_id character varying(255),
    hide_on_login boolean
);


ALTER TABLE public.identity_provider OWNER TO keycloak;

--
-- Name: identity_provider_config; Type: TABLE; Schema: public; Owner: keycloak
--

CREATE TABLE public.identity_provider_config (
    identity_provider_id character varying(36) NOT NULL,
    value text,
    name character varying(255) NOT NULL
);


ALTER TABLE public.identity_provider_config OWNER TO keycloak;

--
-- Name: identity_provider_mapper; Type: TABLE; Schema: public; Owner: keycloak
--

CREATE TABLE public.identity_provider_mapper (
    id character varying(36) NOT NULL,
    name character varying(255) NOT NULL,
    idp_alias character varying(255) NOT NULL,
    idp_mapper_name character varying(255) NOT NULL,
    realm_id character varying(36) NOT NULL
);


ALTER TABLE public.identity_provider_mapper OWNER TO keycloak;

--
-- Name: idp_mapper_config; Type: TABLE; Schema: public; Owner: keycloak
--

CREATE TABLE public.idp_mapper_config (
    idp_mapper_id character varying(36) NOT NULL,
    value text,
    name character varying(255) NOT NULL
);


ALTER TABLE public.idp_mapper_config OWNER TO keycloak;

--
-- Name: jgroups_ping; Type: TABLE; Schema: public; Owner: keycloak
--

CREATE TABLE public.jgroups_ping (
    address character varying(200) NOT NULL,
    name character varying(200),
    cluster_name character varying(200) NOT NULL,
    ip character varying(200) NOT NULL,
    coord boolean
);


ALTER TABLE public.jgroups_ping OWNER TO keycloak;

--
-- Name: keycloak_group; Type: TABLE; Schema: public; Owner: keycloak
--

CREATE TABLE public.keycloak_group (
    id character varying(36) NOT NULL,
    name character varying(255),
    parent_group character varying(36) NOT NULL,
    realm_id character varying(36),
    type integer DEFAULT 0 NOT NULL,
    description character varying(255)
);


ALTER TABLE public.keycloak_group OWNER TO keycloak;

--
-- Name: keycloak_role; Type: TABLE; Schema: public; Owner: keycloak
--

CREATE TABLE public.keycloak_role (
    id character varying(36) NOT NULL,
    client_realm_constraint character varying(255),
    client_role boolean DEFAULT false NOT NULL,
    description character varying(255),
    name character varying(255),
    realm_id character varying(255),
    client character varying(36),
    realm character varying(36)
);


ALTER TABLE public.keycloak_role OWNER TO keycloak;

--
-- Name: migration_model; Type: TABLE; Schema: public; Owner: keycloak
--

CREATE TABLE public.migration_model (
    id character varying(36) NOT NULL,
    version character varying(36),
    update_time bigint DEFAULT 0 NOT NULL
);


ALTER TABLE public.migration_model OWNER TO keycloak;

--
-- Name: offline_client_session; Type: TABLE; Schema: public; Owner: keycloak
--

CREATE TABLE public.offline_client_session (
    user_session_id character varying(36) NOT NULL,
    client_id character varying(255) NOT NULL,
    offline_flag character varying(4) NOT NULL,
    "timestamp" integer,
    data text,
    client_storage_provider character varying(36) DEFAULT 'local'::character varying NOT NULL,
    external_client_id character varying(255) DEFAULT 'local'::character varying NOT NULL,
    version integer DEFAULT 0
);


ALTER TABLE public.offline_client_session OWNER TO keycloak;

--
-- Name: offline_user_session; Type: TABLE; Schema: public; Owner: keycloak
--

CREATE TABLE public.offline_user_session (
    user_session_id character varying(36) NOT NULL,
    user_id character varying(255) NOT NULL,
    realm_id character varying(36) NOT NULL,
    created_on integer NOT NULL,
    offline_flag character varying(4) NOT NULL,
    data text,
    last_session_refresh integer DEFAULT 0 NOT NULL,
    broker_session_id character varying(1024),
    version integer DEFAULT 0,
    remember_me boolean
);


ALTER TABLE public.offline_user_session OWNER TO keycloak;

--
-- Name: org; Type: TABLE; Schema: public; Owner: keycloak
--

CREATE TABLE public.org (
    id character varying(255) NOT NULL,
    enabled boolean NOT NULL,
    realm_id character varying(255) NOT NULL,
    group_id character varying(255) NOT NULL,
    name character varying(255) NOT NULL,
    description character varying(4000),
    alias character varying(255) NOT NULL,
    redirect_url character varying(2048)
);


ALTER TABLE public.org OWNER TO keycloak;

--
-- Name: org_domain; Type: TABLE; Schema: public; Owner: keycloak
--

CREATE TABLE public.org_domain (
    id character varying(36) NOT NULL,
    name character varying(255) NOT NULL,
    verified boolean NOT NULL,
    org_id character varying(255) NOT NULL
);


ALTER TABLE public.org_domain OWNER TO keycloak;

--
-- Name: org_invitation; Type: TABLE; Schema: public; Owner: keycloak
--

CREATE TABLE public.org_invitation (
    id character varying(36) NOT NULL,
    organization_id character varying(255) NOT NULL,
    email character varying(255) NOT NULL,
    first_name character varying(255),
    last_name character varying(255),
    created_at integer NOT NULL,
    expires_at integer,
    invite_link character varying(2048)
);


ALTER TABLE public.org_invitation OWNER TO keycloak;

--
-- Name: policy_config; Type: TABLE; Schema: public; Owner: keycloak
--

CREATE TABLE public.policy_config (
    policy_id character varying(36) NOT NULL,
    name character varying(255) NOT NULL,
    value text
);


ALTER TABLE public.policy_config OWNER TO keycloak;

--
-- Name: protocol_mapper; Type: TABLE; Schema: public; Owner: keycloak
--

CREATE TABLE public.protocol_mapper (
    id character varying(36) NOT NULL,
    name character varying(255) NOT NULL,
    protocol character varying(255) NOT NULL,
    protocol_mapper_name character varying(255) NOT NULL,
    client_id character varying(36),
    client_scope_id character varying(36)
);


ALTER TABLE public.protocol_mapper OWNER TO keycloak;

--
-- Name: protocol_mapper_config; Type: TABLE; Schema: public; Owner: keycloak
--

CREATE TABLE public.protocol_mapper_config (
    protocol_mapper_id character varying(36) NOT NULL,
    value text,
    name character varying(255) NOT NULL
);


ALTER TABLE public.protocol_mapper_config OWNER TO keycloak;

--
-- Name: realm; Type: TABLE; Schema: public; Owner: keycloak
--

CREATE TABLE public.realm (
    id character varying(36) NOT NULL,
    access_code_lifespan integer,
    user_action_lifespan integer,
    access_token_lifespan integer,
    account_theme character varying(255),
    admin_theme character varying(255),
    email_theme character varying(255),
    enabled boolean DEFAULT false NOT NULL,
    events_enabled boolean DEFAULT false NOT NULL,
    events_expiration bigint,
    login_theme character varying(255),
    name character varying(255),
    not_before integer,
    password_policy character varying(2550),
    registration_allowed boolean DEFAULT false NOT NULL,
    remember_me boolean DEFAULT false NOT NULL,
    reset_password_allowed boolean DEFAULT false NOT NULL,
    social boolean DEFAULT false NOT NULL,
    ssl_required character varying(255),
    sso_idle_timeout integer,
    sso_max_lifespan integer,
    update_profile_on_soc_login boolean DEFAULT false NOT NULL,
    verify_email boolean DEFAULT false NOT NULL,
    master_admin_client character varying(36),
    login_lifespan integer,
    internationalization_enabled boolean DEFAULT false NOT NULL,
    default_locale character varying(255),
    reg_email_as_username boolean DEFAULT false NOT NULL,
    admin_events_enabled boolean DEFAULT false NOT NULL,
    admin_events_details_enabled boolean DEFAULT false NOT NULL,
    edit_username_allowed boolean DEFAULT false NOT NULL,
    otp_policy_counter integer DEFAULT 0,
    otp_policy_window integer DEFAULT 1,
    otp_policy_period integer DEFAULT 30,
    otp_policy_digits integer DEFAULT 6,
    otp_policy_alg character varying(36) DEFAULT 'HmacSHA1'::character varying,
    otp_policy_type character varying(36) DEFAULT 'totp'::character varying,
    browser_flow character varying(36),
    registration_flow character varying(36),
    direct_grant_flow character varying(36),
    reset_credentials_flow character varying(36),
    client_auth_flow character varying(36),
    offline_session_idle_timeout integer DEFAULT 0,
    revoke_refresh_token boolean DEFAULT false NOT NULL,
    access_token_life_implicit integer DEFAULT 0,
    login_with_email_allowed boolean DEFAULT true NOT NULL,
    duplicate_emails_allowed boolean DEFAULT false NOT NULL,
    docker_auth_flow character varying(36),
    refresh_token_max_reuse integer DEFAULT 0,
    allow_user_managed_access boolean DEFAULT false NOT NULL,
    sso_max_lifespan_remember_me integer DEFAULT 0 NOT NULL,
    sso_idle_timeout_remember_me integer DEFAULT 0 NOT NULL,
    default_role character varying(255)
);


ALTER TABLE public.realm OWNER TO keycloak;

--
-- Name: realm_attribute; Type: TABLE; Schema: public; Owner: keycloak
--

CREATE TABLE public.realm_attribute (
    name character varying(255) NOT NULL,
    realm_id character varying(36) NOT NULL,
    value text
);


ALTER TABLE public.realm_attribute OWNER TO keycloak;

--
-- Name: realm_default_groups; Type: TABLE; Schema: public; Owner: keycloak
--

CREATE TABLE public.realm_default_groups (
    realm_id character varying(36) NOT NULL,
    group_id character varying(36) NOT NULL
);


ALTER TABLE public.realm_default_groups OWNER TO keycloak;

--
-- Name: realm_enabled_event_types; Type: TABLE; Schema: public; Owner: keycloak
--

CREATE TABLE public.realm_enabled_event_types (
    realm_id character varying(36) NOT NULL,
    value character varying(255) NOT NULL
);


ALTER TABLE public.realm_enabled_event_types OWNER TO keycloak;

--
-- Name: realm_events_listeners; Type: TABLE; Schema: public; Owner: keycloak
--

CREATE TABLE public.realm_events_listeners (
    realm_id character varying(36) NOT NULL,
    value character varying(255) NOT NULL
);


ALTER TABLE public.realm_events_listeners OWNER TO keycloak;

--
-- Name: realm_localizations; Type: TABLE; Schema: public; Owner: keycloak
--

CREATE TABLE public.realm_localizations (
    realm_id character varying(255) NOT NULL,
    locale character varying(255) NOT NULL,
    texts text NOT NULL
);


ALTER TABLE public.realm_localizations OWNER TO keycloak;

--
-- Name: realm_required_credential; Type: TABLE; Schema: public; Owner: keycloak
--

CREATE TABLE public.realm_required_credential (
    type character varying(255) NOT NULL,
    form_label character varying(255),
    input boolean DEFAULT false NOT NULL,
    secret boolean DEFAULT false NOT NULL,
    realm_id character varying(36) NOT NULL
);


ALTER TABLE public.realm_required_credential OWNER TO keycloak;

--
-- Name: realm_smtp_config; Type: TABLE; Schema: public; Owner: keycloak
--

CREATE TABLE public.realm_smtp_config (
    realm_id character varying(36) NOT NULL,
    value character varying(255),
    name character varying(255) NOT NULL
);


ALTER TABLE public.realm_smtp_config OWNER TO keycloak;

--
-- Name: realm_supported_locales; Type: TABLE; Schema: public; Owner: keycloak
--

CREATE TABLE public.realm_supported_locales (
    realm_id character varying(36) NOT NULL,
    value character varying(255) NOT NULL
);


ALTER TABLE public.realm_supported_locales OWNER TO keycloak;

--
-- Name: redirect_uris; Type: TABLE; Schema: public; Owner: keycloak
--

CREATE TABLE public.redirect_uris (
    client_id character varying(36) NOT NULL,
    value character varying(255) NOT NULL
);


ALTER TABLE public.redirect_uris OWNER TO keycloak;

--
-- Name: required_action_config; Type: TABLE; Schema: public; Owner: keycloak
--

CREATE TABLE public.required_action_config (
    required_action_id character varying(36) NOT NULL,
    value text,
    name character varying(255) NOT NULL
);


ALTER TABLE public.required_action_config OWNER TO keycloak;

--
-- Name: required_action_provider; Type: TABLE; Schema: public; Owner: keycloak
--

CREATE TABLE public.required_action_provider (
    id character varying(36) NOT NULL,
    alias character varying(255),
    name character varying(255),
    realm_id character varying(36),
    enabled boolean DEFAULT false NOT NULL,
    default_action boolean DEFAULT false NOT NULL,
    provider_id character varying(255),
    priority integer
);


ALTER TABLE public.required_action_provider OWNER TO keycloak;

--
-- Name: resource_attribute; Type: TABLE; Schema: public; Owner: keycloak
--

CREATE TABLE public.resource_attribute (
    id character varying(36) DEFAULT 'sybase-needs-something-here'::character varying NOT NULL,
    name character varying(255) NOT NULL,
    value character varying(255),
    resource_id character varying(36) NOT NULL
);


ALTER TABLE public.resource_attribute OWNER TO keycloak;

--
-- Name: resource_policy; Type: TABLE; Schema: public; Owner: keycloak
--

CREATE TABLE public.resource_policy (
    resource_id character varying(36) NOT NULL,
    policy_id character varying(36) NOT NULL
);


ALTER TABLE public.resource_policy OWNER TO keycloak;

--
-- Name: resource_scope; Type: TABLE; Schema: public; Owner: keycloak
--

CREATE TABLE public.resource_scope (
    resource_id character varying(36) NOT NULL,
    scope_id character varying(36) NOT NULL
);


ALTER TABLE public.resource_scope OWNER TO keycloak;

--
-- Name: resource_server; Type: TABLE; Schema: public; Owner: keycloak
--

CREATE TABLE public.resource_server (
    id character varying(36) NOT NULL,
    allow_rs_remote_mgmt boolean DEFAULT false NOT NULL,
    policy_enforce_mode smallint NOT NULL,
    decision_strategy smallint DEFAULT 1 NOT NULL
);


ALTER TABLE public.resource_server OWNER TO keycloak;

--
-- Name: resource_server_perm_ticket; Type: TABLE; Schema: public; Owner: keycloak
--

CREATE TABLE public.resource_server_perm_ticket (
    id character varying(36) NOT NULL,
    owner character varying(255) NOT NULL,
    requester character varying(255) NOT NULL,
    created_timestamp bigint NOT NULL,
    granted_timestamp bigint,
    resource_id character varying(36) NOT NULL,
    scope_id character varying(36),
    resource_server_id character varying(36) NOT NULL,
    policy_id character varying(36)
);


ALTER TABLE public.resource_server_perm_ticket OWNER TO keycloak;

--
-- Name: resource_server_policy; Type: TABLE; Schema: public; Owner: keycloak
--

CREATE TABLE public.resource_server_policy (
    id character varying(36) NOT NULL,
    name character varying(255) NOT NULL,
    description character varying(255),
    type character varying(255) NOT NULL,
    decision_strategy smallint,
    logic smallint,
    resource_server_id character varying(36) NOT NULL,
    owner character varying(255)
);


ALTER TABLE public.resource_server_policy OWNER TO keycloak;

--
-- Name: resource_server_resource; Type: TABLE; Schema: public; Owner: keycloak
--

CREATE TABLE public.resource_server_resource (
    id character varying(36) NOT NULL,
    name character varying(255) NOT NULL,
    type character varying(255),
    icon_uri character varying(255),
    owner character varying(255) NOT NULL,
    resource_server_id character varying(36) NOT NULL,
    owner_managed_access boolean DEFAULT false NOT NULL,
    display_name character varying(255)
);


ALTER TABLE public.resource_server_resource OWNER TO keycloak;

--
-- Name: resource_server_scope; Type: TABLE; Schema: public; Owner: keycloak
--

CREATE TABLE public.resource_server_scope (
    id character varying(36) NOT NULL,
    name character varying(255) NOT NULL,
    icon_uri character varying(255),
    resource_server_id character varying(36) NOT NULL,
    display_name character varying(255)
);


ALTER TABLE public.resource_server_scope OWNER TO keycloak;

--
-- Name: resource_uris; Type: TABLE; Schema: public; Owner: keycloak
--

CREATE TABLE public.resource_uris (
    resource_id character varying(36) NOT NULL,
    value character varying(255) NOT NULL
);


ALTER TABLE public.resource_uris OWNER TO keycloak;

--
-- Name: revoked_token; Type: TABLE; Schema: public; Owner: keycloak
--

CREATE TABLE public.revoked_token (
    id character varying(255) NOT NULL,
    expire bigint NOT NULL
);


ALTER TABLE public.revoked_token OWNER TO keycloak;

--
-- Name: role_attribute; Type: TABLE; Schema: public; Owner: keycloak
--

CREATE TABLE public.role_attribute (
    id character varying(36) NOT NULL,
    role_id character varying(36) NOT NULL,
    name character varying(255) NOT NULL,
    value character varying(255)
);


ALTER TABLE public.role_attribute OWNER TO keycloak;

--
-- Name: scope_mapping; Type: TABLE; Schema: public; Owner: keycloak
--

CREATE TABLE public.scope_mapping (
    client_id character varying(36) NOT NULL,
    role_id character varying(36) NOT NULL
);


ALTER TABLE public.scope_mapping OWNER TO keycloak;

--
-- Name: scope_policy; Type: TABLE; Schema: public; Owner: keycloak
--

CREATE TABLE public.scope_policy (
    scope_id character varying(36) NOT NULL,
    policy_id character varying(36) NOT NULL
);


ALTER TABLE public.scope_policy OWNER TO keycloak;

--
-- Name: server_config; Type: TABLE; Schema: public; Owner: keycloak
--

CREATE TABLE public.server_config (
    server_config_key character varying(255) NOT NULL,
    value text NOT NULL,
    version integer DEFAULT 0
);


ALTER TABLE public.server_config OWNER TO keycloak;

--
-- Name: user_attribute; Type: TABLE; Schema: public; Owner: keycloak
--

CREATE TABLE public.user_attribute (
    name character varying(255) NOT NULL,
    value character varying(255),
    user_id character varying(36) NOT NULL,
    id character varying(36) DEFAULT 'sybase-needs-something-here'::character varying NOT NULL,
    long_value_hash bytea,
    long_value_hash_lower_case bytea,
    long_value text
);


ALTER TABLE public.user_attribute OWNER TO keycloak;

--
-- Name: user_consent; Type: TABLE; Schema: public; Owner: keycloak
--

CREATE TABLE public.user_consent (
    id character varying(36) NOT NULL,
    client_id character varying(255),
    user_id character varying(36) NOT NULL,
    created_date bigint,
    last_updated_date bigint,
    client_storage_provider character varying(36),
    external_client_id character varying(255)
);


ALTER TABLE public.user_consent OWNER TO keycloak;

--
-- Name: user_consent_client_scope; Type: TABLE; Schema: public; Owner: keycloak
--

CREATE TABLE public.user_consent_client_scope (
    user_consent_id character varying(36) NOT NULL,
    scope_id character varying(36) NOT NULL
);


ALTER TABLE public.user_consent_client_scope OWNER TO keycloak;

--
-- Name: user_entity; Type: TABLE; Schema: public; Owner: keycloak
--

CREATE TABLE public.user_entity (
    id character varying(36) NOT NULL,
    email character varying(255),
    email_constraint character varying(255),
    email_verified boolean DEFAULT false NOT NULL,
    enabled boolean DEFAULT false NOT NULL,
    federation_link character varying(255),
    first_name character varying(255),
    last_name character varying(255),
    realm_id character varying(255),
    username character varying(255),
    created_timestamp bigint,
    service_account_client_link character varying(255),
    not_before integer DEFAULT 0 NOT NULL
);


ALTER TABLE public.user_entity OWNER TO keycloak;

--
-- Name: user_federation_config; Type: TABLE; Schema: public; Owner: keycloak
--

CREATE TABLE public.user_federation_config (
    user_federation_provider_id character varying(36) NOT NULL,
    value character varying(255),
    name character varying(255) NOT NULL
);


ALTER TABLE public.user_federation_config OWNER TO keycloak;

--
-- Name: user_federation_mapper; Type: TABLE; Schema: public; Owner: keycloak
--

CREATE TABLE public.user_federation_mapper (
    id character varying(36) NOT NULL,
    name character varying(255) NOT NULL,
    federation_provider_id character varying(36) NOT NULL,
    federation_mapper_type character varying(255) NOT NULL,
    realm_id character varying(36) NOT NULL
);


ALTER TABLE public.user_federation_mapper OWNER TO keycloak;

--
-- Name: user_federation_mapper_config; Type: TABLE; Schema: public; Owner: keycloak
--

CREATE TABLE public.user_federation_mapper_config (
    user_federation_mapper_id character varying(36) NOT NULL,
    value character varying(255),
    name character varying(255) NOT NULL
);


ALTER TABLE public.user_federation_mapper_config OWNER TO keycloak;

--
-- Name: user_federation_provider; Type: TABLE; Schema: public; Owner: keycloak
--

CREATE TABLE public.user_federation_provider (
    id character varying(36) NOT NULL,
    changed_sync_period integer,
    display_name character varying(255),
    full_sync_period integer,
    last_sync integer,
    priority integer,
    provider_name character varying(255),
    realm_id character varying(36)
);


ALTER TABLE public.user_federation_provider OWNER TO keycloak;

--
-- Name: user_group_membership; Type: TABLE; Schema: public; Owner: keycloak
--

CREATE TABLE public.user_group_membership (
    group_id character varying(36) NOT NULL,
    user_id character varying(36) NOT NULL,
    membership_type character varying(255) NOT NULL
);


ALTER TABLE public.user_group_membership OWNER TO keycloak;

--
-- Name: user_required_action; Type: TABLE; Schema: public; Owner: keycloak
--

CREATE TABLE public.user_required_action (
    user_id character varying(36) NOT NULL,
    required_action character varying(255) DEFAULT ' '::character varying NOT NULL
);


ALTER TABLE public.user_required_action OWNER TO keycloak;

--
-- Name: user_role_mapping; Type: TABLE; Schema: public; Owner: keycloak
--

CREATE TABLE public.user_role_mapping (
    role_id character varying(255) NOT NULL,
    user_id character varying(36) NOT NULL
);


ALTER TABLE public.user_role_mapping OWNER TO keycloak;

--
-- Name: web_origins; Type: TABLE; Schema: public; Owner: keycloak
--

CREATE TABLE public.web_origins (
    client_id character varying(36) NOT NULL,
    value character varying(255) NOT NULL
);


ALTER TABLE public.web_origins OWNER TO keycloak;

--
-- Name: workflow_state; Type: TABLE; Schema: public; Owner: keycloak
--

CREATE TABLE public.workflow_state (
    execution_id character varying(255) NOT NULL,
    resource_id character varying(255) NOT NULL,
    workflow_id character varying(255) NOT NULL,
    resource_type character varying(255),
    scheduled_step_id character varying(255),
    scheduled_step_timestamp bigint
);


ALTER TABLE public.workflow_state OWNER TO keycloak;

--
-- Data for Name: admin_event_entity; Type: TABLE DATA; Schema: public; Owner: keycloak
--

COPY public.admin_event_entity (id, admin_event_time, realm_id, operation_type, auth_realm_id, auth_client_id, auth_user_id, ip_address, resource_path, representation, error, resource_type, details_json) FROM stdin;
\.


--
-- Data for Name: associated_policy; Type: TABLE DATA; Schema: public; Owner: keycloak
--

COPY public.associated_policy (policy_id, associated_policy_id) FROM stdin;
\.


--
-- Data for Name: authentication_execution; Type: TABLE DATA; Schema: public; Owner: keycloak
--

COPY public.authentication_execution (id, alias, authenticator, realm_id, flow_id, requirement, priority, authenticator_flow, auth_flow_id, auth_config) FROM stdin;
66438e71-c2d5-4284-b86f-89df66a6fdec	\N	auth-cookie	86b2aa03-1225-4835-8758-60f4e03293c9	5ee5265d-2b0a-4b44-8dfd-58462be34154	2	10	f	\N	\N
081c128e-bce4-4970-8057-20b0861744a4	\N	auth-spnego	86b2aa03-1225-4835-8758-60f4e03293c9	5ee5265d-2b0a-4b44-8dfd-58462be34154	3	20	f	\N	\N
95eb09cf-23b6-4284-9ac9-f3ef1942c3f2	\N	identity-provider-redirector	86b2aa03-1225-4835-8758-60f4e03293c9	5ee5265d-2b0a-4b44-8dfd-58462be34154	2	25	f	\N	\N
bb554332-492c-4ce7-aae6-b63e5130ca53	\N	\N	86b2aa03-1225-4835-8758-60f4e03293c9	5ee5265d-2b0a-4b44-8dfd-58462be34154	2	30	t	ea828dfe-c0e3-4ec1-94bd-2a90b09a057c	\N
565409a5-c21d-45c8-b9e0-e0aaba2b19cf	\N	auth-username-password-form	86b2aa03-1225-4835-8758-60f4e03293c9	ea828dfe-c0e3-4ec1-94bd-2a90b09a057c	0	10	f	\N	\N
7926a293-8a1a-4b21-8fed-0da0a733058e	\N	\N	86b2aa03-1225-4835-8758-60f4e03293c9	ea828dfe-c0e3-4ec1-94bd-2a90b09a057c	1	20	t	8f32637e-d769-41f7-8be2-9e33a82e3a10	\N
69be9780-0204-471f-bba3-15cf06e9e533	\N	conditional-user-configured	86b2aa03-1225-4835-8758-60f4e03293c9	8f32637e-d769-41f7-8be2-9e33a82e3a10	0	10	f	\N	\N
9dbb802b-a4da-4662-a0ae-558a24646a8a	\N	conditional-credential	86b2aa03-1225-4835-8758-60f4e03293c9	8f32637e-d769-41f7-8be2-9e33a82e3a10	0	20	f	\N	3b43db42-dcb2-487e-8340-d1344915e9f5
2afd354c-f69e-4d15-bca7-e889ccd195f0	\N	auth-otp-form	86b2aa03-1225-4835-8758-60f4e03293c9	8f32637e-d769-41f7-8be2-9e33a82e3a10	2	30	f	\N	\N
1386f682-10f3-4a2a-92d7-3c0ff501ded0	\N	webauthn-authenticator	86b2aa03-1225-4835-8758-60f4e03293c9	8f32637e-d769-41f7-8be2-9e33a82e3a10	3	40	f	\N	\N
10f88783-6ca9-489b-b41b-0f95dd84c04a	\N	auth-recovery-authn-code-form	86b2aa03-1225-4835-8758-60f4e03293c9	8f32637e-d769-41f7-8be2-9e33a82e3a10	3	50	f	\N	\N
8bff437c-80c9-4e82-953d-1d2469b71ffe	\N	direct-grant-validate-username	86b2aa03-1225-4835-8758-60f4e03293c9	4876e118-2f71-4682-820b-d99a35ef1acb	0	10	f	\N	\N
6877a590-71c9-4896-9d27-40c4175da568	\N	direct-grant-validate-password	86b2aa03-1225-4835-8758-60f4e03293c9	4876e118-2f71-4682-820b-d99a35ef1acb	0	20	f	\N	\N
130abab1-c4e2-4e86-bb9a-27ce1261e639	\N	\N	86b2aa03-1225-4835-8758-60f4e03293c9	4876e118-2f71-4682-820b-d99a35ef1acb	1	30	t	024e81d8-bb89-49f9-8a76-637bfd5ef9db	\N
fa99fa5d-ef3d-4f3f-a11e-a7c7a4516829	\N	conditional-user-configured	86b2aa03-1225-4835-8758-60f4e03293c9	024e81d8-bb89-49f9-8a76-637bfd5ef9db	0	10	f	\N	\N
e354350f-a6b0-44dd-80cf-d5e78fa25e69	\N	direct-grant-validate-otp	86b2aa03-1225-4835-8758-60f4e03293c9	024e81d8-bb89-49f9-8a76-637bfd5ef9db	0	20	f	\N	\N
6752faa4-5d43-44f9-86b0-c23eb994856c	\N	registration-page-form	86b2aa03-1225-4835-8758-60f4e03293c9	76fb239a-cf69-42ef-a4f4-a66400fdea0e	0	10	t	3b101ee9-c6a1-4c5d-aa69-d6913675836a	\N
95a96385-cd85-4480-b9df-5b0b226cfcac	\N	registration-user-creation	86b2aa03-1225-4835-8758-60f4e03293c9	3b101ee9-c6a1-4c5d-aa69-d6913675836a	0	20	f	\N	\N
7ff55404-945f-42cd-a5ff-5e1639153330	\N	registration-password-action	86b2aa03-1225-4835-8758-60f4e03293c9	3b101ee9-c6a1-4c5d-aa69-d6913675836a	0	50	f	\N	\N
2b183604-fcea-4931-b486-89674967959c	\N	registration-recaptcha-action	86b2aa03-1225-4835-8758-60f4e03293c9	3b101ee9-c6a1-4c5d-aa69-d6913675836a	3	60	f	\N	\N
691054bc-c0a0-46e7-8d1e-a20e578f0599	\N	registration-terms-and-conditions	86b2aa03-1225-4835-8758-60f4e03293c9	3b101ee9-c6a1-4c5d-aa69-d6913675836a	3	70	f	\N	\N
9225f2dc-5792-45be-a171-dc0d01523878	\N	reset-credentials-choose-user	86b2aa03-1225-4835-8758-60f4e03293c9	d4cfa9ae-6a39-41c0-8c2c-62a11c3d2117	0	10	f	\N	\N
e43398fb-55d4-4a5e-9370-b9c30faa31fe	\N	reset-credential-email	86b2aa03-1225-4835-8758-60f4e03293c9	d4cfa9ae-6a39-41c0-8c2c-62a11c3d2117	0	20	f	\N	\N
73673184-6dfa-4051-a190-38a84c824db7	\N	reset-password	86b2aa03-1225-4835-8758-60f4e03293c9	d4cfa9ae-6a39-41c0-8c2c-62a11c3d2117	0	30	f	\N	\N
ebdd25fa-dc3c-4618-b5e8-254bab56a88c	\N	\N	86b2aa03-1225-4835-8758-60f4e03293c9	d4cfa9ae-6a39-41c0-8c2c-62a11c3d2117	1	40	t	bd3506e3-f07f-40a9-924d-1aeb3eca539e	\N
003a84ff-bc15-4597-99d3-29f2ec275f2b	\N	conditional-user-configured	86b2aa03-1225-4835-8758-60f4e03293c9	bd3506e3-f07f-40a9-924d-1aeb3eca539e	0	10	f	\N	\N
199f013e-03a0-4a5c-aff0-9bc5efbb35fc	\N	reset-otp	86b2aa03-1225-4835-8758-60f4e03293c9	bd3506e3-f07f-40a9-924d-1aeb3eca539e	0	20	f	\N	\N
c0a91b74-151c-433f-8056-118f7660ad79	\N	client-secret	86b2aa03-1225-4835-8758-60f4e03293c9	63e59bd2-5003-4b43-b979-d7d3de974e6e	2	10	f	\N	\N
7bccf6ea-47d9-4a18-8e06-d7cbe112d8cd	\N	client-jwt	86b2aa03-1225-4835-8758-60f4e03293c9	63e59bd2-5003-4b43-b979-d7d3de974e6e	2	20	f	\N	\N
4a0d07d7-86de-4828-939c-c8a451b8eae4	\N	client-secret-jwt	86b2aa03-1225-4835-8758-60f4e03293c9	63e59bd2-5003-4b43-b979-d7d3de974e6e	2	30	f	\N	\N
22dad931-8d3c-497a-adf9-5c58434ad853	\N	client-x509	86b2aa03-1225-4835-8758-60f4e03293c9	63e59bd2-5003-4b43-b979-d7d3de974e6e	2	40	f	\N	\N
6a660b3b-35ef-42ea-910b-cae049376f4f	\N	idp-review-profile	86b2aa03-1225-4835-8758-60f4e03293c9	04b6912a-4ca7-42ac-8801-cacea86234f3	0	10	f	\N	c9bb0e7a-b25d-4041-bd27-679fb1c329c8
ee9ede2a-cb56-45db-b00c-1eef7f5fc520	\N	\N	86b2aa03-1225-4835-8758-60f4e03293c9	04b6912a-4ca7-42ac-8801-cacea86234f3	0	20	t	5df76b61-2546-480d-9069-d2864e9d3112	\N
d6f493ca-39fe-44a1-aa10-93b2b30b0353	\N	idp-create-user-if-unique	86b2aa03-1225-4835-8758-60f4e03293c9	5df76b61-2546-480d-9069-d2864e9d3112	2	10	f	\N	dce7939e-d3d3-43b6-b16a-3136b6355461
1e54e2c2-fcd6-43fe-bbcd-cf6c7e79a71f	\N	\N	86b2aa03-1225-4835-8758-60f4e03293c9	5df76b61-2546-480d-9069-d2864e9d3112	2	20	t	0de69bf8-4373-49f0-9144-2504d70a6aab	\N
661832be-e9c8-4f92-9ad9-1df92ca7c0f2	\N	idp-confirm-link	86b2aa03-1225-4835-8758-60f4e03293c9	0de69bf8-4373-49f0-9144-2504d70a6aab	0	10	f	\N	\N
d9f5bfca-e277-41cd-aa94-f904a552d3e4	\N	\N	86b2aa03-1225-4835-8758-60f4e03293c9	0de69bf8-4373-49f0-9144-2504d70a6aab	0	20	t	ee7c7c26-b20b-4e9a-a364-2295b6b60e7c	\N
bedefc2c-5976-47bf-8c1a-c65dbfaaebab	\N	idp-email-verification	86b2aa03-1225-4835-8758-60f4e03293c9	ee7c7c26-b20b-4e9a-a364-2295b6b60e7c	2	10	f	\N	\N
b43af805-ec67-4671-82ad-efda3f7221e2	\N	\N	86b2aa03-1225-4835-8758-60f4e03293c9	ee7c7c26-b20b-4e9a-a364-2295b6b60e7c	2	20	t	a6dcf3be-0d17-493f-870b-2ee705bb513d	\N
0d5530af-b158-438d-a4d3-f8b3de7b0975	\N	idp-username-password-form	86b2aa03-1225-4835-8758-60f4e03293c9	a6dcf3be-0d17-493f-870b-2ee705bb513d	0	10	f	\N	\N
1a89a151-f2d5-4169-ae48-1081d91abc66	\N	\N	86b2aa03-1225-4835-8758-60f4e03293c9	a6dcf3be-0d17-493f-870b-2ee705bb513d	1	20	t	63408cca-96f3-4469-9212-ba0ebefac87e	\N
b4e94eb3-59de-4f25-be5c-0f4551e7f3f7	\N	conditional-user-configured	86b2aa03-1225-4835-8758-60f4e03293c9	63408cca-96f3-4469-9212-ba0ebefac87e	0	10	f	\N	\N
b3c7689a-3367-480e-987f-3395694a4da6	\N	conditional-credential	86b2aa03-1225-4835-8758-60f4e03293c9	63408cca-96f3-4469-9212-ba0ebefac87e	0	20	f	\N	f35eae04-ca7b-4dfa-9f04-fb4944e3c219
9a819024-5595-43f9-8a1d-cd0a994a9a82	\N	auth-otp-form	86b2aa03-1225-4835-8758-60f4e03293c9	63408cca-96f3-4469-9212-ba0ebefac87e	2	30	f	\N	\N
78448def-c944-42ff-bece-71cd3deda92a	\N	webauthn-authenticator	86b2aa03-1225-4835-8758-60f4e03293c9	63408cca-96f3-4469-9212-ba0ebefac87e	3	40	f	\N	\N
d0be651d-2ad6-4497-bc74-5babe50a3c1c	\N	auth-recovery-authn-code-form	86b2aa03-1225-4835-8758-60f4e03293c9	63408cca-96f3-4469-9212-ba0ebefac87e	3	50	f	\N	\N
7ad9d58e-00c8-4a0a-a24c-8bbe1cc2d5c4	\N	http-basic-authenticator	86b2aa03-1225-4835-8758-60f4e03293c9	88a2ea30-229b-45f0-a605-bf36778777de	0	10	f	\N	\N
1474a77f-ee17-49d0-933b-73cd0b9bb3b4	\N	docker-http-basic-authenticator	86b2aa03-1225-4835-8758-60f4e03293c9	863d9eec-c10b-48fc-8356-ef79b8c47c23	0	10	f	\N	\N
d91bd510-9d4b-4c9e-b13c-d4124affc302	\N	idp-email-verification	6f348afb-6f1f-428c-a4f9-5f8e2374a075	c9aa61d3-5d87-4cb2-83a9-fc164f2b5930	2	10	f	\N	\N
d3e2fda8-8da0-4e92-b590-43b686a282db	\N	\N	6f348afb-6f1f-428c-a4f9-5f8e2374a075	c9aa61d3-5d87-4cb2-83a9-fc164f2b5930	2	20	t	e952c5c6-8849-4d75-b74e-2d2bdf8ac50f	\N
62b59664-a96c-46f5-adad-c470387b879e	\N	conditional-user-configured	6f348afb-6f1f-428c-a4f9-5f8e2374a075	9e3de326-f007-442f-9696-4ed6677f90e3	0	10	f	\N	\N
ad25ee0a-7d68-474c-aef7-71da665e1c43	\N	auth-otp-form	6f348afb-6f1f-428c-a4f9-5f8e2374a075	9e3de326-f007-442f-9696-4ed6677f90e3	0	20	f	\N	\N
eaed1cc4-eb63-4841-bc4b-ecf20110a027	\N	registration-page-form	6f348afb-6f1f-428c-a4f9-5f8e2374a075	16411ffa-cdf9-40bb-9d06-40de13d84c8e	0	10	t	6e76ce05-128f-4a95-ab0d-80f6b5d8ad38	\N
edef4e76-6bb9-4b10-bc14-60e72802a867	\N	registration-terms-and-conditions	6f348afb-6f1f-428c-a4f9-5f8e2374a075	6e76ce05-128f-4a95-ab0d-80f6b5d8ad38	0	20	f	\N	\N
c236640f-50bd-4c11-8de9-d306922b4026	\N	registration-user-creation	6f348afb-6f1f-428c-a4f9-5f8e2374a075	6e76ce05-128f-4a95-ab0d-80f6b5d8ad38	0	50	f	\N	\N
4deaf5c9-454d-406e-971e-8d17c4a7409d	\N	registration-password-action	6f348afb-6f1f-428c-a4f9-5f8e2374a075	6e76ce05-128f-4a95-ab0d-80f6b5d8ad38	0	60	f	\N	\N
dfc55fae-fafd-4d0d-b472-f6f5948bb659	\N	registration-recaptcha-action	6f348afb-6f1f-428c-a4f9-5f8e2374a075	6e76ce05-128f-4a95-ab0d-80f6b5d8ad38	3	61	f	\N	\N
9d9c7d3a-275e-49ce-a020-29d3cbda9398	\N	conditional-user-configured	6f348afb-6f1f-428c-a4f9-5f8e2374a075	629c59ac-909c-4c3b-8d36-d9cb8d177f3f	0	10	f	\N	\N
0d036c52-fb2c-466a-ab7c-bc9ba3683d45	\N	direct-grant-validate-otp	6f348afb-6f1f-428c-a4f9-5f8e2374a075	629c59ac-909c-4c3b-8d36-d9cb8d177f3f	0	20	f	\N	\N
5af7a323-c109-42d8-9929-57597bb8e669	\N	conditional-user-configured	6f348afb-6f1f-428c-a4f9-5f8e2374a075	c79256c5-d215-4ea7-b68c-b3a0d966930c	0	10	f	\N	\N
17048ffc-c787-49d3-9c8e-a620b1be4cfa	\N	auth-otp-form	6f348afb-6f1f-428c-a4f9-5f8e2374a075	c79256c5-d215-4ea7-b68c-b3a0d966930c	0	20	f	\N	\N
93bbb2ad-f148-4e38-928c-7a026f9b3d7d	\N	idp-confirm-link	6f348afb-6f1f-428c-a4f9-5f8e2374a075	1ad3ab9e-54e4-4397-88a6-9fdec6501b19	0	10	f	\N	\N
5751e2e1-fe06-43df-a29b-f821f2a0d29a	\N	\N	6f348afb-6f1f-428c-a4f9-5f8e2374a075	1ad3ab9e-54e4-4397-88a6-9fdec6501b19	0	20	t	c9aa61d3-5d87-4cb2-83a9-fc164f2b5930	\N
275eb4b7-9982-45bd-97cf-f3b90adf5f17	\N	conditional-user-configured	6f348afb-6f1f-428c-a4f9-5f8e2374a075	71157dfc-793e-4614-9256-a4ee5eedfef1	0	10	f	\N	\N
1dbdabbf-861a-45d0-9aed-d105f742578f	\N	reset-otp	6f348afb-6f1f-428c-a4f9-5f8e2374a075	71157dfc-793e-4614-9256-a4ee5eedfef1	0	20	f	\N	\N
18a86859-a2f9-4b40-a1e4-68d460a5289a	\N	idp-create-user-if-unique	6f348afb-6f1f-428c-a4f9-5f8e2374a075	46f9b776-700b-4abd-8286-b4b23438c5a3	2	10	f	\N	cd71993a-b422-4a88-843a-415f62c820c9
cd16e111-491a-4992-8ece-40fe02da0b13	\N	\N	6f348afb-6f1f-428c-a4f9-5f8e2374a075	46f9b776-700b-4abd-8286-b4b23438c5a3	2	20	t	1ad3ab9e-54e4-4397-88a6-9fdec6501b19	\N
e628a751-51bc-4d89-bb90-3f7b73309d89	\N	idp-username-password-form	6f348afb-6f1f-428c-a4f9-5f8e2374a075	e952c5c6-8849-4d75-b74e-2d2bdf8ac50f	0	10	f	\N	\N
dfc2e0ae-1ec7-4802-a872-731e5e290723	\N	\N	6f348afb-6f1f-428c-a4f9-5f8e2374a075	e952c5c6-8849-4d75-b74e-2d2bdf8ac50f	1	20	t	c79256c5-d215-4ea7-b68c-b3a0d966930c	\N
9914d482-a593-4cf1-a127-7989bf3142f1	\N	auth-cookie	6f348afb-6f1f-428c-a4f9-5f8e2374a075	d53e6878-4a08-4737-8ec8-a893c1a25055	2	10	f	\N	\N
b8f0e729-d0d2-457b-b224-8ca59f01bd87	\N	auth-spnego	6f348afb-6f1f-428c-a4f9-5f8e2374a075	d53e6878-4a08-4737-8ec8-a893c1a25055	3	20	f	\N	\N
350b71f1-9caf-4e5a-8a0d-e780d1eaa91d	\N	identity-provider-redirector	6f348afb-6f1f-428c-a4f9-5f8e2374a075	d53e6878-4a08-4737-8ec8-a893c1a25055	2	25	f	\N	\N
888946a8-d649-4107-a47a-aad8ff289b0f	\N	\N	6f348afb-6f1f-428c-a4f9-5f8e2374a075	d53e6878-4a08-4737-8ec8-a893c1a25055	2	30	t	604aafa0-254a-4ed4-a531-f83b47487901	\N
831face0-03b3-40d4-9dd8-31d6ee4e9e07	\N	client-secret	6f348afb-6f1f-428c-a4f9-5f8e2374a075	27b45afc-dacc-42d2-b505-1cde88d20135	2	10	f	\N	\N
3ce93433-a892-4f6e-8e14-9cfe9bb9ecaf	\N	client-jwt	6f348afb-6f1f-428c-a4f9-5f8e2374a075	27b45afc-dacc-42d2-b505-1cde88d20135	2	20	f	\N	\N
3201485c-6fe3-4307-94af-ee01df000591	\N	client-secret-jwt	6f348afb-6f1f-428c-a4f9-5f8e2374a075	27b45afc-dacc-42d2-b505-1cde88d20135	2	30	f	\N	\N
94a9f79e-c79f-42e9-a7fe-07876fc7e0fd	\N	client-x509	6f348afb-6f1f-428c-a4f9-5f8e2374a075	27b45afc-dacc-42d2-b505-1cde88d20135	2	40	f	\N	\N
5c740fef-d56b-43b5-9da1-1673b717b052	\N	direct-grant-validate-username	6f348afb-6f1f-428c-a4f9-5f8e2374a075	d9478b18-9639-449e-85d6-56540f0803a1	0	10	f	\N	\N
7f7b86e3-8313-4eab-9c7a-8937da17f5a7	\N	direct-grant-validate-password	6f348afb-6f1f-428c-a4f9-5f8e2374a075	d9478b18-9639-449e-85d6-56540f0803a1	0	20	f	\N	\N
10a5bfc7-e33c-4273-b358-d57453de41a2	\N	\N	6f348afb-6f1f-428c-a4f9-5f8e2374a075	d9478b18-9639-449e-85d6-56540f0803a1	1	30	t	629c59ac-909c-4c3b-8d36-d9cb8d177f3f	\N
0cb664c6-85e0-4015-bf60-eeb6995d4d41	\N	docker-http-basic-authenticator	6f348afb-6f1f-428c-a4f9-5f8e2374a075	2c65eda3-a182-4a11-9ade-f61b78d78c6d	0	10	f	\N	\N
da4969d3-e125-44c1-9e43-7e66da3f9205	\N	idp-review-profile	6f348afb-6f1f-428c-a4f9-5f8e2374a075	c4a0ed65-c0be-4a58-b0a1-a68873949032	0	10	f	\N	24be9259-6ac1-4e0b-b776-5c8ec1d783ed
a365b5e5-6c2f-47f1-b0b2-cdb43817d1fc	\N	\N	6f348afb-6f1f-428c-a4f9-5f8e2374a075	c4a0ed65-c0be-4a58-b0a1-a68873949032	0	20	t	46f9b776-700b-4abd-8286-b4b23438c5a3	\N
038423da-5322-443e-b07f-32d3cc0cad00	\N	auth-username-password-form	6f348afb-6f1f-428c-a4f9-5f8e2374a075	604aafa0-254a-4ed4-a531-f83b47487901	0	10	f	\N	\N
eb3c3220-1928-44e1-b046-9a6c73274c21	\N	\N	6f348afb-6f1f-428c-a4f9-5f8e2374a075	604aafa0-254a-4ed4-a531-f83b47487901	1	20	t	9e3de326-f007-442f-9696-4ed6677f90e3	\N
6600465f-379b-4cfe-ba6d-ff71563119e5	\N	registration-page-form	6f348afb-6f1f-428c-a4f9-5f8e2374a075	3be806e8-49ce-4751-9818-4fbfb7027ccc	0	10	t	bb0a7b2c-c1d4-44fa-87ce-12fa5d617994	\N
8d13a623-dadf-40c6-b901-292107a0c062	\N	registration-user-creation	6f348afb-6f1f-428c-a4f9-5f8e2374a075	bb0a7b2c-c1d4-44fa-87ce-12fa5d617994	0	20	f	\N	\N
9c291201-5e6a-4f31-9462-d86ed817b558	\N	registration-password-action	6f348afb-6f1f-428c-a4f9-5f8e2374a075	bb0a7b2c-c1d4-44fa-87ce-12fa5d617994	0	50	f	\N	\N
7cd4503a-3276-4394-80c1-d773bce66109	\N	registration-recaptcha-action	6f348afb-6f1f-428c-a4f9-5f8e2374a075	bb0a7b2c-c1d4-44fa-87ce-12fa5d617994	3	60	f	\N	\N
e5bb9f61-3806-40c2-9e57-aeb5f35b4a5e	\N	reset-credentials-choose-user	6f348afb-6f1f-428c-a4f9-5f8e2374a075	f31bc3bf-8954-4ede-a514-84264864e7e3	0	10	f	\N	\N
b60ac1ec-ec91-4283-9e48-33b674b443b6	\N	reset-credential-email	6f348afb-6f1f-428c-a4f9-5f8e2374a075	f31bc3bf-8954-4ede-a514-84264864e7e3	0	20	f	\N	\N
0ca6d22a-3b4a-44e5-a66c-a188c58550c4	\N	reset-password	6f348afb-6f1f-428c-a4f9-5f8e2374a075	f31bc3bf-8954-4ede-a514-84264864e7e3	0	30	f	\N	\N
8518e81f-82e9-475c-b4e6-c9cf995c41a5	\N	\N	6f348afb-6f1f-428c-a4f9-5f8e2374a075	f31bc3bf-8954-4ede-a514-84264864e7e3	1	40	t	71157dfc-793e-4614-9256-a4ee5eedfef1	\N
608a1c20-cf86-4d33-b22b-cd61975b537b	\N	http-basic-authenticator	6f348afb-6f1f-428c-a4f9-5f8e2374a075	5c6cd2f4-83af-40ff-988b-062581eb15db	0	10	f	\N	\N
\.


--
-- Data for Name: authentication_flow; Type: TABLE DATA; Schema: public; Owner: keycloak
--

COPY public.authentication_flow (id, alias, description, realm_id, provider_id, top_level, built_in) FROM stdin;
5ee5265d-2b0a-4b44-8dfd-58462be34154	browser	Browser based authentication	86b2aa03-1225-4835-8758-60f4e03293c9	basic-flow	t	t
ea828dfe-c0e3-4ec1-94bd-2a90b09a057c	forms	Username, password, otp and other auth forms.	86b2aa03-1225-4835-8758-60f4e03293c9	basic-flow	f	t
8f32637e-d769-41f7-8be2-9e33a82e3a10	Browser - Conditional 2FA	Flow to determine if any 2FA is required for the authentication	86b2aa03-1225-4835-8758-60f4e03293c9	basic-flow	f	t
4876e118-2f71-4682-820b-d99a35ef1acb	direct grant	OpenID Connect Resource Owner Grant	86b2aa03-1225-4835-8758-60f4e03293c9	basic-flow	t	t
024e81d8-bb89-49f9-8a76-637bfd5ef9db	Direct Grant - Conditional OTP	Flow to determine if the OTP is required for the authentication	86b2aa03-1225-4835-8758-60f4e03293c9	basic-flow	f	t
76fb239a-cf69-42ef-a4f4-a66400fdea0e	registration	Registration flow	86b2aa03-1225-4835-8758-60f4e03293c9	basic-flow	t	t
3b101ee9-c6a1-4c5d-aa69-d6913675836a	registration form	Registration form	86b2aa03-1225-4835-8758-60f4e03293c9	form-flow	f	t
d4cfa9ae-6a39-41c0-8c2c-62a11c3d2117	reset credentials	Reset credentials for a user if they forgot their password or something	86b2aa03-1225-4835-8758-60f4e03293c9	basic-flow	t	t
bd3506e3-f07f-40a9-924d-1aeb3eca539e	Reset - Conditional OTP	Flow to determine if the OTP should be reset or not. Set to REQUIRED to force.	86b2aa03-1225-4835-8758-60f4e03293c9	basic-flow	f	t
63e59bd2-5003-4b43-b979-d7d3de974e6e	clients	Base authentication for clients	86b2aa03-1225-4835-8758-60f4e03293c9	client-flow	t	t
04b6912a-4ca7-42ac-8801-cacea86234f3	first broker login	Actions taken after first broker login with identity provider account, which is not yet linked to any Keycloak account	86b2aa03-1225-4835-8758-60f4e03293c9	basic-flow	t	t
5df76b61-2546-480d-9069-d2864e9d3112	User creation or linking	Flow for the existing/non-existing user alternatives	86b2aa03-1225-4835-8758-60f4e03293c9	basic-flow	f	t
0de69bf8-4373-49f0-9144-2504d70a6aab	Handle Existing Account	Handle what to do if there is existing account with same email/username like authenticated identity provider	86b2aa03-1225-4835-8758-60f4e03293c9	basic-flow	f	t
ee7c7c26-b20b-4e9a-a364-2295b6b60e7c	Account verification options	Method with which to verify the existing account	86b2aa03-1225-4835-8758-60f4e03293c9	basic-flow	f	t
a6dcf3be-0d17-493f-870b-2ee705bb513d	Verify Existing Account by Re-authentication	Reauthentication of existing account	86b2aa03-1225-4835-8758-60f4e03293c9	basic-flow	f	t
63408cca-96f3-4469-9212-ba0ebefac87e	First broker login - Conditional 2FA	Flow to determine if any 2FA is required for the authentication	86b2aa03-1225-4835-8758-60f4e03293c9	basic-flow	f	t
88a2ea30-229b-45f0-a605-bf36778777de	saml ecp	SAML ECP Profile Authentication Flow	86b2aa03-1225-4835-8758-60f4e03293c9	basic-flow	t	t
863d9eec-c10b-48fc-8356-ef79b8c47c23	docker auth	Used by Docker clients to authenticate against the IDP	86b2aa03-1225-4835-8758-60f4e03293c9	basic-flow	t	t
c9aa61d3-5d87-4cb2-83a9-fc164f2b5930	Account verification options	Method with which to verity the existing account	6f348afb-6f1f-428c-a4f9-5f8e2374a075	basic-flow	f	t
9e3de326-f007-442f-9696-4ed6677f90e3	Browser - Conditional OTP	Flow to determine if the OTP is required for the authentication	6f348afb-6f1f-428c-a4f9-5f8e2374a075	basic-flow	f	t
629c59ac-909c-4c3b-8d36-d9cb8d177f3f	Direct Grant - Conditional OTP	Flow to determine if the OTP is required for the authentication	6f348afb-6f1f-428c-a4f9-5f8e2374a075	basic-flow	f	t
c79256c5-d215-4ea7-b68c-b3a0d966930c	First broker login - Conditional OTP	Flow to determine if the OTP is required for the authentication	6f348afb-6f1f-428c-a4f9-5f8e2374a075	basic-flow	f	t
1ad3ab9e-54e4-4397-88a6-9fdec6501b19	Handle Existing Account	Handle what to do if there is existing account with same email/username like authenticated identity provider	6f348afb-6f1f-428c-a4f9-5f8e2374a075	basic-flow	f	t
71157dfc-793e-4614-9256-a4ee5eedfef1	Reset - Conditional OTP	Flow to determine if the OTP should be reset or not. Set to REQUIRED to force.	6f348afb-6f1f-428c-a4f9-5f8e2374a075	basic-flow	f	t
46f9b776-700b-4abd-8286-b4b23438c5a3	User creation or linking	Flow for the existing/non-existing user alternatives	6f348afb-6f1f-428c-a4f9-5f8e2374a075	basic-flow	f	t
e952c5c6-8849-4d75-b74e-2d2bdf8ac50f	Verify Existing Account by Re-authentication	Reauthentication of existing account	6f348afb-6f1f-428c-a4f9-5f8e2374a075	basic-flow	f	t
d53e6878-4a08-4737-8ec8-a893c1a25055	browser	browser based authentication	6f348afb-6f1f-428c-a4f9-5f8e2374a075	basic-flow	t	t
27b45afc-dacc-42d2-b505-1cde88d20135	clients	Base authentication for clients	6f348afb-6f1f-428c-a4f9-5f8e2374a075	client-flow	t	t
d9478b18-9639-449e-85d6-56540f0803a1	direct grant	OpenID Connect Resource Owner Grant	6f348afb-6f1f-428c-a4f9-5f8e2374a075	basic-flow	t	t
2c65eda3-a182-4a11-9ade-f61b78d78c6d	docker auth	Used by Docker clients to authenticate against the IDP	6f348afb-6f1f-428c-a4f9-5f8e2374a075	basic-flow	t	t
c4a0ed65-c0be-4a58-b0a1-a68873949032	first broker login	Actions taken after first broker login with identity provider account, which is not yet linked to any Keycloak account	6f348afb-6f1f-428c-a4f9-5f8e2374a075	basic-flow	t	t
604aafa0-254a-4ed4-a531-f83b47487901	forms	Username, password, otp and other auth forms.	6f348afb-6f1f-428c-a4f9-5f8e2374a075	basic-flow	f	t
3be806e8-49ce-4751-9818-4fbfb7027ccc	registration	registration flow	6f348afb-6f1f-428c-a4f9-5f8e2374a075	basic-flow	t	t
bb0a7b2c-c1d4-44fa-87ce-12fa5d617994	registration form	registration form	6f348afb-6f1f-428c-a4f9-5f8e2374a075	form-flow	f	t
f31bc3bf-8954-4ede-a514-84264864e7e3	reset credentials	Reset credentials for a user if they forgot their password or something	6f348afb-6f1f-428c-a4f9-5f8e2374a075	basic-flow	t	t
5c6cd2f4-83af-40ff-988b-062581eb15db	saml ecp	SAML ECP Profile Authentication Flow	6f348afb-6f1f-428c-a4f9-5f8e2374a075	basic-flow	t	t
6e76ce05-128f-4a95-ab0d-80f6b5d8ad38	gdi registration form	registration form	6f348afb-6f1f-428c-a4f9-5f8e2374a075	form-flow	f	f
16411ffa-cdf9-40bb-9d06-40de13d84c8e	gdi registration	registration flow	6f348afb-6f1f-428c-a4f9-5f8e2374a075	basic-flow	t	f
\.


--
-- Data for Name: authenticator_config; Type: TABLE DATA; Schema: public; Owner: keycloak
--

COPY public.authenticator_config (id, alias, realm_id) FROM stdin;
3b43db42-dcb2-487e-8340-d1344915e9f5	browser-conditional-credential	86b2aa03-1225-4835-8758-60f4e03293c9
c9bb0e7a-b25d-4041-bd27-679fb1c329c8	review profile config	86b2aa03-1225-4835-8758-60f4e03293c9
dce7939e-d3d3-43b6-b16a-3136b6355461	create unique user config	86b2aa03-1225-4835-8758-60f4e03293c9
f35eae04-ca7b-4dfa-9f04-fb4944e3c219	first-broker-login-conditional-credential	86b2aa03-1225-4835-8758-60f4e03293c9
cd71993a-b422-4a88-843a-415f62c820c9	create unique user config	6f348afb-6f1f-428c-a4f9-5f8e2374a075
24be9259-6ac1-4e0b-b776-5c8ec1d783ed	review profile config	6f348afb-6f1f-428c-a4f9-5f8e2374a075
\.


--
-- Data for Name: authenticator_config_entry; Type: TABLE DATA; Schema: public; Owner: keycloak
--

COPY public.authenticator_config_entry (authenticator_id, value, name) FROM stdin;
3b43db42-dcb2-487e-8340-d1344915e9f5	webauthn-passwordless	credentials
c9bb0e7a-b25d-4041-bd27-679fb1c329c8	missing	update.profile.on.first.login
dce7939e-d3d3-43b6-b16a-3136b6355461	false	require.password.update.after.registration
f35eae04-ca7b-4dfa-9f04-fb4944e3c219	webauthn-passwordless	credentials
24be9259-6ac1-4e0b-b776-5c8ec1d783ed	missing	update.profile.on.first.login
cd71993a-b422-4a88-843a-415f62c820c9	false	require.password.update.after.registration
\.


--
-- Data for Name: broker_link; Type: TABLE DATA; Schema: public; Owner: keycloak
--

COPY public.broker_link (identity_provider, storage_provider_id, realm_id, broker_user_id, broker_username, token, user_id) FROM stdin;
\.


--
-- Data for Name: client; Type: TABLE DATA; Schema: public; Owner: keycloak
--

COPY public.client (id, enabled, full_scope_allowed, client_id, not_before, public_client, secret, base_url, bearer_only, management_url, surrogate_auth_required, realm_id, protocol, node_rereg_timeout, frontchannel_logout, consent_required, name, service_accounts_enabled, client_authenticator_type, root_url, description, registration_token, standard_flow_enabled, implicit_flow_enabled, direct_access_grants_enabled, always_display_in_console) FROM stdin;
4109f0ef-0360-401b-b3c4-8e8fff5a4c07	t	f	master-realm	0	f	\N	\N	t	\N	f	86b2aa03-1225-4835-8758-60f4e03293c9	\N	0	f	f	master Realm	f	client-secret	\N	\N	\N	t	f	f	f
250d0061-d9ce-4ad2-888b-c5d151e2fe6d	t	f	account	0	t	\N	/realms/master/account/	f	\N	f	86b2aa03-1225-4835-8758-60f4e03293c9	openid-connect	0	f	f	${client_account}	f	client-secret	${authBaseUrl}	\N	\N	t	f	f	f
2a479066-384f-44a7-8ca2-7bb08a9c0b90	t	f	account-console	0	t	\N	/realms/master/account/	f	\N	f	86b2aa03-1225-4835-8758-60f4e03293c9	openid-connect	0	f	f	${client_account-console}	f	client-secret	${authBaseUrl}	\N	\N	t	f	f	f
65689518-2c8c-416b-9862-9acaaa6dbcd0	t	f	broker	0	f	\N	\N	t	\N	f	86b2aa03-1225-4835-8758-60f4e03293c9	openid-connect	0	f	f	${client_broker}	f	client-secret	\N	\N	\N	t	f	f	f
f6127f78-7990-4de5-8eba-6721209ae8d9	t	t	security-admin-console	0	t	\N	/admin/master/console/	f	\N	f	86b2aa03-1225-4835-8758-60f4e03293c9	openid-connect	0	f	f	${client_security-admin-console}	f	client-secret	${authAdminUrl}	\N	\N	t	f	f	f
579feb52-66cf-47ef-9386-fec098a4efb1	t	t	admin-cli	0	t	\N	\N	f	\N	f	86b2aa03-1225-4835-8758-60f4e03293c9	openid-connect	0	f	f	${client_admin-cli}	f	client-secret	\N	\N	\N	f	f	t	f
d9b73b9c-e8ac-4da7-aafb-9e39584eab85	t	f	gdi-realm	0	f	\N	\N	t	\N	f	86b2aa03-1225-4835-8758-60f4e03293c9	\N	0	f	f	gdi Realm	f	client-secret	\N	\N	\N	t	f	f	f
476d5095-dbf9-4fe0-bef8-fde1730956f9	t	f	account	0	t	\N	/realms/gdi/account/	f	\N	f	6f348afb-6f1f-428c-a4f9-5f8e2374a075	openid-connect	0	f	f	${client_account}	f	client-secret	${authBaseUrl}	\N	\N	t	f	f	f
632c3653-00fa-4b03-a4ed-81afbb16f16d	t	f	account-console	0	t	\N	/realms/gdi/account/	f	\N	f	6f348afb-6f1f-428c-a4f9-5f8e2374a075	openid-connect	0	f	f	${client_account-console}	f	client-secret	${authBaseUrl}	\N	\N	t	f	f	f
1a45d7a0-077f-4ec0-8e39-2526c2f3ff5f	t	t	admin-cli	0	t	\N	\N	f	\N	f	6f348afb-6f1f-428c-a4f9-5f8e2374a075	openid-connect	0	f	f	${client_admin-cli}	f	client-secret	\N	\N	\N	f	f	t	f
97b39b11-142c-4dce-b109-917b76790017	t	f	broker	0	f	\N	\N	t	\N	f	6f348afb-6f1f-428c-a4f9-5f8e2374a075	openid-connect	0	f	f	${client_broker}	f	client-secret	\N	\N	\N	t	f	f	f
49dfabcd-b980-414c-94a8-fdb65533ad2f	t	t	gdi	0	t	\N		f		f	6f348afb-6f1f-428c-a4f9-5f8e2374a075	openid-connect	-1	t	f		f	client-secret			\N	t	f	t	f
545c2160-f604-44d4-98c4-cf209d2d0b9d	t	t	ls-aai-service-account	0	f	aud6cgfQh5Dlqmz4eUMsa95DnSbof5wH		f		f	6f348afb-6f1f-428c-a4f9-5f8e2374a075	openid-connect	-1	t	f	ls-aai-service-account	t	client-secret			\N	f	f	f	f
ed6cb8f0-80e0-43a5-bade-3cb5f15f3cc5	t	f	realm-management	0	f	\N	\N	t	\N	f	6f348afb-6f1f-428c-a4f9-5f8e2374a075	openid-connect	0	f	f	${client_realm-management}	f	client-secret	\N	\N	\N	t	f	f	f
08d74ac1-49fc-469d-a687-9ab3b27b69b1	t	t	security-admin-console	0	t	\N	/admin/gdi/console/	f	\N	f	6f348afb-6f1f-428c-a4f9-5f8e2374a075	openid-connect	0	f	f	${client_security-admin-console}	f	client-secret	${authAdminUrl}	\N	\N	t	f	f	f
\.


--
-- Data for Name: client_attributes; Type: TABLE DATA; Schema: public; Owner: keycloak
--

COPY public.client_attributes (client_id, name, value) FROM stdin;
250d0061-d9ce-4ad2-888b-c5d151e2fe6d	post.logout.redirect.uris	+
2a479066-384f-44a7-8ca2-7bb08a9c0b90	post.logout.redirect.uris	+
2a479066-384f-44a7-8ca2-7bb08a9c0b90	pkce.code.challenge.method	S256
f6127f78-7990-4de5-8eba-6721209ae8d9	post.logout.redirect.uris	+
f6127f78-7990-4de5-8eba-6721209ae8d9	pkce.code.challenge.method	S256
f6127f78-7990-4de5-8eba-6721209ae8d9	client.use.lightweight.access.token.enabled	true
579feb52-66cf-47ef-9386-fec098a4efb1	client.use.lightweight.access.token.enabled	true
476d5095-dbf9-4fe0-bef8-fde1730956f9	realm_client	false
476d5095-dbf9-4fe0-bef8-fde1730956f9	post.logout.redirect.uris	+
632c3653-00fa-4b03-a4ed-81afbb16f16d	realm_client	false
632c3653-00fa-4b03-a4ed-81afbb16f16d	post.logout.redirect.uris	+
632c3653-00fa-4b03-a4ed-81afbb16f16d	pkce.code.challenge.method	S256
1a45d7a0-077f-4ec0-8e39-2526c2f3ff5f	realm_client	false
1a45d7a0-077f-4ec0-8e39-2526c2f3ff5f	client.use.lightweight.access.token.enabled	true
1a45d7a0-077f-4ec0-8e39-2526c2f3ff5f	post.logout.redirect.uris	+
97b39b11-142c-4dce-b109-917b76790017	realm_client	true
97b39b11-142c-4dce-b109-917b76790017	post.logout.redirect.uris	+
49dfabcd-b980-414c-94a8-fdb65533ad2f	realm_client	false
49dfabcd-b980-414c-94a8-fdb65533ad2f	oidc.ciba.grant.enabled	false
49dfabcd-b980-414c-94a8-fdb65533ad2f	client.secret.creation.time	1701295297
49dfabcd-b980-414c-94a8-fdb65533ad2f	backchannel.logout.session.required	true
49dfabcd-b980-414c-94a8-fdb65533ad2f	post.logout.redirect.uris	http://catalogue.local.onemilliongenomes.eu/*##http://discover.local.onemilliongenomes.eu/*##http://daam.local.onemilliongenomes.eu/*##https://oauth.pstmn.io/v1/callback
49dfabcd-b980-414c-94a8-fdb65533ad2f	display.on.consent.screen	false
49dfabcd-b980-414c-94a8-fdb65533ad2f	oauth2.device.authorization.grant.enabled	false
49dfabcd-b980-414c-94a8-fdb65533ad2f	backchannel.logout.revoke.offline.tokens	false
545c2160-f604-44d4-98c4-cf209d2d0b9d	realm_client	false
545c2160-f604-44d4-98c4-cf209d2d0b9d	oidc.ciba.grant.enabled	false
545c2160-f604-44d4-98c4-cf209d2d0b9d	client.secret.creation.time	1770675589
545c2160-f604-44d4-98c4-cf209d2d0b9d	backchannel.logout.session.required	true
545c2160-f604-44d4-98c4-cf209d2d0b9d	standard.token.exchange.enabled	false
545c2160-f604-44d4-98c4-cf209d2d0b9d	post.logout.redirect.uris	+
545c2160-f604-44d4-98c4-cf209d2d0b9d	oauth2.device.authorization.grant.enabled	false
545c2160-f604-44d4-98c4-cf209d2d0b9d	backchannel.logout.revoke.offline.tokens	false
545c2160-f604-44d4-98c4-cf209d2d0b9d	dpop.bound.access.tokens	false
ed6cb8f0-80e0-43a5-bade-3cb5f15f3cc5	realm_client	true
ed6cb8f0-80e0-43a5-bade-3cb5f15f3cc5	post.logout.redirect.uris	+
08d74ac1-49fc-469d-a687-9ab3b27b69b1	realm_client	false
08d74ac1-49fc-469d-a687-9ab3b27b69b1	client.use.lightweight.access.token.enabled	true
08d74ac1-49fc-469d-a687-9ab3b27b69b1	post.logout.redirect.uris	+
08d74ac1-49fc-469d-a687-9ab3b27b69b1	pkce.code.challenge.method	S256
\.


--
-- Data for Name: client_auth_flow_bindings; Type: TABLE DATA; Schema: public; Owner: keycloak
--

COPY public.client_auth_flow_bindings (client_id, flow_id, binding_name) FROM stdin;
\.


--
-- Data for Name: client_initial_access; Type: TABLE DATA; Schema: public; Owner: keycloak
--

COPY public.client_initial_access (id, realm_id, "timestamp", expiration, count, remaining_count) FROM stdin;
\.


--
-- Data for Name: client_node_registrations; Type: TABLE DATA; Schema: public; Owner: keycloak
--

COPY public.client_node_registrations (client_id, value, name) FROM stdin;
\.


--
-- Data for Name: client_scope; Type: TABLE DATA; Schema: public; Owner: keycloak
--

COPY public.client_scope (id, name, realm_id, description, protocol) FROM stdin;
c6794528-0a18-4fce-9988-f5f85635837c	offline_access	86b2aa03-1225-4835-8758-60f4e03293c9	OpenID Connect built-in scope: offline_access	openid-connect
e2ea9eef-0762-4ee6-8b90-04d1abd1316e	role_list	86b2aa03-1225-4835-8758-60f4e03293c9	SAML role list	saml
2722ccf7-8558-45d3-bd06-84b43c572a3c	saml_organization	86b2aa03-1225-4835-8758-60f4e03293c9	Organization Membership	saml
94c8b8ed-2c5f-4bdf-ba43-aa08c5fe9192	profile	86b2aa03-1225-4835-8758-60f4e03293c9	OpenID Connect built-in scope: profile	openid-connect
b1c22975-5e52-4a59-a2d5-c8b654fc6645	email	86b2aa03-1225-4835-8758-60f4e03293c9	OpenID Connect built-in scope: email	openid-connect
2bd86ed4-1786-44b4-b0b6-01fd86b24565	address	86b2aa03-1225-4835-8758-60f4e03293c9	OpenID Connect built-in scope: address	openid-connect
5337c14e-5172-43f9-a2a1-e1bb32385e7f	phone	86b2aa03-1225-4835-8758-60f4e03293c9	OpenID Connect built-in scope: phone	openid-connect
c9b53021-3bba-4908-90d8-755f38d861c8	roles	86b2aa03-1225-4835-8758-60f4e03293c9	OpenID Connect scope for add user roles to the access token	openid-connect
4ebd35f2-be54-4a34-bb50-4c1c4f2382f6	web-origins	86b2aa03-1225-4835-8758-60f4e03293c9	OpenID Connect scope for add allowed web origins to the access token	openid-connect
2b81c7e8-3993-456b-9341-05ecccfd5112	microprofile-jwt	86b2aa03-1225-4835-8758-60f4e03293c9	Microprofile - JWT built-in scope	openid-connect
85e82c50-2d25-4009-bdcf-765a62708f9f	acr	86b2aa03-1225-4835-8758-60f4e03293c9	OpenID Connect scope for add acr (authentication context class reference) to the token	openid-connect
cdba92d9-0fd2-4209-9f7c-e1f6f7ffbec6	basic	86b2aa03-1225-4835-8758-60f4e03293c9	OpenID Connect scope for add all basic claims to the token	openid-connect
df30f937-e897-416e-bf56-05fdd5acad60	service_account	86b2aa03-1225-4835-8758-60f4e03293c9	Specific scope for a client enabled for service accounts	openid-connect
e7bf5139-442c-419d-98b9-0833ce102d55	organization	86b2aa03-1225-4835-8758-60f4e03293c9	Additional claims about the organization a subject belongs to	openid-connect
49cae1f3-7c12-41d0-8e9a-189daa5b45ff	address	6f348afb-6f1f-428c-a4f9-5f8e2374a075	OpenID Connect built-in scope: address	openid-connect
b0edc86e-8c20-4f94-be36-e4a6c7913929	basic	6f348afb-6f1f-428c-a4f9-5f8e2374a075	OpenID Connect scope for add all basic claims to the token	openid-connect
0ca5fed1-0041-4acc-b018-b7d4da4c2a9a	email	6f348afb-6f1f-428c-a4f9-5f8e2374a075	OpenID Connect built-in scope: email	openid-connect
bb63fc7c-63cb-4b73-b607-497727b563f2	elixir_id	6f348afb-6f1f-428c-a4f9-5f8e2374a075	Elixer Id	openid-connect
ae433992-c6a6-46ed-89a5-75899f4edc99	microprofile-jwt	6f348afb-6f1f-428c-a4f9-5f8e2374a075	Microprofile - JWT built-in scope	openid-connect
c672e3cb-0646-46fb-887f-00be5de8a12e	web-origins	6f348afb-6f1f-428c-a4f9-5f8e2374a075	OpenID Connect scope for add allowed web origins to the access token	openid-connect
2bd35aef-70dd-4102-a8a9-f4c7e3135edc	phone	6f348afb-6f1f-428c-a4f9-5f8e2374a075	OpenID Connect built-in scope: phone	openid-connect
c5cd6971-f51b-4db8-a59a-3433c27d4882	service_account	6f348afb-6f1f-428c-a4f9-5f8e2374a075	Specific scope for a client enabled for service accounts	openid-connect
e217ed3a-3a19-4548-bbb5-19e9f2642ccd	roles	6f348afb-6f1f-428c-a4f9-5f8e2374a075	OpenID Connect scope for add user roles to the access token	openid-connect
52c605c5-9289-48c4-86bc-d6701a9008d1	offline_access	6f348afb-6f1f-428c-a4f9-5f8e2374a075	OpenID Connect built-in scope: offline_access	openid-connect
337dc738-9720-42e4-8cfa-ca816f3a9c47	profile	6f348afb-6f1f-428c-a4f9-5f8e2374a075	OpenID Connect built-in scope: profile	openid-connect
d797387e-1f5c-4232-8e68-f62892491073	role_list	6f348afb-6f1f-428c-a4f9-5f8e2374a075	SAML role list	saml
f3daaa09-a5d5-4766-ae71-487c67fc99af	acr	6f348afb-6f1f-428c-a4f9-5f8e2374a075	OpenID Connect scope for add acr (authentication context class reference) to the token	openid-connect
\.


--
-- Data for Name: client_scope_attributes; Type: TABLE DATA; Schema: public; Owner: keycloak
--

COPY public.client_scope_attributes (scope_id, value, name) FROM stdin;
c6794528-0a18-4fce-9988-f5f85635837c	true	display.on.consent.screen
c6794528-0a18-4fce-9988-f5f85635837c	${offlineAccessScopeConsentText}	consent.screen.text
e2ea9eef-0762-4ee6-8b90-04d1abd1316e	true	display.on.consent.screen
e2ea9eef-0762-4ee6-8b90-04d1abd1316e	${samlRoleListScopeConsentText}	consent.screen.text
2722ccf7-8558-45d3-bd06-84b43c572a3c	false	display.on.consent.screen
94c8b8ed-2c5f-4bdf-ba43-aa08c5fe9192	true	display.on.consent.screen
94c8b8ed-2c5f-4bdf-ba43-aa08c5fe9192	${profileScopeConsentText}	consent.screen.text
94c8b8ed-2c5f-4bdf-ba43-aa08c5fe9192	true	include.in.token.scope
b1c22975-5e52-4a59-a2d5-c8b654fc6645	true	display.on.consent.screen
b1c22975-5e52-4a59-a2d5-c8b654fc6645	${emailScopeConsentText}	consent.screen.text
b1c22975-5e52-4a59-a2d5-c8b654fc6645	true	include.in.token.scope
2bd86ed4-1786-44b4-b0b6-01fd86b24565	true	display.on.consent.screen
2bd86ed4-1786-44b4-b0b6-01fd86b24565	${addressScopeConsentText}	consent.screen.text
2bd86ed4-1786-44b4-b0b6-01fd86b24565	true	include.in.token.scope
5337c14e-5172-43f9-a2a1-e1bb32385e7f	true	display.on.consent.screen
5337c14e-5172-43f9-a2a1-e1bb32385e7f	${phoneScopeConsentText}	consent.screen.text
5337c14e-5172-43f9-a2a1-e1bb32385e7f	true	include.in.token.scope
c9b53021-3bba-4908-90d8-755f38d861c8	true	display.on.consent.screen
c9b53021-3bba-4908-90d8-755f38d861c8	${rolesScopeConsentText}	consent.screen.text
c9b53021-3bba-4908-90d8-755f38d861c8	false	include.in.token.scope
4ebd35f2-be54-4a34-bb50-4c1c4f2382f6	false	display.on.consent.screen
4ebd35f2-be54-4a34-bb50-4c1c4f2382f6		consent.screen.text
4ebd35f2-be54-4a34-bb50-4c1c4f2382f6	false	include.in.token.scope
2b81c7e8-3993-456b-9341-05ecccfd5112	false	display.on.consent.screen
2b81c7e8-3993-456b-9341-05ecccfd5112	true	include.in.token.scope
85e82c50-2d25-4009-bdcf-765a62708f9f	false	display.on.consent.screen
85e82c50-2d25-4009-bdcf-765a62708f9f	false	include.in.token.scope
cdba92d9-0fd2-4209-9f7c-e1f6f7ffbec6	false	display.on.consent.screen
cdba92d9-0fd2-4209-9f7c-e1f6f7ffbec6	false	include.in.token.scope
df30f937-e897-416e-bf56-05fdd5acad60	false	display.on.consent.screen
df30f937-e897-416e-bf56-05fdd5acad60	false	include.in.token.scope
e7bf5139-442c-419d-98b9-0833ce102d55	true	display.on.consent.screen
e7bf5139-442c-419d-98b9-0833ce102d55	${organizationScopeConsentText}	consent.screen.text
e7bf5139-442c-419d-98b9-0833ce102d55	true	include.in.token.scope
49cae1f3-7c12-41d0-8e9a-189daa5b45ff	true	include.in.token.scope
49cae1f3-7c12-41d0-8e9a-189daa5b45ff	${addressScopeConsentText}	consent.screen.text
49cae1f3-7c12-41d0-8e9a-189daa5b45ff	true	display.on.consent.screen
b0edc86e-8c20-4f94-be36-e4a6c7913929	false	include.in.token.scope
b0edc86e-8c20-4f94-be36-e4a6c7913929	false	display.on.consent.screen
0ca5fed1-0041-4acc-b018-b7d4da4c2a9a	true	include.in.token.scope
0ca5fed1-0041-4acc-b018-b7d4da4c2a9a	${emailScopeConsentText}	consent.screen.text
0ca5fed1-0041-4acc-b018-b7d4da4c2a9a	true	display.on.consent.screen
bb63fc7c-63cb-4b73-b607-497727b563f2	true	include.in.token.scope
bb63fc7c-63cb-4b73-b607-497727b563f2	true	display.on.consent.screen
bb63fc7c-63cb-4b73-b607-497727b563f2		gui.order
bb63fc7c-63cb-4b73-b607-497727b563f2		consent.screen.text
ae433992-c6a6-46ed-89a5-75899f4edc99	true	include.in.token.scope
ae433992-c6a6-46ed-89a5-75899f4edc99	false	display.on.consent.screen
c672e3cb-0646-46fb-887f-00be5de8a12e	false	include.in.token.scope
c672e3cb-0646-46fb-887f-00be5de8a12e		consent.screen.text
c672e3cb-0646-46fb-887f-00be5de8a12e	false	display.on.consent.screen
2bd35aef-70dd-4102-a8a9-f4c7e3135edc	true	include.in.token.scope
2bd35aef-70dd-4102-a8a9-f4c7e3135edc	${phoneScopeConsentText}	consent.screen.text
2bd35aef-70dd-4102-a8a9-f4c7e3135edc	true	display.on.consent.screen
c5cd6971-f51b-4db8-a59a-3433c27d4882	false	include.in.token.scope
c5cd6971-f51b-4db8-a59a-3433c27d4882	false	display.on.consent.screen
e217ed3a-3a19-4548-bbb5-19e9f2642ccd	false	include.in.token.scope
e217ed3a-3a19-4548-bbb5-19e9f2642ccd	${rolesScopeConsentText}	consent.screen.text
e217ed3a-3a19-4548-bbb5-19e9f2642ccd	true	display.on.consent.screen
52c605c5-9289-48c4-86bc-d6701a9008d1	${offlineAccessScopeConsentText}	consent.screen.text
52c605c5-9289-48c4-86bc-d6701a9008d1	true	display.on.consent.screen
337dc738-9720-42e4-8cfa-ca816f3a9c47	true	include.in.token.scope
337dc738-9720-42e4-8cfa-ca816f3a9c47	${profileScopeConsentText}	consent.screen.text
337dc738-9720-42e4-8cfa-ca816f3a9c47	true	display.on.consent.screen
d797387e-1f5c-4232-8e68-f62892491073	${samlRoleListScopeConsentText}	consent.screen.text
d797387e-1f5c-4232-8e68-f62892491073	true	display.on.consent.screen
f3daaa09-a5d5-4766-ae71-487c67fc99af	false	include.in.token.scope
f3daaa09-a5d5-4766-ae71-487c67fc99af	false	display.on.consent.screen
\.


--
-- Data for Name: client_scope_client; Type: TABLE DATA; Schema: public; Owner: keycloak
--

COPY public.client_scope_client (client_id, scope_id, default_scope) FROM stdin;
250d0061-d9ce-4ad2-888b-c5d151e2fe6d	4ebd35f2-be54-4a34-bb50-4c1c4f2382f6	t
250d0061-d9ce-4ad2-888b-c5d151e2fe6d	c9b53021-3bba-4908-90d8-755f38d861c8	t
250d0061-d9ce-4ad2-888b-c5d151e2fe6d	94c8b8ed-2c5f-4bdf-ba43-aa08c5fe9192	t
250d0061-d9ce-4ad2-888b-c5d151e2fe6d	cdba92d9-0fd2-4209-9f7c-e1f6f7ffbec6	t
250d0061-d9ce-4ad2-888b-c5d151e2fe6d	b1c22975-5e52-4a59-a2d5-c8b654fc6645	t
250d0061-d9ce-4ad2-888b-c5d151e2fe6d	85e82c50-2d25-4009-bdcf-765a62708f9f	t
250d0061-d9ce-4ad2-888b-c5d151e2fe6d	e7bf5139-442c-419d-98b9-0833ce102d55	f
250d0061-d9ce-4ad2-888b-c5d151e2fe6d	5337c14e-5172-43f9-a2a1-e1bb32385e7f	f
250d0061-d9ce-4ad2-888b-c5d151e2fe6d	2bd86ed4-1786-44b4-b0b6-01fd86b24565	f
250d0061-d9ce-4ad2-888b-c5d151e2fe6d	c6794528-0a18-4fce-9988-f5f85635837c	f
250d0061-d9ce-4ad2-888b-c5d151e2fe6d	2b81c7e8-3993-456b-9341-05ecccfd5112	f
2a479066-384f-44a7-8ca2-7bb08a9c0b90	4ebd35f2-be54-4a34-bb50-4c1c4f2382f6	t
2a479066-384f-44a7-8ca2-7bb08a9c0b90	c9b53021-3bba-4908-90d8-755f38d861c8	t
2a479066-384f-44a7-8ca2-7bb08a9c0b90	94c8b8ed-2c5f-4bdf-ba43-aa08c5fe9192	t
2a479066-384f-44a7-8ca2-7bb08a9c0b90	cdba92d9-0fd2-4209-9f7c-e1f6f7ffbec6	t
2a479066-384f-44a7-8ca2-7bb08a9c0b90	b1c22975-5e52-4a59-a2d5-c8b654fc6645	t
2a479066-384f-44a7-8ca2-7bb08a9c0b90	85e82c50-2d25-4009-bdcf-765a62708f9f	t
2a479066-384f-44a7-8ca2-7bb08a9c0b90	e7bf5139-442c-419d-98b9-0833ce102d55	f
2a479066-384f-44a7-8ca2-7bb08a9c0b90	5337c14e-5172-43f9-a2a1-e1bb32385e7f	f
2a479066-384f-44a7-8ca2-7bb08a9c0b90	2bd86ed4-1786-44b4-b0b6-01fd86b24565	f
2a479066-384f-44a7-8ca2-7bb08a9c0b90	c6794528-0a18-4fce-9988-f5f85635837c	f
2a479066-384f-44a7-8ca2-7bb08a9c0b90	2b81c7e8-3993-456b-9341-05ecccfd5112	f
579feb52-66cf-47ef-9386-fec098a4efb1	4ebd35f2-be54-4a34-bb50-4c1c4f2382f6	t
579feb52-66cf-47ef-9386-fec098a4efb1	c9b53021-3bba-4908-90d8-755f38d861c8	t
579feb52-66cf-47ef-9386-fec098a4efb1	94c8b8ed-2c5f-4bdf-ba43-aa08c5fe9192	t
579feb52-66cf-47ef-9386-fec098a4efb1	cdba92d9-0fd2-4209-9f7c-e1f6f7ffbec6	t
579feb52-66cf-47ef-9386-fec098a4efb1	b1c22975-5e52-4a59-a2d5-c8b654fc6645	t
579feb52-66cf-47ef-9386-fec098a4efb1	85e82c50-2d25-4009-bdcf-765a62708f9f	t
579feb52-66cf-47ef-9386-fec098a4efb1	e7bf5139-442c-419d-98b9-0833ce102d55	f
579feb52-66cf-47ef-9386-fec098a4efb1	5337c14e-5172-43f9-a2a1-e1bb32385e7f	f
579feb52-66cf-47ef-9386-fec098a4efb1	2bd86ed4-1786-44b4-b0b6-01fd86b24565	f
579feb52-66cf-47ef-9386-fec098a4efb1	c6794528-0a18-4fce-9988-f5f85635837c	f
579feb52-66cf-47ef-9386-fec098a4efb1	2b81c7e8-3993-456b-9341-05ecccfd5112	f
65689518-2c8c-416b-9862-9acaaa6dbcd0	4ebd35f2-be54-4a34-bb50-4c1c4f2382f6	t
65689518-2c8c-416b-9862-9acaaa6dbcd0	c9b53021-3bba-4908-90d8-755f38d861c8	t
65689518-2c8c-416b-9862-9acaaa6dbcd0	94c8b8ed-2c5f-4bdf-ba43-aa08c5fe9192	t
65689518-2c8c-416b-9862-9acaaa6dbcd0	cdba92d9-0fd2-4209-9f7c-e1f6f7ffbec6	t
65689518-2c8c-416b-9862-9acaaa6dbcd0	b1c22975-5e52-4a59-a2d5-c8b654fc6645	t
65689518-2c8c-416b-9862-9acaaa6dbcd0	85e82c50-2d25-4009-bdcf-765a62708f9f	t
65689518-2c8c-416b-9862-9acaaa6dbcd0	e7bf5139-442c-419d-98b9-0833ce102d55	f
65689518-2c8c-416b-9862-9acaaa6dbcd0	5337c14e-5172-43f9-a2a1-e1bb32385e7f	f
65689518-2c8c-416b-9862-9acaaa6dbcd0	2bd86ed4-1786-44b4-b0b6-01fd86b24565	f
65689518-2c8c-416b-9862-9acaaa6dbcd0	c6794528-0a18-4fce-9988-f5f85635837c	f
65689518-2c8c-416b-9862-9acaaa6dbcd0	2b81c7e8-3993-456b-9341-05ecccfd5112	f
4109f0ef-0360-401b-b3c4-8e8fff5a4c07	4ebd35f2-be54-4a34-bb50-4c1c4f2382f6	t
4109f0ef-0360-401b-b3c4-8e8fff5a4c07	c9b53021-3bba-4908-90d8-755f38d861c8	t
4109f0ef-0360-401b-b3c4-8e8fff5a4c07	94c8b8ed-2c5f-4bdf-ba43-aa08c5fe9192	t
4109f0ef-0360-401b-b3c4-8e8fff5a4c07	cdba92d9-0fd2-4209-9f7c-e1f6f7ffbec6	t
4109f0ef-0360-401b-b3c4-8e8fff5a4c07	b1c22975-5e52-4a59-a2d5-c8b654fc6645	t
4109f0ef-0360-401b-b3c4-8e8fff5a4c07	85e82c50-2d25-4009-bdcf-765a62708f9f	t
4109f0ef-0360-401b-b3c4-8e8fff5a4c07	e7bf5139-442c-419d-98b9-0833ce102d55	f
4109f0ef-0360-401b-b3c4-8e8fff5a4c07	5337c14e-5172-43f9-a2a1-e1bb32385e7f	f
4109f0ef-0360-401b-b3c4-8e8fff5a4c07	2bd86ed4-1786-44b4-b0b6-01fd86b24565	f
4109f0ef-0360-401b-b3c4-8e8fff5a4c07	c6794528-0a18-4fce-9988-f5f85635837c	f
4109f0ef-0360-401b-b3c4-8e8fff5a4c07	2b81c7e8-3993-456b-9341-05ecccfd5112	f
f6127f78-7990-4de5-8eba-6721209ae8d9	4ebd35f2-be54-4a34-bb50-4c1c4f2382f6	t
f6127f78-7990-4de5-8eba-6721209ae8d9	c9b53021-3bba-4908-90d8-755f38d861c8	t
f6127f78-7990-4de5-8eba-6721209ae8d9	94c8b8ed-2c5f-4bdf-ba43-aa08c5fe9192	t
f6127f78-7990-4de5-8eba-6721209ae8d9	cdba92d9-0fd2-4209-9f7c-e1f6f7ffbec6	t
f6127f78-7990-4de5-8eba-6721209ae8d9	b1c22975-5e52-4a59-a2d5-c8b654fc6645	t
f6127f78-7990-4de5-8eba-6721209ae8d9	85e82c50-2d25-4009-bdcf-765a62708f9f	t
f6127f78-7990-4de5-8eba-6721209ae8d9	e7bf5139-442c-419d-98b9-0833ce102d55	f
f6127f78-7990-4de5-8eba-6721209ae8d9	5337c14e-5172-43f9-a2a1-e1bb32385e7f	f
f6127f78-7990-4de5-8eba-6721209ae8d9	2bd86ed4-1786-44b4-b0b6-01fd86b24565	f
f6127f78-7990-4de5-8eba-6721209ae8d9	c6794528-0a18-4fce-9988-f5f85635837c	f
f6127f78-7990-4de5-8eba-6721209ae8d9	2b81c7e8-3993-456b-9341-05ecccfd5112	f
476d5095-dbf9-4fe0-bef8-fde1730956f9	b0edc86e-8c20-4f94-be36-e4a6c7913929	t
476d5095-dbf9-4fe0-bef8-fde1730956f9	337dc738-9720-42e4-8cfa-ca816f3a9c47	t
476d5095-dbf9-4fe0-bef8-fde1730956f9	0ca5fed1-0041-4acc-b018-b7d4da4c2a9a	t
476d5095-dbf9-4fe0-bef8-fde1730956f9	c672e3cb-0646-46fb-887f-00be5de8a12e	t
476d5095-dbf9-4fe0-bef8-fde1730956f9	e217ed3a-3a19-4548-bbb5-19e9f2642ccd	t
476d5095-dbf9-4fe0-bef8-fde1730956f9	f3daaa09-a5d5-4766-ae71-487c67fc99af	t
476d5095-dbf9-4fe0-bef8-fde1730956f9	49cae1f3-7c12-41d0-8e9a-189daa5b45ff	f
476d5095-dbf9-4fe0-bef8-fde1730956f9	ae433992-c6a6-46ed-89a5-75899f4edc99	f
476d5095-dbf9-4fe0-bef8-fde1730956f9	2bd35aef-70dd-4102-a8a9-f4c7e3135edc	f
476d5095-dbf9-4fe0-bef8-fde1730956f9	52c605c5-9289-48c4-86bc-d6701a9008d1	f
632c3653-00fa-4b03-a4ed-81afbb16f16d	b0edc86e-8c20-4f94-be36-e4a6c7913929	t
632c3653-00fa-4b03-a4ed-81afbb16f16d	337dc738-9720-42e4-8cfa-ca816f3a9c47	t
632c3653-00fa-4b03-a4ed-81afbb16f16d	0ca5fed1-0041-4acc-b018-b7d4da4c2a9a	t
632c3653-00fa-4b03-a4ed-81afbb16f16d	c672e3cb-0646-46fb-887f-00be5de8a12e	t
632c3653-00fa-4b03-a4ed-81afbb16f16d	e217ed3a-3a19-4548-bbb5-19e9f2642ccd	t
632c3653-00fa-4b03-a4ed-81afbb16f16d	f3daaa09-a5d5-4766-ae71-487c67fc99af	t
632c3653-00fa-4b03-a4ed-81afbb16f16d	49cae1f3-7c12-41d0-8e9a-189daa5b45ff	f
632c3653-00fa-4b03-a4ed-81afbb16f16d	ae433992-c6a6-46ed-89a5-75899f4edc99	f
632c3653-00fa-4b03-a4ed-81afbb16f16d	2bd35aef-70dd-4102-a8a9-f4c7e3135edc	f
632c3653-00fa-4b03-a4ed-81afbb16f16d	52c605c5-9289-48c4-86bc-d6701a9008d1	f
632c3653-00fa-4b03-a4ed-81afbb16f16d	c5cd6971-f51b-4db8-a59a-3433c27d4882	t
632c3653-00fa-4b03-a4ed-81afbb16f16d	bb63fc7c-63cb-4b73-b607-497727b563f2	t
1a45d7a0-077f-4ec0-8e39-2526c2f3ff5f	b0edc86e-8c20-4f94-be36-e4a6c7913929	t
1a45d7a0-077f-4ec0-8e39-2526c2f3ff5f	337dc738-9720-42e4-8cfa-ca816f3a9c47	t
1a45d7a0-077f-4ec0-8e39-2526c2f3ff5f	0ca5fed1-0041-4acc-b018-b7d4da4c2a9a	t
1a45d7a0-077f-4ec0-8e39-2526c2f3ff5f	c672e3cb-0646-46fb-887f-00be5de8a12e	t
1a45d7a0-077f-4ec0-8e39-2526c2f3ff5f	e217ed3a-3a19-4548-bbb5-19e9f2642ccd	t
1a45d7a0-077f-4ec0-8e39-2526c2f3ff5f	f3daaa09-a5d5-4766-ae71-487c67fc99af	t
1a45d7a0-077f-4ec0-8e39-2526c2f3ff5f	49cae1f3-7c12-41d0-8e9a-189daa5b45ff	f
1a45d7a0-077f-4ec0-8e39-2526c2f3ff5f	ae433992-c6a6-46ed-89a5-75899f4edc99	f
1a45d7a0-077f-4ec0-8e39-2526c2f3ff5f	2bd35aef-70dd-4102-a8a9-f4c7e3135edc	f
1a45d7a0-077f-4ec0-8e39-2526c2f3ff5f	52c605c5-9289-48c4-86bc-d6701a9008d1	f
97b39b11-142c-4dce-b109-917b76790017	337dc738-9720-42e4-8cfa-ca816f3a9c47	t
97b39b11-142c-4dce-b109-917b76790017	0ca5fed1-0041-4acc-b018-b7d4da4c2a9a	t
97b39b11-142c-4dce-b109-917b76790017	c672e3cb-0646-46fb-887f-00be5de8a12e	t
97b39b11-142c-4dce-b109-917b76790017	e217ed3a-3a19-4548-bbb5-19e9f2642ccd	t
97b39b11-142c-4dce-b109-917b76790017	f3daaa09-a5d5-4766-ae71-487c67fc99af	t
97b39b11-142c-4dce-b109-917b76790017	49cae1f3-7c12-41d0-8e9a-189daa5b45ff	f
97b39b11-142c-4dce-b109-917b76790017	ae433992-c6a6-46ed-89a5-75899f4edc99	f
97b39b11-142c-4dce-b109-917b76790017	2bd35aef-70dd-4102-a8a9-f4c7e3135edc	f
97b39b11-142c-4dce-b109-917b76790017	52c605c5-9289-48c4-86bc-d6701a9008d1	f
49dfabcd-b980-414c-94a8-fdb65533ad2f	b0edc86e-8c20-4f94-be36-e4a6c7913929	t
49dfabcd-b980-414c-94a8-fdb65533ad2f	337dc738-9720-42e4-8cfa-ca816f3a9c47	t
49dfabcd-b980-414c-94a8-fdb65533ad2f	0ca5fed1-0041-4acc-b018-b7d4da4c2a9a	t
49dfabcd-b980-414c-94a8-fdb65533ad2f	c672e3cb-0646-46fb-887f-00be5de8a12e	t
49dfabcd-b980-414c-94a8-fdb65533ad2f	e217ed3a-3a19-4548-bbb5-19e9f2642ccd	t
49dfabcd-b980-414c-94a8-fdb65533ad2f	f3daaa09-a5d5-4766-ae71-487c67fc99af	t
49dfabcd-b980-414c-94a8-fdb65533ad2f	49cae1f3-7c12-41d0-8e9a-189daa5b45ff	f
49dfabcd-b980-414c-94a8-fdb65533ad2f	ae433992-c6a6-46ed-89a5-75899f4edc99	f
49dfabcd-b980-414c-94a8-fdb65533ad2f	2bd35aef-70dd-4102-a8a9-f4c7e3135edc	f
49dfabcd-b980-414c-94a8-fdb65533ad2f	52c605c5-9289-48c4-86bc-d6701a9008d1	f
49dfabcd-b980-414c-94a8-fdb65533ad2f	bb63fc7c-63cb-4b73-b607-497727b563f2	t
545c2160-f604-44d4-98c4-cf209d2d0b9d	b0edc86e-8c20-4f94-be36-e4a6c7913929	t
545c2160-f604-44d4-98c4-cf209d2d0b9d	337dc738-9720-42e4-8cfa-ca816f3a9c47	t
545c2160-f604-44d4-98c4-cf209d2d0b9d	0ca5fed1-0041-4acc-b018-b7d4da4c2a9a	t
545c2160-f604-44d4-98c4-cf209d2d0b9d	c672e3cb-0646-46fb-887f-00be5de8a12e	t
545c2160-f604-44d4-98c4-cf209d2d0b9d	e217ed3a-3a19-4548-bbb5-19e9f2642ccd	t
545c2160-f604-44d4-98c4-cf209d2d0b9d	f3daaa09-a5d5-4766-ae71-487c67fc99af	t
545c2160-f604-44d4-98c4-cf209d2d0b9d	49cae1f3-7c12-41d0-8e9a-189daa5b45ff	f
545c2160-f604-44d4-98c4-cf209d2d0b9d	ae433992-c6a6-46ed-89a5-75899f4edc99	f
545c2160-f604-44d4-98c4-cf209d2d0b9d	2bd35aef-70dd-4102-a8a9-f4c7e3135edc	f
545c2160-f604-44d4-98c4-cf209d2d0b9d	52c605c5-9289-48c4-86bc-d6701a9008d1	f
545c2160-f604-44d4-98c4-cf209d2d0b9d	c5cd6971-f51b-4db8-a59a-3433c27d4882	t
ed6cb8f0-80e0-43a5-bade-3cb5f15f3cc5	337dc738-9720-42e4-8cfa-ca816f3a9c47	t
ed6cb8f0-80e0-43a5-bade-3cb5f15f3cc5	0ca5fed1-0041-4acc-b018-b7d4da4c2a9a	t
ed6cb8f0-80e0-43a5-bade-3cb5f15f3cc5	c672e3cb-0646-46fb-887f-00be5de8a12e	t
ed6cb8f0-80e0-43a5-bade-3cb5f15f3cc5	e217ed3a-3a19-4548-bbb5-19e9f2642ccd	t
ed6cb8f0-80e0-43a5-bade-3cb5f15f3cc5	f3daaa09-a5d5-4766-ae71-487c67fc99af	t
ed6cb8f0-80e0-43a5-bade-3cb5f15f3cc5	49cae1f3-7c12-41d0-8e9a-189daa5b45ff	f
ed6cb8f0-80e0-43a5-bade-3cb5f15f3cc5	ae433992-c6a6-46ed-89a5-75899f4edc99	f
ed6cb8f0-80e0-43a5-bade-3cb5f15f3cc5	2bd35aef-70dd-4102-a8a9-f4c7e3135edc	f
ed6cb8f0-80e0-43a5-bade-3cb5f15f3cc5	52c605c5-9289-48c4-86bc-d6701a9008d1	f
08d74ac1-49fc-469d-a687-9ab3b27b69b1	b0edc86e-8c20-4f94-be36-e4a6c7913929	t
08d74ac1-49fc-469d-a687-9ab3b27b69b1	337dc738-9720-42e4-8cfa-ca816f3a9c47	t
08d74ac1-49fc-469d-a687-9ab3b27b69b1	0ca5fed1-0041-4acc-b018-b7d4da4c2a9a	t
08d74ac1-49fc-469d-a687-9ab3b27b69b1	c672e3cb-0646-46fb-887f-00be5de8a12e	t
08d74ac1-49fc-469d-a687-9ab3b27b69b1	e217ed3a-3a19-4548-bbb5-19e9f2642ccd	t
08d74ac1-49fc-469d-a687-9ab3b27b69b1	f3daaa09-a5d5-4766-ae71-487c67fc99af	t
08d74ac1-49fc-469d-a687-9ab3b27b69b1	49cae1f3-7c12-41d0-8e9a-189daa5b45ff	f
08d74ac1-49fc-469d-a687-9ab3b27b69b1	ae433992-c6a6-46ed-89a5-75899f4edc99	f
08d74ac1-49fc-469d-a687-9ab3b27b69b1	2bd35aef-70dd-4102-a8a9-f4c7e3135edc	f
08d74ac1-49fc-469d-a687-9ab3b27b69b1	52c605c5-9289-48c4-86bc-d6701a9008d1	f
\.


--
-- Data for Name: client_scope_role_mapping; Type: TABLE DATA; Schema: public; Owner: keycloak
--

COPY public.client_scope_role_mapping (scope_id, role_id) FROM stdin;
c6794528-0a18-4fce-9988-f5f85635837c	f9a0073f-89ef-423a-a038-d800c88c050f
52c605c5-9289-48c4-86bc-d6701a9008d1	20d863dd-6c6a-4357-bea7-50ca195e9032
\.


--
-- Data for Name: component; Type: TABLE DATA; Schema: public; Owner: keycloak
--

COPY public.component (id, name, parent_id, provider_id, provider_type, realm_id, sub_type) FROM stdin;
8b67bd1f-ace1-422f-90e9-bd3ff9d7f2c5	Trusted Hosts	86b2aa03-1225-4835-8758-60f4e03293c9	trusted-hosts	org.keycloak.services.clientregistration.policy.ClientRegistrationPolicy	86b2aa03-1225-4835-8758-60f4e03293c9	anonymous
04b8f1a7-17fc-4df8-81e5-98e1499a6444	Consent Required	86b2aa03-1225-4835-8758-60f4e03293c9	consent-required	org.keycloak.services.clientregistration.policy.ClientRegistrationPolicy	86b2aa03-1225-4835-8758-60f4e03293c9	anonymous
b364d7e2-86c7-4b7c-a47a-b76316c38535	Full Scope Disabled	86b2aa03-1225-4835-8758-60f4e03293c9	scope	org.keycloak.services.clientregistration.policy.ClientRegistrationPolicy	86b2aa03-1225-4835-8758-60f4e03293c9	anonymous
9cf91845-1790-4deb-8bae-bc01aa3235cf	Max Clients Limit	86b2aa03-1225-4835-8758-60f4e03293c9	max-clients	org.keycloak.services.clientregistration.policy.ClientRegistrationPolicy	86b2aa03-1225-4835-8758-60f4e03293c9	anonymous
5ace0c28-41e6-41ed-8b00-62b2e7f4d24b	Allowed Protocol Mapper Types	86b2aa03-1225-4835-8758-60f4e03293c9	allowed-protocol-mappers	org.keycloak.services.clientregistration.policy.ClientRegistrationPolicy	86b2aa03-1225-4835-8758-60f4e03293c9	anonymous
e7f03640-a4de-4eba-825e-25521d190996	Allowed Client Scopes	86b2aa03-1225-4835-8758-60f4e03293c9	allowed-client-templates	org.keycloak.services.clientregistration.policy.ClientRegistrationPolicy	86b2aa03-1225-4835-8758-60f4e03293c9	anonymous
ffd1c6fa-0a9b-4073-94ef-26cd82529eb0	Allowed Registration Web Origins	86b2aa03-1225-4835-8758-60f4e03293c9	registration-web-origins	org.keycloak.services.clientregistration.policy.ClientRegistrationPolicy	86b2aa03-1225-4835-8758-60f4e03293c9	anonymous
2baacfb9-d6d7-49b1-8038-6718327e602e	Allowed Protocol Mapper Types	86b2aa03-1225-4835-8758-60f4e03293c9	allowed-protocol-mappers	org.keycloak.services.clientregistration.policy.ClientRegistrationPolicy	86b2aa03-1225-4835-8758-60f4e03293c9	authenticated
a73f1369-145c-41e8-bb34-10a6a4ac131e	Allowed Client Scopes	86b2aa03-1225-4835-8758-60f4e03293c9	allowed-client-templates	org.keycloak.services.clientregistration.policy.ClientRegistrationPolicy	86b2aa03-1225-4835-8758-60f4e03293c9	authenticated
5517fef7-a73b-4d86-9ab3-1dfd49e1b813	Allowed Registration Web Origins	86b2aa03-1225-4835-8758-60f4e03293c9	registration-web-origins	org.keycloak.services.clientregistration.policy.ClientRegistrationPolicy	86b2aa03-1225-4835-8758-60f4e03293c9	authenticated
f29f8312-3759-418b-8dff-7306215dce6b	rsa-generated	86b2aa03-1225-4835-8758-60f4e03293c9	rsa-generated	org.keycloak.keys.KeyProvider	86b2aa03-1225-4835-8758-60f4e03293c9	\N
994c0f5a-f8e0-460f-9d89-d860cc9c633d	rsa-enc-generated	86b2aa03-1225-4835-8758-60f4e03293c9	rsa-enc-generated	org.keycloak.keys.KeyProvider	86b2aa03-1225-4835-8758-60f4e03293c9	\N
83b0ab2d-4afe-4044-b38c-dbcb002f5614	hmac-generated-hs512	86b2aa03-1225-4835-8758-60f4e03293c9	hmac-generated	org.keycloak.keys.KeyProvider	86b2aa03-1225-4835-8758-60f4e03293c9	\N
f6c1dada-de5f-46fb-b9ef-0d9f0c0bc061	aes-generated	86b2aa03-1225-4835-8758-60f4e03293c9	aes-generated	org.keycloak.keys.KeyProvider	86b2aa03-1225-4835-8758-60f4e03293c9	\N
af5e8188-358e-43d1-9a6b-b77f9fd42351	\N	86b2aa03-1225-4835-8758-60f4e03293c9	declarative-user-profile	org.keycloak.userprofile.UserProfileProvider	86b2aa03-1225-4835-8758-60f4e03293c9	\N
45df67e2-101f-471b-aa00-dbf11bd13bf6	Allowed Protocol Mapper Types	6f348afb-6f1f-428c-a4f9-5f8e2374a075	allowed-protocol-mappers	org.keycloak.services.clientregistration.policy.ClientRegistrationPolicy	6f348afb-6f1f-428c-a4f9-5f8e2374a075	authenticated
1a9c6e95-2a93-47b4-83ee-b414941cac4e	Consent Required	6f348afb-6f1f-428c-a4f9-5f8e2374a075	consent-required	org.keycloak.services.clientregistration.policy.ClientRegistrationPolicy	6f348afb-6f1f-428c-a4f9-5f8e2374a075	anonymous
785f873e-bf19-4386-a4b8-8c3a901a6580	Trusted Hosts	6f348afb-6f1f-428c-a4f9-5f8e2374a075	trusted-hosts	org.keycloak.services.clientregistration.policy.ClientRegistrationPolicy	6f348afb-6f1f-428c-a4f9-5f8e2374a075	anonymous
3a90975c-27da-4807-9918-85c4d170880c	Max Clients Limit	6f348afb-6f1f-428c-a4f9-5f8e2374a075	max-clients	org.keycloak.services.clientregistration.policy.ClientRegistrationPolicy	6f348afb-6f1f-428c-a4f9-5f8e2374a075	anonymous
d4ec2bdf-67fe-4c7a-bd62-d6cbe89046d5	Allowed Client Scopes	6f348afb-6f1f-428c-a4f9-5f8e2374a075	allowed-client-templates	org.keycloak.services.clientregistration.policy.ClientRegistrationPolicy	6f348afb-6f1f-428c-a4f9-5f8e2374a075	anonymous
895416e8-a54b-4695-9a2f-422c00e70466	Allowed Protocol Mapper Types	6f348afb-6f1f-428c-a4f9-5f8e2374a075	allowed-protocol-mappers	org.keycloak.services.clientregistration.policy.ClientRegistrationPolicy	6f348afb-6f1f-428c-a4f9-5f8e2374a075	anonymous
c6451db3-895c-4b82-9b16-3923fc8161f4	Allowed Client Scopes	6f348afb-6f1f-428c-a4f9-5f8e2374a075	allowed-client-templates	org.keycloak.services.clientregistration.policy.ClientRegistrationPolicy	6f348afb-6f1f-428c-a4f9-5f8e2374a075	authenticated
4a99f0f3-26a3-4ef1-8dda-9b9c46e9c88d	Full Scope Disabled	6f348afb-6f1f-428c-a4f9-5f8e2374a075	scope	org.keycloak.services.clientregistration.policy.ClientRegistrationPolicy	6f348afb-6f1f-428c-a4f9-5f8e2374a075	anonymous
66c380f0-517a-46fa-b2d5-78191d2f8ead	\N	6f348afb-6f1f-428c-a4f9-5f8e2374a075	declarative-user-profile	org.keycloak.userprofile.UserProfileProvider	6f348afb-6f1f-428c-a4f9-5f8e2374a075	\N
2189659d-5fe5-411f-80ef-64947f7220d1	rsa-generated	6f348afb-6f1f-428c-a4f9-5f8e2374a075	rsa-generated	org.keycloak.keys.KeyProvider	6f348afb-6f1f-428c-a4f9-5f8e2374a075	\N
4ce21678-f937-4f84-a9a0-f6db3719e122	hmac-generated	6f348afb-6f1f-428c-a4f9-5f8e2374a075	hmac-generated	org.keycloak.keys.KeyProvider	6f348afb-6f1f-428c-a4f9-5f8e2374a075	\N
dceadb9f-9f49-4817-a671-5acd962f8edf	rsa-enc-generated	6f348afb-6f1f-428c-a4f9-5f8e2374a075	rsa-enc-generated	org.keycloak.keys.KeyProvider	6f348afb-6f1f-428c-a4f9-5f8e2374a075	\N
22cbb94c-4328-4b8b-be5c-da82b2d221e6	aes-generated	6f348afb-6f1f-428c-a4f9-5f8e2374a075	aes-generated	org.keycloak.keys.KeyProvider	6f348afb-6f1f-428c-a4f9-5f8e2374a075	\N
393a9657-6aa1-4f24-9561-024441cec2aa	hmac-generated-hs512	6f348afb-6f1f-428c-a4f9-5f8e2374a075	hmac-generated	org.keycloak.keys.KeyProvider	6f348afb-6f1f-428c-a4f9-5f8e2374a075	\N
\.


--
-- Data for Name: component_config; Type: TABLE DATA; Schema: public; Owner: keycloak
--

COPY public.component_config (id, component_id, name, value) FROM stdin;
a5d2d3f5-52cd-49be-af8d-e8369b820bab	9cf91845-1790-4deb-8bae-bc01aa3235cf	max-clients	200
1a29c8ed-bcef-4960-b6cd-1bc62ed1e102	2baacfb9-d6d7-49b1-8038-6718327e602e	allowed-protocol-mapper-types	oidc-full-name-mapper
73f05d76-093f-4439-961f-1d3e8897126e	2baacfb9-d6d7-49b1-8038-6718327e602e	allowed-protocol-mapper-types	saml-role-list-mapper
67d33bda-02e0-4270-b4e8-3584838797ee	2baacfb9-d6d7-49b1-8038-6718327e602e	allowed-protocol-mapper-types	oidc-address-mapper
c2d32bce-0a17-4c8a-b17e-514f63246c95	2baacfb9-d6d7-49b1-8038-6718327e602e	allowed-protocol-mapper-types	oidc-usermodel-attribute-mapper
d7c903f2-8534-4741-9afd-327e3bb379ea	2baacfb9-d6d7-49b1-8038-6718327e602e	allowed-protocol-mapper-types	oidc-sha256-pairwise-sub-mapper
5ce6f29b-91b6-4911-9be1-c60dc180ef12	2baacfb9-d6d7-49b1-8038-6718327e602e	allowed-protocol-mapper-types	saml-user-property-mapper
0e281ae3-957b-4df8-8bae-9ca6f01b0aa9	2baacfb9-d6d7-49b1-8038-6718327e602e	allowed-protocol-mapper-types	oidc-usermodel-property-mapper
b83f1afd-f8f4-4e2e-9c84-7ce0f212b1c4	2baacfb9-d6d7-49b1-8038-6718327e602e	allowed-protocol-mapper-types	saml-user-attribute-mapper
826402e0-e944-4566-b0e6-dfdf4e562454	a73f1369-145c-41e8-bb34-10a6a4ac131e	allow-default-scopes	true
b03c329f-5005-40a8-8f0b-772148102ed8	8b67bd1f-ace1-422f-90e9-bd3ff9d7f2c5	client-uris-must-match	true
182c56bf-3bd5-4f6f-b37c-0ccbaddf7fb2	8b67bd1f-ace1-422f-90e9-bd3ff9d7f2c5	host-sending-registration-request-must-match	true
5b110994-c462-4c47-84c0-0a94835f7f5e	e7f03640-a4de-4eba-825e-25521d190996	allow-default-scopes	true
a68e196f-09b5-42f0-a9a8-8a1453ddd295	5ace0c28-41e6-41ed-8b00-62b2e7f4d24b	allowed-protocol-mapper-types	saml-user-property-mapper
179fb087-47bd-44aa-b3c5-d6c2794918b5	5ace0c28-41e6-41ed-8b00-62b2e7f4d24b	allowed-protocol-mapper-types	oidc-sha256-pairwise-sub-mapper
2a600a4c-9527-47fe-ae70-6f5558c4efc0	5ace0c28-41e6-41ed-8b00-62b2e7f4d24b	allowed-protocol-mapper-types	saml-user-attribute-mapper
13182e9d-dfbd-42d4-bddf-369938d63d4e	5ace0c28-41e6-41ed-8b00-62b2e7f4d24b	allowed-protocol-mapper-types	oidc-full-name-mapper
73a2dc0b-ed4e-45cf-89fc-33ad1b0824c4	5ace0c28-41e6-41ed-8b00-62b2e7f4d24b	allowed-protocol-mapper-types	oidc-usermodel-property-mapper
9e0d4089-a869-48dd-9604-5431634d1a51	5ace0c28-41e6-41ed-8b00-62b2e7f4d24b	allowed-protocol-mapper-types	oidc-address-mapper
0667824f-f48a-441f-a582-8092d3c2bfb3	5ace0c28-41e6-41ed-8b00-62b2e7f4d24b	allowed-protocol-mapper-types	saml-role-list-mapper
7442db32-caf9-4f64-89d8-0a4f7b0390e2	5ace0c28-41e6-41ed-8b00-62b2e7f4d24b	allowed-protocol-mapper-types	oidc-usermodel-attribute-mapper
33dae563-c038-4d56-bc5d-d38b8b4db8f4	83b0ab2d-4afe-4044-b38c-dbcb002f5614	priority	100
882f70af-0443-4838-a0b0-3749054755fa	83b0ab2d-4afe-4044-b38c-dbcb002f5614	algorithm	HS512
e78d1202-791e-420e-987c-9cc984906dbc	83b0ab2d-4afe-4044-b38c-dbcb002f5614	kid	65985110-5e0a-4a41-b86c-3fe47c6d36cb
4cfb8d3a-d84a-425c-85c8-d99cd8cdccad	83b0ab2d-4afe-4044-b38c-dbcb002f5614	secret	lLPhdabDtKfFaCd07gHr6JOIs9T4FdgupbHbH9c3HqwN-3p5ILIp17c3nkVFDVx2cuWR15N-LJRM-eqxRlq0HPH-WQNw5MWuqzzUyX5EGICrL3-MQXjnM4Ha6YxohFAzI84buR-jd_Jcw-9U7zEPQYFqarlh0M3xq1bCSC8busk
7db99827-259d-4d3f-a783-6f84b9da76bb	f6c1dada-de5f-46fb-b9ef-0d9f0c0bc061	kid	cc04c1d4-13fd-4e2e-958d-fa807c1a1e17
040a0c90-93e5-4f4f-b63f-a10988b669c1	f6c1dada-de5f-46fb-b9ef-0d9f0c0bc061	priority	100
abb9209c-0444-4b03-b565-a468c67384a4	f6c1dada-de5f-46fb-b9ef-0d9f0c0bc061	secret	rNp1iCrzOvrJqiIJ01r0fw
f3d48488-774f-4ae9-9a16-0969964f5eba	af5e8188-358e-43d1-9a6b-b77f9fd42351	kc.user.profile.config	{"attributes":[{"name":"username","displayName":"${username}","validations":{"length":{"min":3,"max":255},"username-prohibited-characters":{},"up-username-not-idn-homograph":{}},"permissions":{"view":["admin","user"],"edit":["admin","user"]},"multivalued":false},{"name":"email","displayName":"${email}","validations":{"email":{},"length":{"max":255}},"permissions":{"view":["admin","user"],"edit":["admin","user"]},"multivalued":false},{"name":"firstName","displayName":"${firstName}","validations":{"length":{"max":255},"person-name-prohibited-characters":{}},"permissions":{"view":["admin","user"],"edit":["admin","user"]},"multivalued":false},{"name":"lastName","displayName":"${lastName}","validations":{"length":{"max":255},"person-name-prohibited-characters":{}},"permissions":{"view":["admin","user"],"edit":["admin","user"]},"multivalued":false}],"groups":[{"name":"user-metadata","displayHeader":"User metadata","displayDescription":"Attributes, which refer to user metadata"}]}
42e03cdd-c4c5-4b0e-8ef2-a787cbfc8377	f29f8312-3759-418b-8dff-7306215dce6b	privateKey	MIIEogIBAAKCAQEApttAVHCNHS6YXZ97hyYAeviRaDPL+yhQra980P4OfNZx/CExtcUAmP8W+U79PFkDY838OPr1K6ukkqeds9EWX2FU83u3jfu21iTNkhBRRWIuV67V79tO0NfzWgEPfJ1hDw+0BPHT4lYeDT72ZlLaVtpZgtnbx+m48pL+PWANqMiO0qxrrQ/JVxcTn9xrzTYCQ3zviVEkNmeZi3Ru42wA5Ktj1hBSTuqEuMrDNBchyBKj1NM+r89kwn1UpEyONF4UD6XeYa5eLhqXa3G4g2xsPF9lLMxIwF2XHaSJFdMxdq4X+ke5nZGZpRwLGGIdY0HeDsLYSDYfC7duG6rD9aoK1wIDAQABAoIBAAbzVyitT5OJn1s3C4RDtv1oYVY/4h1iPoodp0tlaeEVZcYk89coj6/P4HseKTpcUuHTcNBG0/OvwLlDNjSJXy819L33x1uowqMFAXM2Lsx/HIMWi17kedIFTOPQ6347aBGii9Mw56yj/bh7iPQWO3YmvlfPD3Kyb7vbF7Ai0i7XqpkIzxGyHzIiPzoSkZyJZE3ZugoRL42JGCB45y1Eo3VYPv/7lmAerxYyhOXQmPbR2M+tNxMZjuVty5fP+vl6pPz/6QnvVKUWA6fl6FKaS0NWjaS4RG8iGZYUKsW94NQDmYV07yB/xSGj7bsnbTPAddcVBnMI9u3+u/f24HARflECgYEA5orKnA/oOGgXbkaoiYqtGf1MN4BHsAyyDPIKK2yeoXGneh1NuIFpk+exLUCIanXbT5/o72WZpxjElwgACWqiXsO6d1URkMGbG/HXPaaYYWMaTFp/kKXhFEr/zQAbLK8wULdUrRyHCJA9Nypo5EVbGOdRZe8t8BKMP/sdFgPBlRUCgYEAuUggEQUheyeAjL//No1Ff+HZtT3PWaa91ThbevYpw8mwbDtsq9WoBk1Kzr8XjS2RkrRBorfdaDyxVJ8m741hFGpnveXBgc3Fvg/eWc6EWRb9XMf+N4DWFyef91ucxWYdbGPqLfC8BQpEuWJUtklxl5+UL8Ns5h2VhaVBr4tTszsCgYAKtT+b6BE9LXiJIrcJTGul3WIA4fByeOR8PXHDepQTo5fH0Dyf6ULiH8zW8Txk1XyOQjsrg2iTnk7jRPfbeBx6klTC3iymsJdnwN/ieS5yt4utKDbsnQfLTYB8IRkiBjEUTq+cKssK1shBG7Mrhx0oFvZs6aMUl4f0INHFB/+h0QKBgAHS0OX5+/NfVyeLeDKMP2Pb0C21dwX12yZvEI9sPsr7gC4Ag7hJOQce2Z6hSNUN3sHn3kGAt8Af4MrpahOve4Yc6fp3eWkSomCVfWW635iU3ld8bGcVcIX30N45W5ihwaZgcVyUYvVVvYlpi1Xj8SdB3c5+iOLW5bLUBop4v5EjAoGAYYyjAYUnMsKEiyLFHWcW0N/T9kDJKOlm+c3mTfoaRuCxCY1oavMatwlvq/c53lW3t3W3RZ0iat117Z5rsMN68llNrLbg4ClvE8+Su0j3KQGbIPb+tNKF8hOMcFo281927XP4CPFh9fXIJARBYFzA06ugKnOunx4PXIZV4P+bf+A=
7e3f8815-5feb-4eb6-ab69-b5bcfe91dfc8	f29f8312-3759-418b-8dff-7306215dce6b	priority	100
194951f7-80d7-4c37-b103-201e7fff15de	f29f8312-3759-418b-8dff-7306215dce6b	keyUse	SIG
259cb1ec-c376-4e3b-a8ba-f266fec8051c	f29f8312-3759-418b-8dff-7306215dce6b	certificate	MIICmzCCAYMCBgGeTAHCaTANBgkqhkiG9w0BAQsFADARMQ8wDQYDVQQDDAZtYXN0ZXIwHhcNMjYwNTIxMTkyNTQ0WhcNMzYwNTIxMTkyNzI0WjARMQ8wDQYDVQQDDAZtYXN0ZXIwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCm20BUcI0dLphdn3uHJgB6+JFoM8v7KFCtr3zQ/g581nH8ITG1xQCY/xb5Tv08WQNjzfw4+vUrq6SSp52z0RZfYVTze7eN+7bWJM2SEFFFYi5XrtXv207Q1/NaAQ98nWEPD7QE8dPiVh4NPvZmUtpW2lmC2dvH6bjykv49YA2oyI7SrGutD8lXFxOf3GvNNgJDfO+JUSQ2Z5mLdG7jbADkq2PWEFJO6oS4ysM0FyHIEqPU0z6vz2TCfVSkTI40XhQPpd5hrl4uGpdrcbiDbGw8X2UszEjAXZcdpIkV0zF2rhf6R7mdkZmlHAsYYh1jQd4OwthINh8Lt24bqsP1qgrXAgMBAAEwDQYJKoZIhvcNAQELBQADggEBAHispJfTonxYoQ61eCrk7GCHvQCEvb/nE9c6//EVAPYqu3Lm/GLMM9QFVWbZ0wuntycnorreLDtArpXxYL6A0k78on7DvS4wJBBlA5VcoLzniJFtUydNKLZFerlU0FjrFUnw59LM+tXKqKlrvM9WokCLqlHypGc6EHMU5ir9ae3mJTMA35RQOxWj4vzdgX0Xi2TJOaDCErevJ9CFw5uWqHL5LC3AIv0vV68i2J8UTIOBFNzU+NXy5y5Pefve9UkkmfjtZRcL4gVbEY4UCyhnKFW84DfJc+jVG65nUSjqZP3spznosThxsxAy1pMlj36hk/zR/wr8uYMJ93hpHvpeH3k=
618e2347-108b-4efd-8299-406a7e643248	994c0f5a-f8e0-460f-9d89-d860cc9c633d	priority	100
e813d39e-9357-4db1-a749-cb514ea170ee	994c0f5a-f8e0-460f-9d89-d860cc9c633d	algorithm	RSA-OAEP
0847c8b9-f328-469a-af91-b5b53844871b	994c0f5a-f8e0-460f-9d89-d860cc9c633d	certificate	MIICmzCCAYMCBgGeTAHC+DANBgkqhkiG9w0BAQsFADARMQ8wDQYDVQQDDAZtYXN0ZXIwHhcNMjYwNTIxMTkyNTQ0WhcNMzYwNTIxMTkyNzI0WjARMQ8wDQYDVQQDDAZtYXN0ZXIwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC/TNgIwS8Co9u0Lv0Px0Bn+59ua5NYHd5FKSasVwv1JVzOCu01UAj9E8ETkMAZQ+aV4Py2KNtkFdWF9sIfgw0qZ93v5bCz9CeIvVSgqCTdvBUHCi5uxPskN/VyZLtwYwasa8d3U8NrOH80pkC8+k6GO5Ah/X1YaJcmZBADPiVJJ0JxkA9lnRBwdmliKTWV3AqLCc6wt/im2AHfw/1o9/fQHUKa7ng+iTlnXDF16h5pCUPDwSwCZI0nKpWxYdlra4SQYSrdjtt33P2dPi5KRgraxZZIuhWwPfEs1hkgMNrH6wt3BKJvf7R1EL5TwpsLe/k1QGE7YaXsFKfkBdMSBf+nAgMBAAEwDQYJKoZIhvcNAQELBQADggEBAECOA4KpyUi997gtt2zCTxop3rYc5yQm5026557teC22xNaIxuhStMCrBQW4ngJX8dFIsGdWY2kDTLHYJji4KkghU2R3oNKJpIRu7uhXCbhDuEfHDUid9/wmfUwYklVqYA212UwTvK0cbGUJRW4qITpMF/N2mYkpA3F8yY7v8ZqtmYpJWQU+TDwoxGfy08L9q6ySu1+YH68OWkcgbFB51WEV4GyXI+YxokBqWozry8k8BqZuOs0kbiGykpdQHX/lCKtWV3N+Eg5L2SCIWH1dyz2iW8qlwCF1W5oqbi4CzmMG+AsbR5JybGCWhTsThEyvYelnd3me+cMZom593opGtKs=
f1b5814d-5667-4219-8ed5-8a753c3dfbf4	994c0f5a-f8e0-460f-9d89-d860cc9c633d	keyUse	ENC
87634039-ee5e-4196-b6df-77821236fc74	994c0f5a-f8e0-460f-9d89-d860cc9c633d	privateKey	MIIEowIBAAKCAQEAv0zYCMEvAqPbtC79D8dAZ/ufbmuTWB3eRSkmrFcL9SVczgrtNVAI/RPBE5DAGUPmleD8tijbZBXVhfbCH4MNKmfd7+Wws/QniL1UoKgk3bwVBwoubsT7JDf1cmS7cGMGrGvHd1PDazh/NKZAvPpOhjuQIf19WGiXJmQQAz4lSSdCcZAPZZ0QcHZpYik1ldwKiwnOsLf4ptgB38P9aPf30B1Cmu54Pok5Z1wxdeoeaQlDw8EsAmSNJyqVsWHZa2uEkGEq3Y7bd9z9nT4uSkYK2sWWSLoVsD3xLNYZIDDax+sLdwSib3+0dRC+U8KbC3v5NUBhO2Gl7BSn5AXTEgX/pwIDAQABAoIBABC5xUGusk+GyBTO7u1MPINa6qua2D0iD2b4nBsBWVhLtfuF1QuOPdryuTTeuQz8dNKx4yaCF/x+NDcMRhi/Oo10m2D4MiTpufMoqpeJW//PC/+bkke5DUQzaFBiIklHPzQgEEaMmk9rlyOhTZO4RtlRp95w7V6ndl+y6/t8mYH1t9eTbsPPrrNd/w7kPUEYkzCJgzjRg4gUqtUHvNnlvXg8Dprh8uXw9ugaDxEQ9mxi0pD/My5FfEAl4b1xBMfgNHjGRMfBs/2qjjgERrMtFPsq3X2HcxN6qKzeXwosFi2lHP0dp1wtchXyfhm6zHQ6cDLYWdQKQSL0/ykumGAS4GECgYEA91YC+9NKEJmPBKFvNQcA//zOt7jVwFvo0f0ATnJ8WQ4C2FJ8SV9XgoaRSWahqQFoqX6YG6rpqIC79Ekt+iA59uaCBmP2JmXp+dwUBQmE6sTvok8Ssj6M/jCOv4YyqzIO6cV2T4g+FWssnIdO9LQQ5m6F9dk9fSN3bR5Zat+JPKkCgYEAxgBUlt3l3/uCC/v/9caezb64BIvpLIQct4oCmBq7+8bzD9CCAjMan4JNT7/vZSviDoc0IsW2pdm3MPCzunCWxreZYG46F6fzYJFtabOsejuM1POgCMwhK9X9AudSyemG8tyYlAzWpwSuyQ9WgxcLFnjJZqFPn016YEsAPblbO88CgYB4+LKg5KjXEaQnyaWQtApDKi0ZIug5Gzr2ad4agFhdXkL59u4fHOi6SIMK+Y2cEbpVHDvdXGzII57KTniUW+q93eQ+p+mewj38HS4VgKBoC0aBhldIottm/+zxs/tYTDWLFS9WmvZyl2bMcEmn2eJiMjCHHGe8qvogfrWRVh/TcQKBgF6FjdwvtiuE74I1HO4BkZH6t/JDsF61+teLpM1kBdWeFi64hTfzmYQIOkwV/ny3xETXOoZXCGiIVLGiVspsMS5QO4ITXNwqKz8wbaEGSxJXF1YZr45DlJpOn2ghch49w1RxBs22i0pUK/SDw/L0rzBdHRhHbbFI1WDerRDKScl1AoGBAKw0E/H0xJYCJk+n4imL/IfPbFq3MKJEy3yL0v9ek6uCQb/YzJh7EmNjCd6Ri7/MaMSOjZysdXqKK9nMuWBNtxCqlmm0VO1TKytuV3hXf80xez2at120Cu3kyvV2Er9hRZGN/uQpvrW7TIM5Dg2uCEsiqOZ/j/MbTYvGfqn47TOm
e0755c86-7cfe-440d-a43d-6363a248f802	785f873e-bf19-4386-a4b8-8c3a901a6580	host-sending-registration-request-must-match	true
6fb56c50-b100-4a69-b91d-d6d6c12d4530	785f873e-bf19-4386-a4b8-8c3a901a6580	client-uris-must-match	true
cc0f8d16-e420-4762-93f8-8953dc0a075c	3a90975c-27da-4807-9918-85c4d170880c	max-clients	200
31540a8e-3a0a-46c3-ac59-a11ed2d48e86	45df67e2-101f-471b-aa00-dbf11bd13bf6	allowed-protocol-mapper-types	oidc-address-mapper
82297dd3-9f9f-4f55-b31f-66ee3a22f1e8	45df67e2-101f-471b-aa00-dbf11bd13bf6	allowed-protocol-mapper-types	oidc-usermodel-attribute-mapper
446350fa-017b-4f9e-98fd-5329203f4d71	45df67e2-101f-471b-aa00-dbf11bd13bf6	allowed-protocol-mapper-types	oidc-usermodel-property-mapper
abfd5326-27e2-44a3-8022-6ad60549a857	45df67e2-101f-471b-aa00-dbf11bd13bf6	allowed-protocol-mapper-types	saml-user-attribute-mapper
d46652b2-c341-4d8e-80d3-e084f93a058e	45df67e2-101f-471b-aa00-dbf11bd13bf6	allowed-protocol-mapper-types	oidc-sha256-pairwise-sub-mapper
080ba503-0ebb-456d-8401-2ce5705c1ec2	45df67e2-101f-471b-aa00-dbf11bd13bf6	allowed-protocol-mapper-types	saml-role-list-mapper
604394e7-b803-46a3-b379-ceeb90cafa7c	45df67e2-101f-471b-aa00-dbf11bd13bf6	allowed-protocol-mapper-types	saml-user-property-mapper
9b06358d-a978-47db-aeae-32585f341f34	45df67e2-101f-471b-aa00-dbf11bd13bf6	allowed-protocol-mapper-types	oidc-full-name-mapper
2ce8cd7f-0e0b-477c-878a-2b08195a9333	d4ec2bdf-67fe-4c7a-bd62-d6cbe89046d5	allow-default-scopes	true
bdee1bba-571d-47e5-839e-0762de9381ee	895416e8-a54b-4695-9a2f-422c00e70466	allowed-protocol-mapper-types	saml-user-property-mapper
27d5353e-23a1-425d-bd1a-217d8fca2d11	895416e8-a54b-4695-9a2f-422c00e70466	allowed-protocol-mapper-types	saml-user-attribute-mapper
f051257d-6941-4a4d-a302-f1cdf1c11b9b	895416e8-a54b-4695-9a2f-422c00e70466	allowed-protocol-mapper-types	oidc-address-mapper
e750c9fd-8dd5-4eaf-9afe-c8afee701823	895416e8-a54b-4695-9a2f-422c00e70466	allowed-protocol-mapper-types	oidc-full-name-mapper
11d63aad-58e9-43c3-b204-74ad175e95ab	895416e8-a54b-4695-9a2f-422c00e70466	allowed-protocol-mapper-types	saml-role-list-mapper
8a9692f0-27ec-4af8-b87f-4650dba43432	895416e8-a54b-4695-9a2f-422c00e70466	allowed-protocol-mapper-types	oidc-usermodel-property-mapper
35b0aaf4-2353-4230-931e-ae8701fcc17a	895416e8-a54b-4695-9a2f-422c00e70466	allowed-protocol-mapper-types	oidc-sha256-pairwise-sub-mapper
93e13eff-2593-4300-9bc0-dbeac181350e	895416e8-a54b-4695-9a2f-422c00e70466	allowed-protocol-mapper-types	oidc-usermodel-attribute-mapper
ee711f0b-574c-4d77-8385-2b01f4f44e8c	2189659d-5fe5-411f-80ef-64947f7220d1	certificate	MIIClzCCAX8CBgGMHVjjUjANBgkqhkiG9w0BAQsFADAPMQ0wCwYDVQQDDARja2FuMB4XDTIzMTEyOTIzMDgzM1oXDTMzMTEyOTIzMTAxM1owDzENMAsGA1UEAwwEY2thbjCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMURH583sY9NVU81ozXOE592Ksb6YU1m2dZ34k15Ck/gJy2pzBYs+G5i2sNsxL8fK5LYr1uvOo3eVehmi0ClejdXVQAoq82dzZY2xTcQCF7PoQnvR/dnWR0mMgWBoJzPwj57rMaVRN2qPcZDMU8Egp2662xftLcOekHQqWI8DDWCqvi8eKb7oPscRQu58Q0d+u0Pb5ECYaxwaCkc/+L2yuKhAcetx92WgeCDMcpFF1iteVIrDJ4Z20RRWDdoOJfiv85oSlGcq/7m8g2HI5r55AUxtSxMKbf7hbOX2nttz0qzVJZ5E15jwet9yxMRlwbMgctzWeAIC8p0ClbmT3FFR+sCAwEAATANBgkqhkiG9w0BAQsFAAOCAQEAjykLIjiCFjHmJCj60rC2CBq5MFf7knJuCIZKOMUU2e1zZI1kkI4IZ7yQT9iHURU2bZngvKd8EKwoPw1MDlNgGVDA/UvjOgCOXKOKkd9VuEMk7pGbjURBbRiPmJqv2mKs16/7Jzt3n/xBF513H35AO54JwoMg0gFjG40HnMz7OhIxnUgCls0Slk0BE7hGpVwXs9Iw7tPDrTnVSkObwpdlgQVaqI2igylPYsE6C7piMNEkmaPGwrLNsq9kVzph+Rj9C5/7HyK6N3M397JDTp9F1wpDWMB/ZQrwQ5EHUJxaBbkoQ6IbdFwBlVtz2CzhllpPsnIF3Pn7RGfrQXp0B9zjCg==
94236131-31fb-41ad-8661-6a6bf82b9302	2189659d-5fe5-411f-80ef-64947f7220d1	privateKey	MIIEogIBAAKCAQEAxREfnzexj01VTzWjNc4Tn3YqxvphTWbZ1nfiTXkKT+AnLanMFiz4bmLaw2zEvx8rktivW686jd5V6GaLQKV6N1dVACirzZ3NljbFNxAIXs+hCe9H92dZHSYyBYGgnM/CPnusxpVE3ao9xkMxTwSCnbrrbF+0tw56QdCpYjwMNYKq+Lx4pvug+xxFC7nxDR367Q9vkQJhrHBoKRz/4vbK4qEBx63H3ZaB4IMxykUXWK15UisMnhnbRFFYN2g4l+K/zmhKUZyr/ubyDYcjmvnkBTG1LEwpt/uFs5fae23PSrNUlnkTXmPB633LExGXBsyBy3NZ4AgLynQKVuZPcUVH6wIDAQABAoIBADWELG+7GqudZzTvDocOkzKjTwOhPCpea3r8LIc4fy3o5ArZCTTeeorTqrAWiimS5+zljl2aLQ8Y2YCW1Gs2ZQXBYDJ+WQWqPIn2DsGgx30j6oo9onAT71XkqQHozXq4SvpX8LgvEjgWQtdkKPBZ+7Sk7ckNBpENy/KynUUxpGklPAv5m5fkXkiiCl/64n9Ar24xL7mRbQxHzvD5MdWqcCvWx6dtMmYo3Q0b6KeM9CjcBKhKiJfJZ2/besbTFJYzIBjt5zTEfInHbWthoqqy6JGnh8DHJ64yp1/t49a3qIwHBxDQkRp81OLiRYTEMYyDDdkfYl57He9+DalBIuAbHnUCgYEA9rc6GQwWPZTHdu31FXu4JSDTUQ0uIX9zcKvxHDp3a8dEhTjm1Zu/l+T/IxVexZqElaMh9fzUWsw2SOdDZEd+vMgU0gJtGgPIl+iYX8qvM4y8TrnIQTuSFeW2hKazycyOWJA8KwN3196bjyQEIBts2c+A5ZjO2xUWfNZLd/LiSq8CgYEAzHuY1UnBl0/NGyDOtgm7aQ5ip74EgBLpdXQBwQX/QVPy5LWoyu0T6BAHL4902t5bGL30yXgnnaLguwhXPVBCFwg5iJjHbOUiD3NgETse9xaNW68COONAwfNGYRtEGr4UmYZTbylga2ysB30xUcUJ6GEFObrbXx3ztJ9eN+Y19YUCgYBm1ebEi/I1Ru+BVhxjEQenijAqx5ij49EFdNXyUzh110BrW1V0UhAhSxVB1WWEbiy3hqDgPLtzAU3bQ3ImuVpNbASpqNM7Fbql/xCMVRqEHTRciDm9Xww8TlyunCGyiq4GolBCCZcJhsNGfdeuXmAXxdNPYEtQrFCMRnJ8k+PZBwKBgEKSGneVw4jXWhby31k0YecZ39RscFqhzY+HbOrCYQ+LnRAIdCNce5aZYT2CnrCCo3WyofbVP1B6rl81n/E+J8YHz3NBCevRzPzquuPhM3uNxAeNOlP66CI8aTVEAzARofM5YABYoCNZBciKYXwVgdw9ec4Jn1GgFq8/ExVvxTFhAoGAcu6HCooz9XyMAuUb0V+1WxiAqv20dU+lLsQUcYMRq/Xtkc/veEKixzqUSCy1WQtTWcJvRQDuGAMbvztUOqeg3IQNQ/omANXOAnrH/xqVTW5iJsrs4s+EIKIg0/AMTu31Wl7EvovujZK28eDbhn/UXkWzZ8m6XeX4w5gPOgimgrQ=
eb1e9e7e-96de-450c-a5d0-342608b1f146	2189659d-5fe5-411f-80ef-64947f7220d1	priority	100
568a5c30-743f-4834-b1f2-ff10ca443d51	4ce21678-f937-4f84-a9a0-f6db3719e122	algorithm	HS256
12a3fcbb-e24f-4cec-bf1b-a8104793b11b	4ce21678-f937-4f84-a9a0-f6db3719e122	kid	8ff3f9b8-43cf-4fa8-a23e-a2c0b571023a
1933c655-c064-425a-b3c3-392e3788b0ec	4ce21678-f937-4f84-a9a0-f6db3719e122	secret	Q-quxNo6VpCD21lFiz6DTtKku1Zfs8IqrJj6fSvbaVXLk4V8pV4OloS359ntndsv8CN4_zrf4SmbtYab5eR6hw
2ded2932-1040-426f-8e41-2a62292e864e	4ce21678-f937-4f84-a9a0-f6db3719e122	secretSize	64
21189af1-5530-447e-b587-116926868c0e	4ce21678-f937-4f84-a9a0-f6db3719e122	priority	100
cc9ef345-5bcf-4252-b241-98298fca6c0f	dceadb9f-9f49-4817-a671-5acd962f8edf	priority	100
a29165a7-d6f1-4554-a0e7-26a5a1826819	dceadb9f-9f49-4817-a671-5acd962f8edf	certificate	MIIClzCCAX8CBgGMHVjkPTANBgkqhkiG9w0BAQsFADAPMQ0wCwYDVQQDDARja2FuMB4XDTIzMTEyOTIzMDgzNFoXDTMzMTEyOTIzMTAxNFowDzENMAsGA1UEAwwEY2thbjCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAK/YuafeRxwCIA9MnzX/GfH9Js073yX2tz6FjoZSTsFxpjHHKZLqBv6pQljMgDHhR/lArq6IqX1VTZq1c76Ez/acukw3JaFCW1FKof6QJ2qsUm8l3hqBICyQ5D20GM2ZKddKSY2Ux2Fl5HibCx5a8k7YMZZPSCT+mOfagWJvsqGqp9k1Za7vKKpvB0W+8MzRV+hQnBuSVujVfx0uMT9DSBoLIuyhT8LYblFt8ys+QKmr/GK+I0hyiQBHq2LwF61xwOXo/hQYR/3S2KE5qMT+PN0rNiykg9AZhX7QWHc62dKXA67mnTOR+T0utw1a2uTT3T/ppTtj4gwFLJ+J5wiib4ECAwEAATANBgkqhkiG9w0BAQsFAAOCAQEAc494XGxjSw8yRicpnk00jIdbZ3SgeJadkXhAm13yeX+YYgUgk08MDIr4laPY4I6zBb/L3bz6j132TUBYDXriJ1EokHp6kOM2bN9UDMFQEmsaMs2wcFPDNu8p/fbMoljeGF3D5YiQPJUlBb1AX/3HWK6qFIJlQRdppUneJ2ANM2vBRN5mjX0Ss2dG0dXaM9NrTK5EmGc4io9yevWagK6/BNSgKVzZN6Sr0Yi5DX/NW8V43aGfUAxRZdLgTpbM1i/TKZGxYsL3KPquIYRn+SB9+U0uX7D6+5hKq5CJG4HAdawCtHqMGwLKlBkv2+Wj//zpM0LHv2vrmObUl3nJfDCU7A==
469ba87e-f04a-46a9-866d-d7a6111a0574	dceadb9f-9f49-4817-a671-5acd962f8edf	algorithm	RSA-OAEP
1e295222-0f11-4adb-81a1-97c91e5f6245	dceadb9f-9f49-4817-a671-5acd962f8edf	privateKey	MIIEpAIBAAKCAQEAr9i5p95HHAIgD0yfNf8Z8f0mzTvfJfa3PoWOhlJOwXGmMccpkuoG/qlCWMyAMeFH+UCuroipfVVNmrVzvoTP9py6TDcloUJbUUqh/pAnaqxSbyXeGoEgLJDkPbQYzZkp10pJjZTHYWXkeJsLHlryTtgxlk9IJP6Y59qBYm+yoaqn2TVlru8oqm8HRb7wzNFX6FCcG5JW6NV/HS4xP0NIGgsi7KFPwthuUW3zKz5Aqav8Yr4jSHKJAEerYvAXrXHA5ej+FBhH/dLYoTmoxP483Ss2LKSD0BmFftBYdzrZ0pcDruadM5H5PS63DVra5NPdP+mlO2PiDAUsn4nnCKJvgQIDAQABAoIBACdiLMKSH+7/8to6WPYo+lCeWBBjNmk0Rno0Q2WGDal5oLVJW+BRldt3YSquMo/5WrtSZ00jwoIVltnthczHxiP/miHzv/PL/tPIGVwAQTO9AIFwQ7w/60rP8K55JYz2ns5fDvYsujLwNSll4CmeSOKrvP9jJk9SzkAvSgcX6TQXuwn2nLTFmahRyTDT2RhfSVcOejbZSFN8CzuWCQISn178Z1m22YavZVob/uFUg8QC1vWCt5oftOZ91744GMia66wJSC7BHrXwVSH0I5vl9n24T4ZwQhOtbXSWd1AS2jljZjj9dLK7cibrW6xtp4Fzco+llKNZIMOsjyXhqpXUgSECgYEA69GIFVzlRdvi8npFYcvTGYmNl503tf1jxNrSv2KQzUwuSt3/P4T8Iboinp3ZfB8Q6NkMvgwyWC2d9oENND9wOQ2LSU3bZBHVgV1nxQd1c+qqZiLbuR8TPc2S/EKQ0qk/TGfGyNkmjhGtVo6xxq/sfswmnOfuE8s/JkB7sTCoYN0CgYEAvuVKD/lCG8VQKYn7oqxuo46ofCarSl0eYbMtxhDRSlMmt+28V8sDMS6owyP0mkFOzprKdNAg0FXgZc2xO88NoUHwCGvM9n7cLyU9rtu/7UPehOyFonk4xQYKHrvmOraNVii/YsYQOKd8K02gvkXOFEYQU4zzNHqD6K3OH6ra7PUCgYBYjYxOiV3HR/UHHQck3EdfVZoIDw+2lXp7l7iACeFaVnsjvg11qtiLSbxqV9gtlfThm2//hdD579dbk8aDkjbwFbfyRPxXraLBO3QWNuDSMJLgW8Kq15KAKMxDUjPUB54vcODi1zh1LQoscNUtSS7DxqHRVf6/DBmgoaJRPXZdOQKBgQCy+rvT+jnXW8prB+ocfVtGkky6Cm9zS5detuZl3AK+kvOsY4PBNKCLjlnAjIeb0TuYTl0f5Lu/WaUJDi/sCZeX6ACrhJcpTYwXz+zjczmhtY5+RlyNFub5I059vmKADgS6EX5Pl7BBzhaHa0MY4s3zCDXqgC7Ot0fR8pNd8Y1NuQKBgQCGWCRQ+Rw5eYd8YmCsaRnTVfNI2clMXKx6/dLx8fjppoDaF0+37+iieMfbxDyNAgDR16ed/VxWA6b/JC1cjRgFtpGl7ZIVX2upudrBp/Mu/CBbTv6UZF3KuyidAXpt0OnJeZo/E7/oFO6DwqmnW/7VPNx9yoHuuno43bVPSiGtjg==
76042a54-dcaf-48d7-bb9a-b69910c688d1	22cbb94c-4328-4b8b-be5c-da82b2d221e6	kid	734358e6-0b32-4ead-ab4c-3c5db4e9626d
5339ee97-c75b-46b3-9c25-d4f22379f748	22cbb94c-4328-4b8b-be5c-da82b2d221e6	secret	2H-mDD3LuqVZYS1tp76EOA
1ee0efdf-ad14-441a-8441-2e3fd92e6662	22cbb94c-4328-4b8b-be5c-da82b2d221e6	priority	100
cebcf9a4-f7be-45c0-9f57-253008fbe6fd	c6451db3-895c-4b82-9b16-3923fc8161f4	allow-default-scopes	true
1f4b8b04-e842-4707-91af-68cfaeb085d5	393a9657-6aa1-4f24-9561-024441cec2aa	kid	51522b86-2e61-4bd0-bae9-d444537623a5
eecfb0d3-9583-4c96-832b-3666cafee9ab	393a9657-6aa1-4f24-9561-024441cec2aa	priority	100
28c8221e-88fd-4002-88ac-cf51c8eb369b	393a9657-6aa1-4f24-9561-024441cec2aa	algorithm	HS512
4cc1f3a7-6335-4be0-aea2-a2f83cc8d645	393a9657-6aa1-4f24-9561-024441cec2aa	secret	T_dR5kklB4FSrWb5cqgBfzMFtBvc6qnBS_1hgZhbiK0NYEIxgQJVx3mm9HmzFSbMmQK99kSWbVoVOdMjanDfvxcah0nB1vn6cyCar6PV7ZVUwL0nGnjn8WM94YhWK1g6wNTNU7GJzuf5i9juKiBPKpLQYwu3tRBuXBNSOc4yIT8
19f1e892-01df-49da-8fe8-04950c325302	66c380f0-517a-46fa-b2d5-78191d2f8ead	kc.user.profile.config	{"attributes":[{"name":"username","displayName":"${username}","validations":{"length":{"min":3,"max":255},"username-prohibited-characters":{},"up-username-not-idn-homograph":{}},"permissions":{"view":["admin","user"],"edit":["admin","user"]},"multivalued":false},{"name":"email","displayName":"${email}","validations":{"email":{},"length":{"max":255}},"required":{"roles":["user"]},"permissions":{"view":["admin","user"],"edit":["admin","user"]},"multivalued":false},{"name":"firstName","displayName":"${firstName}","validations":{"length":{"max":255},"person-name-prohibited-characters":{}},"required":{"roles":["user"]},"permissions":{"view":["admin","user"],"edit":["admin","user"]},"multivalued":false},{"name":"lastName","displayName":"${lastName}","validations":{"length":{"max":255},"person-name-prohibited-characters":{}},"required":{"roles":["user"]},"permissions":{"view":["admin","user"],"edit":["admin","user"]},"multivalued":false}],"groups":[{"name":"user-metadata","displayHeader":"User metadata","displayDescription":"Attributes, which refer to user metadata"}],"unmanagedAttributePolicy":"ENABLED"}
\.


--
-- Data for Name: composite_role; Type: TABLE DATA; Schema: public; Owner: keycloak
--

COPY public.composite_role (composite, child_role) FROM stdin;
9ec7cdc9-cf2b-4d40-93dc-f89ed5c8a0f2	627d0135-adbd-49f5-97a5-3c4c5bd2f6cc
9ec7cdc9-cf2b-4d40-93dc-f89ed5c8a0f2	363ad2a8-5d38-4282-9d49-19598d47b3ce
9ec7cdc9-cf2b-4d40-93dc-f89ed5c8a0f2	e020d0c6-0787-442a-92e0-dcee50f7d1bb
9ec7cdc9-cf2b-4d40-93dc-f89ed5c8a0f2	59bdc687-35d3-44ed-849c-99c5565fa832
9ec7cdc9-cf2b-4d40-93dc-f89ed5c8a0f2	9c74ef5e-a565-4db3-8018-bdb3ae337878
9ec7cdc9-cf2b-4d40-93dc-f89ed5c8a0f2	22cf7b9b-ecf8-4a6b-940d-6e4e11e761b2
9ec7cdc9-cf2b-4d40-93dc-f89ed5c8a0f2	6e573cda-1c0e-4233-bdfa-db532f4b2e78
9ec7cdc9-cf2b-4d40-93dc-f89ed5c8a0f2	f209b1d7-2985-4e5a-a136-45998bb0a47c
9ec7cdc9-cf2b-4d40-93dc-f89ed5c8a0f2	c2c890f0-ae59-4b91-a392-6539dd867e22
9ec7cdc9-cf2b-4d40-93dc-f89ed5c8a0f2	cce7b2f5-7ae7-4bd0-a165-be70f177f598
9ec7cdc9-cf2b-4d40-93dc-f89ed5c8a0f2	2b8d745c-1800-4a8c-af99-ba9ac7c2352b
9ec7cdc9-cf2b-4d40-93dc-f89ed5c8a0f2	c45c9ec6-fcb9-489c-91e2-e0cbc9a34eaf
9ec7cdc9-cf2b-4d40-93dc-f89ed5c8a0f2	7ac34dd7-4e4b-4ad4-a1f8-777a697c21e5
9ec7cdc9-cf2b-4d40-93dc-f89ed5c8a0f2	c85932ab-602a-4992-9fde-cfa0894c5ed4
9ec7cdc9-cf2b-4d40-93dc-f89ed5c8a0f2	d7e46f98-ec59-4acd-9c52-46701c5df625
9ec7cdc9-cf2b-4d40-93dc-f89ed5c8a0f2	5a6efb0d-52b9-4660-93b7-76b64d5207cf
9ec7cdc9-cf2b-4d40-93dc-f89ed5c8a0f2	cb33c936-538e-4337-955a-bf678d83474b
9ec7cdc9-cf2b-4d40-93dc-f89ed5c8a0f2	532678c4-3481-4e05-af7d-13ed0d006686
9c74ef5e-a565-4db3-8018-bdb3ae337878	5a6efb0d-52b9-4660-93b7-76b64d5207cf
59bdc687-35d3-44ed-849c-99c5565fa832	d7e46f98-ec59-4acd-9c52-46701c5df625
59bdc687-35d3-44ed-849c-99c5565fa832	532678c4-3481-4e05-af7d-13ed0d006686
b3054bb8-c40e-4a91-a086-c364629ce753	4cbf279b-4ef4-47e7-acb7-02f05e32ed03
b3054bb8-c40e-4a91-a086-c364629ce753	60193ccb-5aaf-4faa-a96f-0230790d6f02
60193ccb-5aaf-4faa-a96f-0230790d6f02	526756d1-34f4-43a9-a640-3b79037e9e51
de4474d3-ee9a-47d7-b9a3-3ec5361bcccf	b4595704-0b60-43db-ba3c-d193af3b77b5
9ec7cdc9-cf2b-4d40-93dc-f89ed5c8a0f2	d76c11c9-077f-47e8-bd55-10e6418fdee8
b3054bb8-c40e-4a91-a086-c364629ce753	f9a0073f-89ef-423a-a038-d800c88c050f
b3054bb8-c40e-4a91-a086-c364629ce753	b654bacc-6b9f-411b-a89c-bb2b3be56d23
9ec7cdc9-cf2b-4d40-93dc-f89ed5c8a0f2	04f017d2-4f74-4b3d-96ee-2dcd863f616c
9ec7cdc9-cf2b-4d40-93dc-f89ed5c8a0f2	4cc75219-d276-4a8d-85b8-58e7ed57b701
9ec7cdc9-cf2b-4d40-93dc-f89ed5c8a0f2	af74d514-f774-4e52-92f9-d4aae1d7c95b
9ec7cdc9-cf2b-4d40-93dc-f89ed5c8a0f2	05df4622-81a9-42da-82fc-92d66938b618
9ec7cdc9-cf2b-4d40-93dc-f89ed5c8a0f2	1de32797-f085-472c-bb69-c2a1d3304e91
9ec7cdc9-cf2b-4d40-93dc-f89ed5c8a0f2	ebbb3a23-11f8-46e5-8bc9-d26e2e6ce33b
9ec7cdc9-cf2b-4d40-93dc-f89ed5c8a0f2	1cdf82a6-08f4-43c9-ae5d-1fb8a34464eb
9ec7cdc9-cf2b-4d40-93dc-f89ed5c8a0f2	a9fd9060-2531-45cd-b4de-33df64b73eb9
9ec7cdc9-cf2b-4d40-93dc-f89ed5c8a0f2	ea1e1e53-0570-4566-b3b3-8c165a0b97d3
9ec7cdc9-cf2b-4d40-93dc-f89ed5c8a0f2	275bf0fa-d9fe-4ee3-b686-155924ddfb12
9ec7cdc9-cf2b-4d40-93dc-f89ed5c8a0f2	85a8d42f-ec02-4194-918a-f7eea8d55997
9ec7cdc9-cf2b-4d40-93dc-f89ed5c8a0f2	d5d9adbf-b9ea-4aee-be3d-5797d2fe1557
9ec7cdc9-cf2b-4d40-93dc-f89ed5c8a0f2	a50956a8-e469-4e93-bf2e-460996cc411b
9ec7cdc9-cf2b-4d40-93dc-f89ed5c8a0f2	9f591e8d-22db-486a-910f-257effd9f0fd
9ec7cdc9-cf2b-4d40-93dc-f89ed5c8a0f2	5d4ba0d7-6685-436c-87bc-07511c4a657e
9ec7cdc9-cf2b-4d40-93dc-f89ed5c8a0f2	0903100d-742e-4f97-ba61-6dfc00b8cc8b
9ec7cdc9-cf2b-4d40-93dc-f89ed5c8a0f2	fccb989f-b8c9-4886-bd86-69552b08dfbf
05df4622-81a9-42da-82fc-92d66938b618	5d4ba0d7-6685-436c-87bc-07511c4a657e
af74d514-f774-4e52-92f9-d4aae1d7c95b	9f591e8d-22db-486a-910f-257effd9f0fd
af74d514-f774-4e52-92f9-d4aae1d7c95b	fccb989f-b8c9-4886-bd86-69552b08dfbf
93059c31-b7bc-4d3d-bc95-dc94a5ebb7ad	20d863dd-6c6a-4357-bea7-50ca195e9032
93059c31-b7bc-4d3d-bc95-dc94a5ebb7ad	cd273c77-3c3e-4673-bd40-1cf5b82e1c20
93059c31-b7bc-4d3d-bc95-dc94a5ebb7ad	112b6f3b-3904-421f-abf0-dda37752c236
93059c31-b7bc-4d3d-bc95-dc94a5ebb7ad	39e06706-101b-42b6-adee-f5235743eda8
a61f4d23-5fd7-466d-8654-c515c4044f2a	08a5cb36-e078-404f-8ec8-adca98518bf2
a61f4d23-5fd7-466d-8654-c515c4044f2a	6e0c16e4-1848-4675-8cfd-9029b941e703
f9c888a1-2470-45e7-b2f9-b80fa4b1c30a	a2eba2cb-9d42-420b-a728-3ce37166d521
f9c888a1-2470-45e7-b2f9-b80fa4b1c30a	9fad18b8-66e2-419f-82b9-48991dd49847
f9c888a1-2470-45e7-b2f9-b80fa4b1c30a	a48e1955-b0ce-46d6-93ed-09ba372bb577
f9c888a1-2470-45e7-b2f9-b80fa4b1c30a	47e3ec31-a6c0-4051-94d8-1c624a63591f
f9c888a1-2470-45e7-b2f9-b80fa4b1c30a	08a5cb36-e078-404f-8ec8-adca98518bf2
f9c888a1-2470-45e7-b2f9-b80fa4b1c30a	16c7221b-58a3-4670-b09f-de5bef4986a1
f9c888a1-2470-45e7-b2f9-b80fa4b1c30a	26e2947c-84ac-41ed-8503-b284d157365d
f9c888a1-2470-45e7-b2f9-b80fa4b1c30a	9ac6cf4f-02e1-463e-9034-cce441b97235
f9c888a1-2470-45e7-b2f9-b80fa4b1c30a	1195a822-80fd-4810-883d-a9148b6dc49b
f9c888a1-2470-45e7-b2f9-b80fa4b1c30a	9aefe793-abe0-4052-9826-00e4b8c18cc0
f9c888a1-2470-45e7-b2f9-b80fa4b1c30a	8828f436-44ce-47c1-b357-4423fe0d9792
f9c888a1-2470-45e7-b2f9-b80fa4b1c30a	db7cc3e4-b91d-422c-944d-8b38bad70d3a
f9c888a1-2470-45e7-b2f9-b80fa4b1c30a	a61f4d23-5fd7-466d-8654-c515c4044f2a
f9c888a1-2470-45e7-b2f9-b80fa4b1c30a	aedfd698-0589-497b-996a-56b5488b2c90
f9c888a1-2470-45e7-b2f9-b80fa4b1c30a	793fcba9-d7d9-4ee7-af7e-74c3fa4abf6c
f9c888a1-2470-45e7-b2f9-b80fa4b1c30a	a8d15439-95e1-4241-b070-79f3014437a2
f9c888a1-2470-45e7-b2f9-b80fa4b1c30a	4a894d73-6b48-4315-bbbc-51324ab59916
f9c888a1-2470-45e7-b2f9-b80fa4b1c30a	6e0c16e4-1848-4675-8cfd-9029b941e703
793fcba9-d7d9-4ee7-af7e-74c3fa4abf6c	9fad18b8-66e2-419f-82b9-48991dd49847
112b6f3b-3904-421f-abf0-dda37752c236	71504726-a8a7-47db-bc3b-ca07e310b0be
4d0b20af-df72-49d4-b2ec-d6f82e92d4b1	9bffb9ea-0141-46f1-8adb-ae91529d6813
9ec7cdc9-cf2b-4d40-93dc-f89ed5c8a0f2	fcd31082-864b-4ad4-8da7-84020e903166
\.


--
-- Data for Name: credential; Type: TABLE DATA; Schema: public; Owner: keycloak
--

COPY public.credential (id, salt, type, user_id, created_date, user_label, secret_data, credential_data, priority, version) FROM stdin;
0aa1a9e9-a586-4b7b-9c5f-82a096e4b354	\N	password	6074dc87-06d6-40e0-b851-f702fe11d3c6	1779391645291	\N	{"value":"/ytECarYpaw/eTnR2RH2A3vmJH+VpUkElUtOjkAe5Wg=","salt":"c40yc4AbcOEM2T7rYttJvA==","additionalParameters":{}}	{"hashIterations":5,"algorithm":"argon2","additionalParameters":{"hashLength":["32"],"memory":["7168"],"type":["id"],"version":["1.3"],"parallelism":["1"]}}	10	0
5e3a41f4-a771-4bf1-9948-c9beb494ec6c	\N	password	addddfb1-5606-4b7a-b6cc-925a36faece3	1779392200191	My password	{"value":"OH7JaF1VRFDQ6fMGIZ6ptSmzDSihF1unKdCk+TE1Y60=","salt":"0Ax/TWDk5dMLkmGWSkda9Q==","additionalParameters":{}}	{"hashIterations":5,"algorithm":"argon2","additionalParameters":{"hashLength":["32"],"memory":["7168"],"type":["id"],"version":["1.3"],"parallelism":["1"]}}	10	1
\.


--
-- Data for Name: databasechangelog; Type: TABLE DATA; Schema: public; Owner: keycloak
--

COPY public.databasechangelog (id, author, filename, dateexecuted, orderexecuted, exectype, md5sum, description, comments, tag, liquibase, contexts, labels, deployment_id) FROM stdin;
1.0.0.Final-KEYCLOAK-5461	sthorger@redhat.com	META-INF/jpa-changelog-1.0.0.Final.xml	2026-05-21 19:27:20.264499	1	EXECUTED	9:6f1016664e21e16d26517a4418f5e3df	createTable tableName=APPLICATION_DEFAULT_ROLES; createTable tableName=CLIENT; createTable tableName=CLIENT_SESSION; createTable tableName=CLIENT_SESSION_ROLE; createTable tableName=COMPOSITE_ROLE; createTable tableName=CREDENTIAL; createTable tab...		\N	4.33.0	\N	\N	9391638388
1.0.0.Final-KEYCLOAK-5461	sthorger@redhat.com	META-INF/db2-jpa-changelog-1.0.0.Final.xml	2026-05-21 19:27:20.272145	2	MARK_RAN	9:828775b1596a07d1200ba1d49e5e3941	createTable tableName=APPLICATION_DEFAULT_ROLES; createTable tableName=CLIENT; createTable tableName=CLIENT_SESSION; createTable tableName=CLIENT_SESSION_ROLE; createTable tableName=COMPOSITE_ROLE; createTable tableName=CREDENTIAL; createTable tab...		\N	4.33.0	\N	\N	9391638388
1.1.0.Beta1	sthorger@redhat.com	META-INF/jpa-changelog-1.1.0.Beta1.xml	2026-05-21 19:27:20.284096	3	EXECUTED	9:5f090e44a7d595883c1fb61f4b41fd38	delete tableName=CLIENT_SESSION_ROLE; delete tableName=CLIENT_SESSION; delete tableName=USER_SESSION; createTable tableName=CLIENT_ATTRIBUTES; createTable tableName=CLIENT_SESSION_NOTE; createTable tableName=APP_NODE_REGISTRATIONS; addColumn table...		\N	4.33.0	\N	\N	9391638388
1.1.0.Final	sthorger@redhat.com	META-INF/jpa-changelog-1.1.0.Final.xml	2026-05-21 19:27:20.285421	4	EXECUTED	9:c07e577387a3d2c04d1adc9aaad8730e	renameColumn newColumnName=EVENT_TIME, oldColumnName=TIME, tableName=EVENT_ENTITY		\N	4.33.0	\N	\N	9391638388
1.2.0.Beta1	psilva@redhat.com	META-INF/jpa-changelog-1.2.0.Beta1.xml	2026-05-21 19:27:20.314858	5	EXECUTED	9:b68ce996c655922dbcd2fe6b6ae72686	delete tableName=CLIENT_SESSION_ROLE; delete tableName=CLIENT_SESSION_NOTE; delete tableName=CLIENT_SESSION; delete tableName=USER_SESSION; createTable tableName=PROTOCOL_MAPPER; createTable tableName=PROTOCOL_MAPPER_CONFIG; createTable tableName=...		\N	4.33.0	\N	\N	9391638388
1.2.0.Beta1	psilva@redhat.com	META-INF/db2-jpa-changelog-1.2.0.Beta1.xml	2026-05-21 19:27:20.317698	6	MARK_RAN	9:543b5c9989f024fe35c6f6c5a97de88e	delete tableName=CLIENT_SESSION_ROLE; delete tableName=CLIENT_SESSION_NOTE; delete tableName=CLIENT_SESSION; delete tableName=USER_SESSION; createTable tableName=PROTOCOL_MAPPER; createTable tableName=PROTOCOL_MAPPER_CONFIG; createTable tableName=...		\N	4.33.0	\N	\N	9391638388
1.2.0.RC1	bburke@redhat.com	META-INF/jpa-changelog-1.2.0.CR1.xml	2026-05-21 19:27:20.341495	7	EXECUTED	9:765afebbe21cf5bbca048e632df38336	delete tableName=CLIENT_SESSION_ROLE; delete tableName=CLIENT_SESSION_NOTE; delete tableName=CLIENT_SESSION; delete tableName=USER_SESSION_NOTE; delete tableName=USER_SESSION; createTable tableName=MIGRATION_MODEL; createTable tableName=IDENTITY_P...		\N	4.33.0	\N	\N	9391638388
1.2.0.RC1	bburke@redhat.com	META-INF/db2-jpa-changelog-1.2.0.CR1.xml	2026-05-21 19:27:20.344537	8	MARK_RAN	9:db4a145ba11a6fdaefb397f6dbf829a1	delete tableName=CLIENT_SESSION_ROLE; delete tableName=CLIENT_SESSION_NOTE; delete tableName=CLIENT_SESSION; delete tableName=USER_SESSION_NOTE; delete tableName=USER_SESSION; createTable tableName=MIGRATION_MODEL; createTable tableName=IDENTITY_P...		\N	4.33.0	\N	\N	9391638388
1.2.0.Final	keycloak	META-INF/jpa-changelog-1.2.0.Final.xml	2026-05-21 19:27:20.347347	9	EXECUTED	9:9d05c7be10cdb873f8bcb41bc3a8ab23	update tableName=CLIENT; update tableName=CLIENT; update tableName=CLIENT		\N	4.33.0	\N	\N	9391638388
1.3.0	bburke@redhat.com	META-INF/jpa-changelog-1.3.0.xml	2026-05-21 19:27:20.385692	10	EXECUTED	9:18593702353128d53111f9b1ff0b82b8	delete tableName=CLIENT_SESSION_ROLE; delete tableName=CLIENT_SESSION_PROT_MAPPER; delete tableName=CLIENT_SESSION_NOTE; delete tableName=CLIENT_SESSION; delete tableName=USER_SESSION_NOTE; delete tableName=USER_SESSION; createTable tableName=ADMI...		\N	4.33.0	\N	\N	9391638388
1.4.0	bburke@redhat.com	META-INF/jpa-changelog-1.4.0.xml	2026-05-21 19:27:20.400465	11	EXECUTED	9:6122efe5f090e41a85c0f1c9e52cbb62	delete tableName=CLIENT_SESSION_AUTH_STATUS; delete tableName=CLIENT_SESSION_ROLE; delete tableName=CLIENT_SESSION_PROT_MAPPER; delete tableName=CLIENT_SESSION_NOTE; delete tableName=CLIENT_SESSION; delete tableName=USER_SESSION_NOTE; delete table...		\N	4.33.0	\N	\N	9391638388
1.4.0	bburke@redhat.com	META-INF/db2-jpa-changelog-1.4.0.xml	2026-05-21 19:27:20.402615	12	MARK_RAN	9:e1ff28bf7568451453f844c5d54bb0b5	delete tableName=CLIENT_SESSION_AUTH_STATUS; delete tableName=CLIENT_SESSION_ROLE; delete tableName=CLIENT_SESSION_PROT_MAPPER; delete tableName=CLIENT_SESSION_NOTE; delete tableName=CLIENT_SESSION; delete tableName=USER_SESSION_NOTE; delete table...		\N	4.33.0	\N	\N	9391638388
1.5.0	bburke@redhat.com	META-INF/jpa-changelog-1.5.0.xml	2026-05-21 19:27:20.410029	13	EXECUTED	9:7af32cd8957fbc069f796b61217483fd	delete tableName=CLIENT_SESSION_AUTH_STATUS; delete tableName=CLIENT_SESSION_ROLE; delete tableName=CLIENT_SESSION_PROT_MAPPER; delete tableName=CLIENT_SESSION_NOTE; delete tableName=CLIENT_SESSION; delete tableName=USER_SESSION_NOTE; delete table...		\N	4.33.0	\N	\N	9391638388
1.6.1_from15	mposolda@redhat.com	META-INF/jpa-changelog-1.6.1.xml	2026-05-21 19:27:20.41548	14	EXECUTED	9:6005e15e84714cd83226bf7879f54190	addColumn tableName=REALM; addColumn tableName=KEYCLOAK_ROLE; addColumn tableName=CLIENT; createTable tableName=OFFLINE_USER_SESSION; createTable tableName=OFFLINE_CLIENT_SESSION; addPrimaryKey constraintName=CONSTRAINT_OFFL_US_SES_PK2, tableName=...		\N	4.33.0	\N	\N	9391638388
1.6.1_from16-pre	mposolda@redhat.com	META-INF/jpa-changelog-1.6.1.xml	2026-05-21 19:27:20.416521	15	MARK_RAN	9:bf656f5a2b055d07f314431cae76f06c	delete tableName=OFFLINE_CLIENT_SESSION; delete tableName=OFFLINE_USER_SESSION		\N	4.33.0	\N	\N	9391638388
1.6.1_from16	mposolda@redhat.com	META-INF/jpa-changelog-1.6.1.xml	2026-05-21 19:27:20.41803	16	MARK_RAN	9:f8dadc9284440469dcf71e25ca6ab99b	dropPrimaryKey constraintName=CONSTRAINT_OFFLINE_US_SES_PK, tableName=OFFLINE_USER_SESSION; dropPrimaryKey constraintName=CONSTRAINT_OFFLINE_CL_SES_PK, tableName=OFFLINE_CLIENT_SESSION; addColumn tableName=OFFLINE_USER_SESSION; update tableName=OF...		\N	4.33.0	\N	\N	9391638388
1.6.1	mposolda@redhat.com	META-INF/jpa-changelog-1.6.1.xml	2026-05-21 19:27:20.41906	17	EXECUTED	9:d41d8cd98f00b204e9800998ecf8427e	empty		\N	4.33.0	\N	\N	9391638388
1.7.0	bburke@redhat.com	META-INF/jpa-changelog-1.7.0.xml	2026-05-21 19:27:20.429395	18	EXECUTED	9:3368ff0be4c2855ee2dd9ca813b38d8e	createTable tableName=KEYCLOAK_GROUP; createTable tableName=GROUP_ROLE_MAPPING; createTable tableName=GROUP_ATTRIBUTE; createTable tableName=USER_GROUP_MEMBERSHIP; createTable tableName=REALM_DEFAULT_GROUPS; addColumn tableName=IDENTITY_PROVIDER; ...		\N	4.33.0	\N	\N	9391638388
1.8.0	mposolda@redhat.com	META-INF/jpa-changelog-1.8.0.xml	2026-05-21 19:27:20.439706	19	EXECUTED	9:8ac2fb5dd030b24c0570a763ed75ed20	addColumn tableName=IDENTITY_PROVIDER; createTable tableName=CLIENT_TEMPLATE; createTable tableName=CLIENT_TEMPLATE_ATTRIBUTES; createTable tableName=TEMPLATE_SCOPE_MAPPING; dropNotNullConstraint columnName=CLIENT_ID, tableName=PROTOCOL_MAPPER; ad...		\N	4.33.0	\N	\N	9391638388
1.8.0-2	keycloak	META-INF/jpa-changelog-1.8.0.xml	2026-05-21 19:27:20.440935	20	EXECUTED	9:f91ddca9b19743db60e3057679810e6c	dropDefaultValue columnName=ALGORITHM, tableName=CREDENTIAL; update tableName=CREDENTIAL		\N	4.33.0	\N	\N	9391638388
22.0.5-24031	keycloak	META-INF/jpa-changelog-22.0.0.xml	2026-05-21 19:27:22.225495	119	MARK_RAN	9:a60d2d7b315ec2d3eba9e2f145f9df28	customChange		\N	4.33.0	\N	\N	9391638388
1.8.0	mposolda@redhat.com	META-INF/db2-jpa-changelog-1.8.0.xml	2026-05-21 19:27:20.442295	21	MARK_RAN	9:831e82914316dc8a57dc09d755f23c51	addColumn tableName=IDENTITY_PROVIDER; createTable tableName=CLIENT_TEMPLATE; createTable tableName=CLIENT_TEMPLATE_ATTRIBUTES; createTable tableName=TEMPLATE_SCOPE_MAPPING; dropNotNullConstraint columnName=CLIENT_ID, tableName=PROTOCOL_MAPPER; ad...		\N	4.33.0	\N	\N	9391638388
1.8.0-2	keycloak	META-INF/db2-jpa-changelog-1.8.0.xml	2026-05-21 19:27:20.443159	22	MARK_RAN	9:f91ddca9b19743db60e3057679810e6c	dropDefaultValue columnName=ALGORITHM, tableName=CREDENTIAL; update tableName=CREDENTIAL		\N	4.33.0	\N	\N	9391638388
1.9.0	mposolda@redhat.com	META-INF/jpa-changelog-1.9.0.xml	2026-05-21 19:27:20.470918	23	EXECUTED	9:bc3d0f9e823a69dc21e23e94c7a94bb1	update tableName=REALM; update tableName=REALM; update tableName=REALM; update tableName=REALM; update tableName=CREDENTIAL; update tableName=CREDENTIAL; update tableName=CREDENTIAL; update tableName=REALM; update tableName=REALM; customChange; dr...		\N	4.33.0	\N	\N	9391638388
1.9.1	keycloak	META-INF/jpa-changelog-1.9.1.xml	2026-05-21 19:27:20.473056	24	EXECUTED	9:c9999da42f543575ab790e76439a2679	modifyDataType columnName=PRIVATE_KEY, tableName=REALM; modifyDataType columnName=PUBLIC_KEY, tableName=REALM; modifyDataType columnName=CERTIFICATE, tableName=REALM		\N	4.33.0	\N	\N	9391638388
1.9.1	keycloak	META-INF/db2-jpa-changelog-1.9.1.xml	2026-05-21 19:27:20.47361	25	MARK_RAN	9:0d6c65c6f58732d81569e77b10ba301d	modifyDataType columnName=PRIVATE_KEY, tableName=REALM; modifyDataType columnName=CERTIFICATE, tableName=REALM		\N	4.33.0	\N	\N	9391638388
1.9.2	keycloak	META-INF/jpa-changelog-1.9.2.xml	2026-05-21 19:27:20.624182	26	EXECUTED	9:fc576660fc016ae53d2d4778d84d86d0	createIndex indexName=IDX_USER_EMAIL, tableName=USER_ENTITY; createIndex indexName=IDX_USER_ROLE_MAPPING, tableName=USER_ROLE_MAPPING; createIndex indexName=IDX_USER_GROUP_MAPPING, tableName=USER_GROUP_MEMBERSHIP; createIndex indexName=IDX_USER_CO...		\N	4.33.0	\N	\N	9391638388
authz-2.0.0	psilva@redhat.com	META-INF/jpa-changelog-authz-2.0.0.xml	2026-05-21 19:27:20.640109	27	EXECUTED	9:43ed6b0da89ff77206289e87eaa9c024	createTable tableName=RESOURCE_SERVER; addPrimaryKey constraintName=CONSTRAINT_FARS, tableName=RESOURCE_SERVER; addUniqueConstraint constraintName=UK_AU8TT6T700S9V50BU18WS5HA6, tableName=RESOURCE_SERVER; createTable tableName=RESOURCE_SERVER_RESOU...		\N	4.33.0	\N	\N	9391638388
authz-2.5.1	psilva@redhat.com	META-INF/jpa-changelog-authz-2.5.1.xml	2026-05-21 19:27:20.641565	28	EXECUTED	9:44bae577f551b3738740281eceb4ea70	update tableName=RESOURCE_SERVER_POLICY		\N	4.33.0	\N	\N	9391638388
2.1.0-KEYCLOAK-5461	bburke@redhat.com	META-INF/jpa-changelog-2.1.0.xml	2026-05-21 19:27:20.65423	29	EXECUTED	9:bd88e1f833df0420b01e114533aee5e8	createTable tableName=BROKER_LINK; createTable tableName=FED_USER_ATTRIBUTE; createTable tableName=FED_USER_CONSENT; createTable tableName=FED_USER_CONSENT_ROLE; createTable tableName=FED_USER_CONSENT_PROT_MAPPER; createTable tableName=FED_USER_CR...		\N	4.33.0	\N	\N	9391638388
2.2.0	bburke@redhat.com	META-INF/jpa-changelog-2.2.0.xml	2026-05-21 19:27:20.658354	30	EXECUTED	9:a7022af5267f019d020edfe316ef4371	addColumn tableName=ADMIN_EVENT_ENTITY; createTable tableName=CREDENTIAL_ATTRIBUTE; createTable tableName=FED_CREDENTIAL_ATTRIBUTE; modifyDataType columnName=VALUE, tableName=CREDENTIAL; addForeignKeyConstraint baseTableName=FED_CREDENTIAL_ATTRIBU...		\N	4.33.0	\N	\N	9391638388
2.3.0	bburke@redhat.com	META-INF/jpa-changelog-2.3.0.xml	2026-05-21 19:27:20.663619	31	EXECUTED	9:fc155c394040654d6a79227e56f5e25a	createTable tableName=FEDERATED_USER; addPrimaryKey constraintName=CONSTR_FEDERATED_USER, tableName=FEDERATED_USER; dropDefaultValue columnName=TOTP, tableName=USER_ENTITY; dropColumn columnName=TOTP, tableName=USER_ENTITY; addColumn tableName=IDE...		\N	4.33.0	\N	\N	9391638388
2.4.0	bburke@redhat.com	META-INF/jpa-changelog-2.4.0.xml	2026-05-21 19:27:20.665079	32	EXECUTED	9:eac4ffb2a14795e5dc7b426063e54d88	customChange		\N	4.33.0	\N	\N	9391638388
2.5.0	bburke@redhat.com	META-INF/jpa-changelog-2.5.0.xml	2026-05-21 19:27:20.667133	33	EXECUTED	9:54937c05672568c4c64fc9524c1e9462	customChange; modifyDataType columnName=USER_ID, tableName=OFFLINE_USER_SESSION		\N	4.33.0	\N	\N	9391638388
2.5.0-unicode-oracle	hmlnarik@redhat.com	META-INF/jpa-changelog-2.5.0.xml	2026-05-21 19:27:20.668345	34	MARK_RAN	9:f9753208029f582525ed12011a19d054	modifyDataType columnName=DESCRIPTION, tableName=AUTHENTICATION_FLOW; modifyDataType columnName=DESCRIPTION, tableName=CLIENT_TEMPLATE; modifyDataType columnName=DESCRIPTION, tableName=RESOURCE_SERVER_POLICY; modifyDataType columnName=DESCRIPTION,...		\N	4.33.0	\N	\N	9391638388
2.5.0-unicode-other-dbs	hmlnarik@redhat.com	META-INF/jpa-changelog-2.5.0.xml	2026-05-21 19:27:20.676605	35	EXECUTED	9:33d72168746f81f98ae3a1e8e0ca3554	modifyDataType columnName=DESCRIPTION, tableName=AUTHENTICATION_FLOW; modifyDataType columnName=DESCRIPTION, tableName=CLIENT_TEMPLATE; modifyDataType columnName=DESCRIPTION, tableName=RESOURCE_SERVER_POLICY; modifyDataType columnName=DESCRIPTION,...		\N	4.33.0	\N	\N	9391638388
2.5.0-duplicate-email-support	slawomir@dabek.name	META-INF/jpa-changelog-2.5.0.xml	2026-05-21 19:27:20.678419	36	EXECUTED	9:61b6d3d7a4c0e0024b0c839da283da0c	addColumn tableName=REALM		\N	4.33.0	\N	\N	9391638388
2.5.0-unique-group-names	hmlnarik@redhat.com	META-INF/jpa-changelog-2.5.0.xml	2026-05-21 19:27:20.679627	37	EXECUTED	9:8dcac7bdf7378e7d823cdfddebf72fda	addUniqueConstraint constraintName=SIBLING_NAMES, tableName=KEYCLOAK_GROUP		\N	4.33.0	\N	\N	9391638388
2.5.1	bburke@redhat.com	META-INF/jpa-changelog-2.5.1.xml	2026-05-21 19:27:20.68075	38	EXECUTED	9:a2b870802540cb3faa72098db5388af3	addColumn tableName=FED_USER_CONSENT		\N	4.33.0	\N	\N	9391638388
3.0.0	bburke@redhat.com	META-INF/jpa-changelog-3.0.0.xml	2026-05-21 19:27:20.681907	39	EXECUTED	9:132a67499ba24bcc54fb5cbdcfe7e4c0	addColumn tableName=IDENTITY_PROVIDER		\N	4.33.0	\N	\N	9391638388
3.2.0-fix	keycloak	META-INF/jpa-changelog-3.2.0.xml	2026-05-21 19:27:20.682331	40	MARK_RAN	9:938f894c032f5430f2b0fafb1a243462	addNotNullConstraint columnName=REALM_ID, tableName=CLIENT_INITIAL_ACCESS		\N	4.33.0	\N	\N	9391638388
3.2.0-fix-with-keycloak-5416	keycloak	META-INF/jpa-changelog-3.2.0.xml	2026-05-21 19:27:20.682971	41	MARK_RAN	9:845c332ff1874dc5d35974b0babf3006	dropIndex indexName=IDX_CLIENT_INIT_ACC_REALM, tableName=CLIENT_INITIAL_ACCESS; addNotNullConstraint columnName=REALM_ID, tableName=CLIENT_INITIAL_ACCESS; createIndex indexName=IDX_CLIENT_INIT_ACC_REALM, tableName=CLIENT_INITIAL_ACCESS		\N	4.33.0	\N	\N	9391638388
3.2.0-fix-offline-sessions	hmlnarik	META-INF/jpa-changelog-3.2.0.xml	2026-05-21 19:27:20.684529	42	EXECUTED	9:fc86359c079781adc577c5a217e4d04c	customChange		\N	4.33.0	\N	\N	9391638388
3.2.0-fixed	keycloak	META-INF/jpa-changelog-3.2.0.xml	2026-05-21 19:27:21.264574	43	EXECUTED	9:59a64800e3c0d09b825f8a3b444fa8f4	addColumn tableName=REALM; dropPrimaryKey constraintName=CONSTRAINT_OFFL_CL_SES_PK2, tableName=OFFLINE_CLIENT_SESSION; dropColumn columnName=CLIENT_SESSION_ID, tableName=OFFLINE_CLIENT_SESSION; addPrimaryKey constraintName=CONSTRAINT_OFFL_CL_SES_P...		\N	4.33.0	\N	\N	9391638388
3.3.0	keycloak	META-INF/jpa-changelog-3.3.0.xml	2026-05-21 19:27:21.26631	44	EXECUTED	9:d48d6da5c6ccf667807f633fe489ce88	addColumn tableName=USER_ENTITY		\N	4.33.0	\N	\N	9391638388
authz-3.4.0.CR1-resource-server-pk-change-part1	glavoie@gmail.com	META-INF/jpa-changelog-authz-3.4.0.CR1.xml	2026-05-21 19:27:21.268676	45	EXECUTED	9:dde36f7973e80d71fceee683bc5d2951	addColumn tableName=RESOURCE_SERVER_POLICY; addColumn tableName=RESOURCE_SERVER_RESOURCE; addColumn tableName=RESOURCE_SERVER_SCOPE		\N	4.33.0	\N	\N	9391638388
authz-3.4.0.CR1-resource-server-pk-change-part2-KEYCLOAK-6095	hmlnarik@redhat.com	META-INF/jpa-changelog-authz-3.4.0.CR1.xml	2026-05-21 19:27:21.270289	46	EXECUTED	9:b855e9b0a406b34fa323235a0cf4f640	customChange		\N	4.33.0	\N	\N	9391638388
authz-3.4.0.CR1-resource-server-pk-change-part3-fixed	glavoie@gmail.com	META-INF/jpa-changelog-authz-3.4.0.CR1.xml	2026-05-21 19:27:21.270814	47	MARK_RAN	9:51abbacd7b416c50c4421a8cabf7927e	dropIndex indexName=IDX_RES_SERV_POL_RES_SERV, tableName=RESOURCE_SERVER_POLICY; dropIndex indexName=IDX_RES_SRV_RES_RES_SRV, tableName=RESOURCE_SERVER_RESOURCE; dropIndex indexName=IDX_RES_SRV_SCOPE_RES_SRV, tableName=RESOURCE_SERVER_SCOPE		\N	4.33.0	\N	\N	9391638388
authz-3.4.0.CR1-resource-server-pk-change-part3-fixed-nodropindex	glavoie@gmail.com	META-INF/jpa-changelog-authz-3.4.0.CR1.xml	2026-05-21 19:27:21.307664	48	EXECUTED	9:bdc99e567b3398bac83263d375aad143	addNotNullConstraint columnName=RESOURCE_SERVER_CLIENT_ID, tableName=RESOURCE_SERVER_POLICY; addNotNullConstraint columnName=RESOURCE_SERVER_CLIENT_ID, tableName=RESOURCE_SERVER_RESOURCE; addNotNullConstraint columnName=RESOURCE_SERVER_CLIENT_ID, ...		\N	4.33.0	\N	\N	9391638388
authn-3.4.0.CR1-refresh-token-max-reuse	glavoie@gmail.com	META-INF/jpa-changelog-authz-3.4.0.CR1.xml	2026-05-21 19:27:21.309399	49	EXECUTED	9:d198654156881c46bfba39abd7769e69	addColumn tableName=REALM		\N	4.33.0	\N	\N	9391638388
3.4.0	keycloak	META-INF/jpa-changelog-3.4.0.xml	2026-05-21 19:27:21.315518	50	EXECUTED	9:cfdd8736332ccdd72c5256ccb42335db	addPrimaryKey constraintName=CONSTRAINT_REALM_DEFAULT_ROLES, tableName=REALM_DEFAULT_ROLES; addPrimaryKey constraintName=CONSTRAINT_COMPOSITE_ROLE, tableName=COMPOSITE_ROLE; addPrimaryKey constraintName=CONSTR_REALM_DEFAULT_GROUPS, tableName=REALM...		\N	4.33.0	\N	\N	9391638388
3.4.0-KEYCLOAK-5230	hmlnarik@redhat.com	META-INF/jpa-changelog-3.4.0.xml	2026-05-21 19:27:21.434401	51	EXECUTED	9:7c84de3d9bd84d7f077607c1a4dcb714	createIndex indexName=IDX_FU_ATTRIBUTE, tableName=FED_USER_ATTRIBUTE; createIndex indexName=IDX_FU_CONSENT, tableName=FED_USER_CONSENT; createIndex indexName=IDX_FU_CONSENT_RU, tableName=FED_USER_CONSENT; createIndex indexName=IDX_FU_CREDENTIAL, t...		\N	4.33.0	\N	\N	9391638388
3.4.1	psilva@redhat.com	META-INF/jpa-changelog-3.4.1.xml	2026-05-21 19:27:21.435904	52	EXECUTED	9:5a6bb36cbefb6a9d6928452c0852af2d	modifyDataType columnName=VALUE, tableName=CLIENT_ATTRIBUTES		\N	4.33.0	\N	\N	9391638388
3.4.2	keycloak	META-INF/jpa-changelog-3.4.2.xml	2026-05-21 19:27:21.437108	53	EXECUTED	9:8f23e334dbc59f82e0a328373ca6ced0	update tableName=REALM		\N	4.33.0	\N	\N	9391638388
3.4.2-KEYCLOAK-5172	mkanis@redhat.com	META-INF/jpa-changelog-3.4.2.xml	2026-05-21 19:27:21.438435	54	EXECUTED	9:9156214268f09d970cdf0e1564d866af	update tableName=CLIENT		\N	4.33.0	\N	\N	9391638388
4.0.0-KEYCLOAK-6335	bburke@redhat.com	META-INF/jpa-changelog-4.0.0.xml	2026-05-21 19:27:21.440145	55	EXECUTED	9:db806613b1ed154826c02610b7dbdf74	createTable tableName=CLIENT_AUTH_FLOW_BINDINGS; addPrimaryKey constraintName=C_CLI_FLOW_BIND, tableName=CLIENT_AUTH_FLOW_BINDINGS		\N	4.33.0	\N	\N	9391638388
4.0.0-CLEANUP-UNUSED-TABLE	bburke@redhat.com	META-INF/jpa-changelog-4.0.0.xml	2026-05-21 19:27:21.441942	56	EXECUTED	9:229a041fb72d5beac76bb94a5fa709de	dropTable tableName=CLIENT_IDENTITY_PROV_MAPPING		\N	4.33.0	\N	\N	9391638388
4.0.0-KEYCLOAK-6228	bburke@redhat.com	META-INF/jpa-changelog-4.0.0.xml	2026-05-21 19:27:21.459915	57	EXECUTED	9:079899dade9c1e683f26b2aa9ca6ff04	dropUniqueConstraint constraintName=UK_JKUWUVD56ONTGSUHOGM8UEWRT, tableName=USER_CONSENT; dropNotNullConstraint columnName=CLIENT_ID, tableName=USER_CONSENT; addColumn tableName=USER_CONSENT; addUniqueConstraint constraintName=UK_JKUWUVD56ONTGSUHO...		\N	4.33.0	\N	\N	9391638388
4.0.0-KEYCLOAK-5579-fixed	mposolda@redhat.com	META-INF/jpa-changelog-4.0.0.xml	2026-05-21 19:27:21.631596	58	EXECUTED	9:139b79bcbbfe903bb1c2d2a4dbf001d9	dropForeignKeyConstraint baseTableName=CLIENT_TEMPLATE_ATTRIBUTES, constraintName=FK_CL_TEMPL_ATTR_TEMPL; renameTable newTableName=CLIENT_SCOPE_ATTRIBUTES, oldTableName=CLIENT_TEMPLATE_ATTRIBUTES; renameColumn newColumnName=SCOPE_ID, oldColumnName...		\N	4.33.0	\N	\N	9391638388
authz-4.0.0.CR1	psilva@redhat.com	META-INF/jpa-changelog-authz-4.0.0.CR1.xml	2026-05-21 19:27:21.642658	59	EXECUTED	9:b55738ad889860c625ba2bf483495a04	createTable tableName=RESOURCE_SERVER_PERM_TICKET; addPrimaryKey constraintName=CONSTRAINT_FAPMT, tableName=RESOURCE_SERVER_PERM_TICKET; addForeignKeyConstraint baseTableName=RESOURCE_SERVER_PERM_TICKET, constraintName=FK_FRSRHO213XCX4WNKOG82SSPMT...		\N	4.33.0	\N	\N	9391638388
authz-4.0.0.Beta3	psilva@redhat.com	META-INF/jpa-changelog-authz-4.0.0.Beta3.xml	2026-05-21 19:27:21.6445	60	EXECUTED	9:e0057eac39aa8fc8e09ac6cfa4ae15fe	addColumn tableName=RESOURCE_SERVER_POLICY; addColumn tableName=RESOURCE_SERVER_PERM_TICKET; addForeignKeyConstraint baseTableName=RESOURCE_SERVER_PERM_TICKET, constraintName=FK_FRSRPO2128CX4WNKOG82SSRFY, referencedTableName=RESOURCE_SERVER_POLICY		\N	4.33.0	\N	\N	9391638388
authz-4.2.0.Final	mhajas@redhat.com	META-INF/jpa-changelog-authz-4.2.0.Final.xml	2026-05-21 19:27:21.647486	61	EXECUTED	9:42a33806f3a0443fe0e7feeec821326c	createTable tableName=RESOURCE_URIS; addForeignKeyConstraint baseTableName=RESOURCE_URIS, constraintName=FK_RESOURCE_SERVER_URIS, referencedTableName=RESOURCE_SERVER_RESOURCE; customChange; dropColumn columnName=URI, tableName=RESOURCE_SERVER_RESO...		\N	4.33.0	\N	\N	9391638388
authz-4.2.0.Final-KEYCLOAK-9944	hmlnarik@redhat.com	META-INF/jpa-changelog-authz-4.2.0.Final.xml	2026-05-21 19:27:21.648553	62	EXECUTED	9:9968206fca46eecc1f51db9c024bfe56	addPrimaryKey constraintName=CONSTRAINT_RESOUR_URIS_PK, tableName=RESOURCE_URIS		\N	4.33.0	\N	\N	9391638388
4.2.0-KEYCLOAK-6313	wadahiro@gmail.com	META-INF/jpa-changelog-4.2.0.xml	2026-05-21 19:27:21.649616	63	EXECUTED	9:92143a6daea0a3f3b8f598c97ce55c3d	addColumn tableName=REQUIRED_ACTION_PROVIDER		\N	4.33.0	\N	\N	9391638388
4.3.0-KEYCLOAK-7984	wadahiro@gmail.com	META-INF/jpa-changelog-4.3.0.xml	2026-05-21 19:27:21.65055	64	EXECUTED	9:82bab26a27195d889fb0429003b18f40	update tableName=REQUIRED_ACTION_PROVIDER		\N	4.33.0	\N	\N	9391638388
4.6.0-KEYCLOAK-7950	psilva@redhat.com	META-INF/jpa-changelog-4.6.0.xml	2026-05-21 19:27:21.651453	65	EXECUTED	9:e590c88ddc0b38b0ae4249bbfcb5abc3	update tableName=RESOURCE_SERVER_RESOURCE		\N	4.33.0	\N	\N	9391638388
4.6.0-KEYCLOAK-8377	keycloak	META-INF/jpa-changelog-4.6.0.xml	2026-05-21 19:27:21.672499	66	EXECUTED	9:5c1f475536118dbdc38d5d7977950cc0	createTable tableName=ROLE_ATTRIBUTE; addPrimaryKey constraintName=CONSTRAINT_ROLE_ATTRIBUTE_PK, tableName=ROLE_ATTRIBUTE; addForeignKeyConstraint baseTableName=ROLE_ATTRIBUTE, constraintName=FK_ROLE_ATTRIBUTE_ID, referencedTableName=KEYCLOAK_ROLE...		\N	4.33.0	\N	\N	9391638388
4.6.0-KEYCLOAK-8555	gideonray@gmail.com	META-INF/jpa-changelog-4.6.0.xml	2026-05-21 19:27:21.713623	67	EXECUTED	9:e7c9f5f9c4d67ccbbcc215440c718a17	createIndex indexName=IDX_COMPONENT_PROVIDER_TYPE, tableName=COMPONENT		\N	4.33.0	\N	\N	9391638388
4.7.0-KEYCLOAK-1267	sguilhen@redhat.com	META-INF/jpa-changelog-4.7.0.xml	2026-05-21 19:27:21.715984	68	EXECUTED	9:88e0bfdda924690d6f4e430c53447dd5	addColumn tableName=REALM		\N	4.33.0	\N	\N	9391638388
4.7.0-KEYCLOAK-7275	keycloak	META-INF/jpa-changelog-4.7.0.xml	2026-05-21 19:27:21.738153	69	EXECUTED	9:f53177f137e1c46b6a88c59ec1cb5218	renameColumn newColumnName=CREATED_ON, oldColumnName=LAST_SESSION_REFRESH, tableName=OFFLINE_USER_SESSION; addNotNullConstraint columnName=CREATED_ON, tableName=OFFLINE_USER_SESSION; addColumn tableName=OFFLINE_USER_SESSION; customChange; createIn...		\N	4.33.0	\N	\N	9391638388
4.8.0-KEYCLOAK-8835	sguilhen@redhat.com	META-INF/jpa-changelog-4.8.0.xml	2026-05-21 19:27:21.741007	70	EXECUTED	9:a74d33da4dc42a37ec27121580d1459f	addNotNullConstraint columnName=SSO_MAX_LIFESPAN_REMEMBER_ME, tableName=REALM; addNotNullConstraint columnName=SSO_IDLE_TIMEOUT_REMEMBER_ME, tableName=REALM		\N	4.33.0	\N	\N	9391638388
authz-7.0.0-KEYCLOAK-10443	psilva@redhat.com	META-INF/jpa-changelog-authz-7.0.0.xml	2026-05-21 19:27:21.743007	71	EXECUTED	9:fd4ade7b90c3b67fae0bfcfcb42dfb5f	addColumn tableName=RESOURCE_SERVER		\N	4.33.0	\N	\N	9391638388
8.0.0-adding-credential-columns	keycloak	META-INF/jpa-changelog-8.0.0.xml	2026-05-21 19:27:21.745887	72	EXECUTED	9:aa072ad090bbba210d8f18781b8cebf4	addColumn tableName=CREDENTIAL; addColumn tableName=FED_USER_CREDENTIAL		\N	4.33.0	\N	\N	9391638388
8.0.0-updating-credential-data-not-oracle-fixed	keycloak	META-INF/jpa-changelog-8.0.0.xml	2026-05-21 19:27:21.750518	73	EXECUTED	9:1ae6be29bab7c2aa376f6983b932be37	update tableName=CREDENTIAL; update tableName=CREDENTIAL; update tableName=CREDENTIAL; update tableName=FED_USER_CREDENTIAL; update tableName=FED_USER_CREDENTIAL; update tableName=FED_USER_CREDENTIAL		\N	4.33.0	\N	\N	9391638388
8.0.0-updating-credential-data-oracle-fixed	keycloak	META-INF/jpa-changelog-8.0.0.xml	2026-05-21 19:27:21.752175	74	MARK_RAN	9:14706f286953fc9a25286dbd8fb30d97	update tableName=CREDENTIAL; update tableName=CREDENTIAL; update tableName=CREDENTIAL; update tableName=FED_USER_CREDENTIAL; update tableName=FED_USER_CREDENTIAL; update tableName=FED_USER_CREDENTIAL		\N	4.33.0	\N	\N	9391638388
8.0.0-credential-cleanup-fixed	keycloak	META-INF/jpa-changelog-8.0.0.xml	2026-05-21 19:27:21.854195	75	EXECUTED	9:2b9cc12779be32c5b40e2e67711a218b	dropDefaultValue columnName=COUNTER, tableName=CREDENTIAL; dropDefaultValue columnName=DIGITS, tableName=CREDENTIAL; dropDefaultValue columnName=PERIOD, tableName=CREDENTIAL; dropDefaultValue columnName=ALGORITHM, tableName=CREDENTIAL; dropColumn ...		\N	4.33.0	\N	\N	9391638388
8.0.0-resource-tag-support	keycloak	META-INF/jpa-changelog-8.0.0.xml	2026-05-21 19:27:21.910611	76	EXECUTED	9:91fa186ce7a5af127a2d7a91ee083cc5	addColumn tableName=MIGRATION_MODEL; createIndex indexName=IDX_UPDATE_TIME, tableName=MIGRATION_MODEL		\N	4.33.0	\N	\N	9391638388
9.0.0-always-display-client	keycloak	META-INF/jpa-changelog-9.0.0.xml	2026-05-21 19:27:21.912305	77	EXECUTED	9:6335e5c94e83a2639ccd68dd24e2e5ad	addColumn tableName=CLIENT		\N	4.33.0	\N	\N	9391638388
9.0.0-drop-constraints-for-column-increase	keycloak	META-INF/jpa-changelog-9.0.0.xml	2026-05-21 19:27:21.912902	78	MARK_RAN	9:6bdb5658951e028bfe16fa0a8228b530	dropUniqueConstraint constraintName=UK_FRSR6T700S9V50BU18WS5PMT, tableName=RESOURCE_SERVER_PERM_TICKET; dropUniqueConstraint constraintName=UK_FRSR6T700S9V50BU18WS5HA6, tableName=RESOURCE_SERVER_RESOURCE; dropPrimaryKey constraintName=CONSTRAINT_O...		\N	4.33.0	\N	\N	9391638388
9.0.0-increase-column-size-federated-fk	keycloak	META-INF/jpa-changelog-9.0.0.xml	2026-05-21 19:27:21.918346	79	EXECUTED	9:d5bc15a64117ccad481ce8792d4c608f	modifyDataType columnName=CLIENT_ID, tableName=FED_USER_CONSENT; modifyDataType columnName=CLIENT_REALM_CONSTRAINT, tableName=KEYCLOAK_ROLE; modifyDataType columnName=OWNER, tableName=RESOURCE_SERVER_POLICY; modifyDataType columnName=CLIENT_ID, ta...		\N	4.33.0	\N	\N	9391638388
9.0.0-recreate-constraints-after-column-increase	keycloak	META-INF/jpa-changelog-9.0.0.xml	2026-05-21 19:27:21.918936	80	MARK_RAN	9:077cba51999515f4d3e7ad5619ab592c	addNotNullConstraint columnName=CLIENT_ID, tableName=OFFLINE_CLIENT_SESSION; addNotNullConstraint columnName=OWNER, tableName=RESOURCE_SERVER_PERM_TICKET; addNotNullConstraint columnName=REQUESTER, tableName=RESOURCE_SERVER_PERM_TICKET; addNotNull...		\N	4.33.0	\N	\N	9391638388
9.0.1-add-index-to-client.client_id	keycloak	META-INF/jpa-changelog-9.0.1.xml	2026-05-21 19:27:21.943888	81	EXECUTED	9:be969f08a163bf47c6b9e9ead8ac2afb	createIndex indexName=IDX_CLIENT_ID, tableName=CLIENT		\N	4.33.0	\N	\N	9391638388
9.0.1-KEYCLOAK-12579-drop-constraints	keycloak	META-INF/jpa-changelog-9.0.1.xml	2026-05-21 19:27:21.944479	82	MARK_RAN	9:6d3bb4408ba5a72f39bd8a0b301ec6e3	dropUniqueConstraint constraintName=SIBLING_NAMES, tableName=KEYCLOAK_GROUP		\N	4.33.0	\N	\N	9391638388
9.0.1-KEYCLOAK-12579-add-not-null-constraint	keycloak	META-INF/jpa-changelog-9.0.1.xml	2026-05-21 19:27:21.946647	83	EXECUTED	9:966bda61e46bebf3cc39518fbed52fa7	addNotNullConstraint columnName=PARENT_GROUP, tableName=KEYCLOAK_GROUP		\N	4.33.0	\N	\N	9391638388
9.0.1-KEYCLOAK-12579-recreate-constraints	keycloak	META-INF/jpa-changelog-9.0.1.xml	2026-05-21 19:27:21.947149	84	MARK_RAN	9:8dcac7bdf7378e7d823cdfddebf72fda	addUniqueConstraint constraintName=SIBLING_NAMES, tableName=KEYCLOAK_GROUP		\N	4.33.0	\N	\N	9391638388
9.0.1-add-index-to-events	keycloak	META-INF/jpa-changelog-9.0.1.xml	2026-05-21 19:27:21.967436	85	EXECUTED	9:7d93d602352a30c0c317e6a609b56599	createIndex indexName=IDX_EVENT_TIME, tableName=EVENT_ENTITY		\N	4.33.0	\N	\N	9391638388
map-remove-ri	keycloak	META-INF/jpa-changelog-11.0.0.xml	2026-05-21 19:27:21.968955	86	EXECUTED	9:71c5969e6cdd8d7b6f47cebc86d37627	dropForeignKeyConstraint baseTableName=REALM, constraintName=FK_TRAF444KK6QRKMS7N56AIWQ5Y; dropForeignKeyConstraint baseTableName=KEYCLOAK_ROLE, constraintName=FK_KJHO5LE2C0RAL09FL8CM9WFW9		\N	4.33.0	\N	\N	9391638388
map-remove-ri	keycloak	META-INF/jpa-changelog-12.0.0.xml	2026-05-21 19:27:21.971134	87	EXECUTED	9:a9ba7d47f065f041b7da856a81762021	dropForeignKeyConstraint baseTableName=REALM_DEFAULT_GROUPS, constraintName=FK_DEF_GROUPS_GROUP; dropForeignKeyConstraint baseTableName=REALM_DEFAULT_ROLES, constraintName=FK_H4WPD7W4HSOOLNI3H0SW7BTJE; dropForeignKeyConstraint baseTableName=CLIENT...		\N	4.33.0	\N	\N	9391638388
12.1.0-add-realm-localization-table	keycloak	META-INF/jpa-changelog-12.0.0.xml	2026-05-21 19:27:21.973403	88	EXECUTED	9:fffabce2bc01e1a8f5110d5278500065	createTable tableName=REALM_LOCALIZATIONS; addPrimaryKey tableName=REALM_LOCALIZATIONS		\N	4.33.0	\N	\N	9391638388
default-roles	keycloak	META-INF/jpa-changelog-13.0.0.xml	2026-05-21 19:27:21.975345	89	EXECUTED	9:fa8a5b5445e3857f4b010bafb5009957	addColumn tableName=REALM; customChange		\N	4.33.0	\N	\N	9391638388
default-roles-cleanup	keycloak	META-INF/jpa-changelog-13.0.0.xml	2026-05-21 19:27:21.977965	90	EXECUTED	9:67ac3241df9a8582d591c5ed87125f39	dropTable tableName=REALM_DEFAULT_ROLES; dropTable tableName=CLIENT_DEFAULT_ROLES		\N	4.33.0	\N	\N	9391638388
13.0.0-KEYCLOAK-16844	keycloak	META-INF/jpa-changelog-13.0.0.xml	2026-05-21 19:27:21.996251	91	EXECUTED	9:ad1194d66c937e3ffc82386c050ba089	createIndex indexName=IDX_OFFLINE_USS_PRELOAD, tableName=OFFLINE_USER_SESSION		\N	4.33.0	\N	\N	9391638388
map-remove-ri-13.0.0	keycloak	META-INF/jpa-changelog-13.0.0.xml	2026-05-21 19:27:21.998454	92	EXECUTED	9:d9be619d94af5a2f5d07b9f003543b91	dropForeignKeyConstraint baseTableName=DEFAULT_CLIENT_SCOPE, constraintName=FK_R_DEF_CLI_SCOPE_SCOPE; dropForeignKeyConstraint baseTableName=CLIENT_SCOPE_CLIENT, constraintName=FK_C_CLI_SCOPE_SCOPE; dropForeignKeyConstraint baseTableName=CLIENT_SC...		\N	4.33.0	\N	\N	9391638388
13.0.0-KEYCLOAK-17992-drop-constraints	keycloak	META-INF/jpa-changelog-13.0.0.xml	2026-05-21 19:27:21.998954	93	MARK_RAN	9:544d201116a0fcc5a5da0925fbbc3bde	dropPrimaryKey constraintName=C_CLI_SCOPE_BIND, tableName=CLIENT_SCOPE_CLIENT; dropIndex indexName=IDX_CLSCOPE_CL, tableName=CLIENT_SCOPE_CLIENT; dropIndex indexName=IDX_CL_CLSCOPE, tableName=CLIENT_SCOPE_CLIENT		\N	4.33.0	\N	\N	9391638388
13.0.0-increase-column-size-federated	keycloak	META-INF/jpa-changelog-13.0.0.xml	2026-05-21 19:27:22.001496	94	EXECUTED	9:43c0c1055b6761b4b3e89de76d612ccf	modifyDataType columnName=CLIENT_ID, tableName=CLIENT_SCOPE_CLIENT; modifyDataType columnName=SCOPE_ID, tableName=CLIENT_SCOPE_CLIENT		\N	4.33.0	\N	\N	9391638388
13.0.0-KEYCLOAK-17992-recreate-constraints	keycloak	META-INF/jpa-changelog-13.0.0.xml	2026-05-21 19:27:22.002076	95	MARK_RAN	9:8bd711fd0330f4fe980494ca43ab1139	addNotNullConstraint columnName=CLIENT_ID, tableName=CLIENT_SCOPE_CLIENT; addNotNullConstraint columnName=SCOPE_ID, tableName=CLIENT_SCOPE_CLIENT; addPrimaryKey constraintName=C_CLI_SCOPE_BIND, tableName=CLIENT_SCOPE_CLIENT; createIndex indexName=...		\N	4.33.0	\N	\N	9391638388
json-string-accomodation-fixed	keycloak	META-INF/jpa-changelog-13.0.0.xml	2026-05-21 19:27:22.004084	96	EXECUTED	9:e07d2bc0970c348bb06fb63b1f82ddbf	addColumn tableName=REALM_ATTRIBUTE; update tableName=REALM_ATTRIBUTE; dropColumn columnName=VALUE, tableName=REALM_ATTRIBUTE; renameColumn newColumnName=VALUE, oldColumnName=VALUE_NEW, tableName=REALM_ATTRIBUTE		\N	4.33.0	\N	\N	9391638388
14.0.0-KEYCLOAK-11019	keycloak	META-INF/jpa-changelog-14.0.0.xml	2026-05-21 19:27:22.057749	97	EXECUTED	9:24fb8611e97f29989bea412aa38d12b7	createIndex indexName=IDX_OFFLINE_CSS_PRELOAD, tableName=OFFLINE_CLIENT_SESSION; createIndex indexName=IDX_OFFLINE_USS_BY_USER, tableName=OFFLINE_USER_SESSION; createIndex indexName=IDX_OFFLINE_USS_BY_USERSESS, tableName=OFFLINE_USER_SESSION		\N	4.33.0	\N	\N	9391638388
14.0.0-KEYCLOAK-18286	keycloak	META-INF/jpa-changelog-14.0.0.xml	2026-05-21 19:27:22.058488	98	MARK_RAN	9:259f89014ce2506ee84740cbf7163aa7	createIndex indexName=IDX_CLIENT_ATT_BY_NAME_VALUE, tableName=CLIENT_ATTRIBUTES		\N	4.33.0	\N	\N	9391638388
14.0.0-KEYCLOAK-18286-revert	keycloak	META-INF/jpa-changelog-14.0.0.xml	2026-05-21 19:27:22.064322	99	MARK_RAN	9:04baaf56c116ed19951cbc2cca584022	dropIndex indexName=IDX_CLIENT_ATT_BY_NAME_VALUE, tableName=CLIENT_ATTRIBUTES		\N	4.33.0	\N	\N	9391638388
14.0.0-KEYCLOAK-18286-supported-dbs	keycloak	META-INF/jpa-changelog-14.0.0.xml	2026-05-21 19:27:22.085518	100	EXECUTED	9:60ca84a0f8c94ec8c3504a5a3bc88ee8	createIndex indexName=IDX_CLIENT_ATT_BY_NAME_VALUE, tableName=CLIENT_ATTRIBUTES		\N	4.33.0	\N	\N	9391638388
14.0.0-KEYCLOAK-18286-unsupported-dbs	keycloak	META-INF/jpa-changelog-14.0.0.xml	2026-05-21 19:27:22.086141	101	MARK_RAN	9:d3d977031d431db16e2c181ce49d73e9	createIndex indexName=IDX_CLIENT_ATT_BY_NAME_VALUE, tableName=CLIENT_ATTRIBUTES		\N	4.33.0	\N	\N	9391638388
KEYCLOAK-17267-add-index-to-user-attributes	keycloak	META-INF/jpa-changelog-14.0.0.xml	2026-05-21 19:27:22.106879	102	EXECUTED	9:0b305d8d1277f3a89a0a53a659ad274c	createIndex indexName=IDX_USER_ATTRIBUTE_NAME, tableName=USER_ATTRIBUTE		\N	4.33.0	\N	\N	9391638388
KEYCLOAK-18146-add-saml-art-binding-identifier	keycloak	META-INF/jpa-changelog-14.0.0.xml	2026-05-21 19:27:22.108538	103	EXECUTED	9:2c374ad2cdfe20e2905a84c8fac48460	customChange		\N	4.33.0	\N	\N	9391638388
15.0.0-KEYCLOAK-18467	keycloak	META-INF/jpa-changelog-15.0.0.xml	2026-05-21 19:27:22.110541	104	EXECUTED	9:47a760639ac597360a8219f5b768b4de	addColumn tableName=REALM_LOCALIZATIONS; update tableName=REALM_LOCALIZATIONS; dropColumn columnName=TEXTS, tableName=REALM_LOCALIZATIONS; renameColumn newColumnName=TEXTS, oldColumnName=TEXTS_NEW, tableName=REALM_LOCALIZATIONS; addNotNullConstrai...		\N	4.33.0	\N	\N	9391638388
17.0.0-9562	keycloak	META-INF/jpa-changelog-17.0.0.xml	2026-05-21 19:27:22.129033	105	EXECUTED	9:a6272f0576727dd8cad2522335f5d99e	createIndex indexName=IDX_USER_SERVICE_ACCOUNT, tableName=USER_ENTITY		\N	4.33.0	\N	\N	9391638388
18.0.0-10625-IDX_ADMIN_EVENT_TIME	keycloak	META-INF/jpa-changelog-18.0.0.xml	2026-05-21 19:27:22.146101	106	EXECUTED	9:015479dbd691d9cc8669282f4828c41d	createIndex indexName=IDX_ADMIN_EVENT_TIME, tableName=ADMIN_EVENT_ENTITY		\N	4.33.0	\N	\N	9391638388
18.0.15-30992-index-consent	keycloak	META-INF/jpa-changelog-18.0.15.xml	2026-05-21 19:27:22.166403	107	EXECUTED	9:80071ede7a05604b1f4906f3bf3b00f0	createIndex indexName=IDX_USCONSENT_SCOPE_ID, tableName=USER_CONSENT_CLIENT_SCOPE		\N	4.33.0	\N	\N	9391638388
19.0.0-10135	keycloak	META-INF/jpa-changelog-19.0.0.xml	2026-05-21 19:27:22.168163	108	EXECUTED	9:9518e495fdd22f78ad6425cc30630221	customChange		\N	4.33.0	\N	\N	9391638388
20.0.0-12964-supported-dbs	keycloak	META-INF/jpa-changelog-20.0.0.xml	2026-05-21 19:27:22.186833	109	EXECUTED	9:e5f243877199fd96bcc842f27a1656ac	createIndex indexName=IDX_GROUP_ATT_BY_NAME_VALUE, tableName=GROUP_ATTRIBUTE		\N	4.33.0	\N	\N	9391638388
20.0.0-12964-supported-dbs-edb-migration	keycloak	META-INF/jpa-changelog-20.0.0.xml	2026-05-21 19:27:22.210968	110	EXECUTED	9:a6b18a8e38062df5793edbe064f4aecd	dropIndex indexName=IDX_GROUP_ATT_BY_NAME_VALUE, tableName=GROUP_ATTRIBUTE; createIndex indexName=IDX_GROUP_ATT_BY_NAME_VALUE, tableName=GROUP_ATTRIBUTE		\N	4.33.0	\N	\N	9391638388
20.0.0-12964-unsupported-dbs	keycloak	META-INF/jpa-changelog-20.0.0.xml	2026-05-21 19:27:22.211832	111	MARK_RAN	9:1a6fcaa85e20bdeae0a9ce49b41946a5	createIndex indexName=IDX_GROUP_ATT_BY_NAME_VALUE, tableName=GROUP_ATTRIBUTE		\N	4.33.0	\N	\N	9391638388
client-attributes-string-accomodation-fixed-pre-drop-index	keycloak	META-INF/jpa-changelog-20.0.0.xml	2026-05-21 19:27:22.213656	112	EXECUTED	9:04baaf56c116ed19951cbc2cca584022	dropIndex indexName=IDX_CLIENT_ATT_BY_NAME_VALUE, tableName=CLIENT_ATTRIBUTES		\N	4.33.0	\N	\N	9391638388
client-attributes-string-accomodation-fixed	keycloak	META-INF/jpa-changelog-20.0.0.xml	2026-05-21 19:27:22.215848	113	EXECUTED	9:3f332e13e90739ed0c35b0b25b7822ca	addColumn tableName=CLIENT_ATTRIBUTES; update tableName=CLIENT_ATTRIBUTES; dropColumn columnName=VALUE, tableName=CLIENT_ATTRIBUTES; renameColumn newColumnName=VALUE, oldColumnName=VALUE_NEW, tableName=CLIENT_ATTRIBUTES		\N	4.33.0	\N	\N	9391638388
client-attributes-string-accomodation-fixed-post-create-index	keycloak	META-INF/jpa-changelog-20.0.0.xml	2026-05-21 19:27:22.216499	114	MARK_RAN	9:bd2bd0fc7768cf0845ac96a8786fa735	createIndex indexName=IDX_CLIENT_ATT_BY_NAME_VALUE, tableName=CLIENT_ATTRIBUTES		\N	4.33.0	\N	\N	9391638388
21.0.2-17277	keycloak	META-INF/jpa-changelog-21.0.2.xml	2026-05-21 19:27:22.218246	115	EXECUTED	9:7ee1f7a3fb8f5588f171fb9a6ab623c0	customChange		\N	4.33.0	\N	\N	9391638388
21.1.0-19404	keycloak	META-INF/jpa-changelog-21.1.0.xml	2026-05-21 19:27:22.221937	116	EXECUTED	9:3d7e830b52f33676b9d64f7f2b2ea634	modifyDataType columnName=DECISION_STRATEGY, tableName=RESOURCE_SERVER_POLICY; modifyDataType columnName=LOGIC, tableName=RESOURCE_SERVER_POLICY; modifyDataType columnName=POLICY_ENFORCE_MODE, tableName=RESOURCE_SERVER		\N	4.33.0	\N	\N	9391638388
21.1.0-19404-2	keycloak	META-INF/jpa-changelog-21.1.0.xml	2026-05-21 19:27:22.223277	117	MARK_RAN	9:627d032e3ef2c06c0e1f73d2ae25c26c	addColumn tableName=RESOURCE_SERVER_POLICY; update tableName=RESOURCE_SERVER_POLICY; dropColumn columnName=DECISION_STRATEGY, tableName=RESOURCE_SERVER_POLICY; renameColumn newColumnName=DECISION_STRATEGY, oldColumnName=DECISION_STRATEGY_NEW, tabl...		\N	4.33.0	\N	\N	9391638388
22.0.0-17484-updated	keycloak	META-INF/jpa-changelog-22.0.0.xml	2026-05-21 19:27:22.225062	118	EXECUTED	9:90af0bfd30cafc17b9f4d6eccd92b8b3	customChange		\N	4.33.0	\N	\N	9391638388
23.0.0-12062	keycloak	META-INF/jpa-changelog-23.0.0.xml	2026-05-21 19:27:22.227451	120	EXECUTED	9:2168fbe728fec46ae9baf15bf80927b8	addColumn tableName=COMPONENT_CONFIG; update tableName=COMPONENT_CONFIG; dropColumn columnName=VALUE, tableName=COMPONENT_CONFIG; renameColumn newColumnName=VALUE, oldColumnName=VALUE_NEW, tableName=COMPONENT_CONFIG		\N	4.33.0	\N	\N	9391638388
23.0.0-17258	keycloak	META-INF/jpa-changelog-23.0.0.xml	2026-05-21 19:27:22.22848	121	EXECUTED	9:36506d679a83bbfda85a27ea1864dca8	addColumn tableName=EVENT_ENTITY		\N	4.33.0	\N	\N	9391638388
24.0.0-9758	keycloak	META-INF/jpa-changelog-24.0.0.xml	2026-05-21 19:27:22.30159	122	EXECUTED	9:502c557a5189f600f0f445a9b49ebbce	addColumn tableName=USER_ATTRIBUTE; addColumn tableName=FED_USER_ATTRIBUTE; createIndex indexName=USER_ATTR_LONG_VALUES, tableName=USER_ATTRIBUTE; createIndex indexName=FED_USER_ATTR_LONG_VALUES, tableName=FED_USER_ATTRIBUTE; createIndex indexName...		\N	4.33.0	\N	\N	9391638388
24.0.0-9758-2	keycloak	META-INF/jpa-changelog-24.0.0.xml	2026-05-21 19:27:22.303157	123	EXECUTED	9:bf0fdee10afdf597a987adbf291db7b2	customChange		\N	4.33.0	\N	\N	9391638388
24.0.0-26618-drop-index-if-present	keycloak	META-INF/jpa-changelog-24.0.0.xml	2026-05-21 19:27:22.305069	124	MARK_RAN	9:04baaf56c116ed19951cbc2cca584022	dropIndex indexName=IDX_CLIENT_ATT_BY_NAME_VALUE, tableName=CLIENT_ATTRIBUTES		\N	4.33.0	\N	\N	9391638388
24.0.0-26618-reindex	keycloak	META-INF/jpa-changelog-24.0.0.xml	2026-05-21 19:27:22.328118	125	EXECUTED	9:08707c0f0db1cef6b352db03a60edc7f	createIndex indexName=IDX_CLIENT_ATT_BY_NAME_VALUE, tableName=CLIENT_ATTRIBUTES		\N	4.33.0	\N	\N	9391638388
24.0.0-26618-edb-migration	keycloak	META-INF/jpa-changelog-24.0.0.xml	2026-05-21 19:27:22.342885	126	EXECUTED	9:2f684b29d414cd47efe3a3599f390741	dropIndex indexName=IDX_CLIENT_ATT_BY_NAME_VALUE, tableName=CLIENT_ATTRIBUTES; createIndex indexName=IDX_CLIENT_ATT_BY_NAME_VALUE, tableName=CLIENT_ATTRIBUTES		\N	4.33.0	\N	\N	9391638388
24.0.2-27228	keycloak	META-INF/jpa-changelog-24.0.2.xml	2026-05-21 19:27:22.344403	127	EXECUTED	9:eaee11f6b8aa25d2cc6a84fb86fc6238	customChange		\N	4.33.0	\N	\N	9391638388
24.0.2-27967-drop-index-if-present	keycloak	META-INF/jpa-changelog-24.0.2.xml	2026-05-21 19:27:22.344942	128	MARK_RAN	9:04baaf56c116ed19951cbc2cca584022	dropIndex indexName=IDX_CLIENT_ATT_BY_NAME_VALUE, tableName=CLIENT_ATTRIBUTES		\N	4.33.0	\N	\N	9391638388
24.0.2-27967-reindex	keycloak	META-INF/jpa-changelog-24.0.2.xml	2026-05-21 19:27:22.345553	129	MARK_RAN	9:d3d977031d431db16e2c181ce49d73e9	createIndex indexName=IDX_CLIENT_ATT_BY_NAME_VALUE, tableName=CLIENT_ATTRIBUTES		\N	4.33.0	\N	\N	9391638388
25.0.0-28265-tables	keycloak	META-INF/jpa-changelog-25.0.0.xml	2026-05-21 19:27:22.346991	130	EXECUTED	9:deda2df035df23388af95bbd36c17cef	addColumn tableName=OFFLINE_USER_SESSION; addColumn tableName=OFFLINE_CLIENT_SESSION		\N	4.33.0	\N	\N	9391638388
25.0.0-28265-index-creation	keycloak	META-INF/jpa-changelog-25.0.0.xml	2026-05-21 19:27:22.359731	131	EXECUTED	9:3e96709818458ae49f3c679ae58d263a	createIndex indexName=IDX_OFFLINE_USS_BY_LAST_SESSION_REFRESH, tableName=OFFLINE_USER_SESSION		\N	4.33.0	\N	\N	9391638388
25.0.0-28265-index-cleanup-uss-createdon	keycloak	META-INF/jpa-changelog-25.0.0.xml	2026-05-21 19:27:22.362171	132	EXECUTED	9:78ab4fc129ed5e8265dbcc3485fba92f	dropIndex indexName=IDX_OFFLINE_USS_CREATEDON, tableName=OFFLINE_USER_SESSION		\N	4.33.0	\N	\N	9391638388
25.0.0-28265-index-cleanup-uss-preload	keycloak	META-INF/jpa-changelog-25.0.0.xml	2026-05-21 19:27:22.364287	133	EXECUTED	9:de5f7c1f7e10994ed8b62e621d20eaab	dropIndex indexName=IDX_OFFLINE_USS_PRELOAD, tableName=OFFLINE_USER_SESSION		\N	4.33.0	\N	\N	9391638388
25.0.0-28265-index-cleanup-uss-by-usersess	keycloak	META-INF/jpa-changelog-25.0.0.xml	2026-05-21 19:27:22.366391	134	EXECUTED	9:6eee220d024e38e89c799417ec33667f	dropIndex indexName=IDX_OFFLINE_USS_BY_USERSESS, tableName=OFFLINE_USER_SESSION		\N	4.33.0	\N	\N	9391638388
25.0.0-28265-index-cleanup-css-preload	keycloak	META-INF/jpa-changelog-25.0.0.xml	2026-05-21 19:27:22.368665	135	EXECUTED	9:5411d2fb2891d3e8d63ddb55dfa3c0c9	dropIndex indexName=IDX_OFFLINE_CSS_PRELOAD, tableName=OFFLINE_CLIENT_SESSION		\N	4.33.0	\N	\N	9391638388
25.0.0-28265-index-2-mysql	keycloak	META-INF/jpa-changelog-25.0.0.xml	2026-05-21 19:27:22.369243	136	MARK_RAN	9:b7ef76036d3126bb83c2423bf4d449d6	createIndex indexName=IDX_OFFLINE_USS_BY_BROKER_SESSION_ID, tableName=OFFLINE_USER_SESSION		\N	4.33.0	\N	\N	9391638388
25.0.0-28265-index-2-not-mysql	keycloak	META-INF/jpa-changelog-25.0.0.xml	2026-05-21 19:27:22.383318	137	EXECUTED	9:23396cf51ab8bc1ae6f0cac7f9f6fcf7	createIndex indexName=IDX_OFFLINE_USS_BY_BROKER_SESSION_ID, tableName=OFFLINE_USER_SESSION		\N	4.33.0	\N	\N	9391638388
25.0.0-org	keycloak	META-INF/jpa-changelog-25.0.0.xml	2026-05-21 19:27:22.387216	138	EXECUTED	9:5c859965c2c9b9c72136c360649af157	createTable tableName=ORG; addUniqueConstraint constraintName=UK_ORG_NAME, tableName=ORG; addUniqueConstraint constraintName=UK_ORG_GROUP, tableName=ORG; createTable tableName=ORG_DOMAIN		\N	4.33.0	\N	\N	9391638388
unique-consentuser	keycloak	META-INF/jpa-changelog-25.0.0.xml	2026-05-21 19:27:22.390139	139	EXECUTED	9:5857626a2ea8767e9a6c66bf3a2cb32f	customChange; dropUniqueConstraint constraintName=UK_JKUWUVD56ONTGSUHOGM8UEWRT, tableName=USER_CONSENT; addUniqueConstraint constraintName=UK_LOCAL_CONSENT, tableName=USER_CONSENT; addUniqueConstraint constraintName=UK_EXTERNAL_CONSENT, tableName=...		\N	4.33.0	\N	\N	9391638388
unique-consentuser-edb-migration	keycloak	META-INF/jpa-changelog-25.0.0.xml	2026-05-21 19:27:22.39293	140	MARK_RAN	9:5857626a2ea8767e9a6c66bf3a2cb32f	customChange; dropUniqueConstraint constraintName=UK_JKUWUVD56ONTGSUHOGM8UEWRT, tableName=USER_CONSENT; addUniqueConstraint constraintName=UK_LOCAL_CONSENT, tableName=USER_CONSENT; addUniqueConstraint constraintName=UK_EXTERNAL_CONSENT, tableName=...		\N	4.33.0	\N	\N	9391638388
unique-consentuser-mysql	keycloak	META-INF/jpa-changelog-25.0.0.xml	2026-05-21 19:27:22.39369	141	MARK_RAN	9:b79478aad5adaa1bc428e31563f55e8e	customChange; dropUniqueConstraint constraintName=UK_JKUWUVD56ONTGSUHOGM8UEWRT, tableName=USER_CONSENT; addUniqueConstraint constraintName=UK_LOCAL_CONSENT, tableName=USER_CONSENT; addUniqueConstraint constraintName=UK_EXTERNAL_CONSENT, tableName=...		\N	4.33.0	\N	\N	9391638388
25.0.0-28861-index-creation	keycloak	META-INF/jpa-changelog-25.0.0.xml	2026-05-21 19:27:22.422595	142	EXECUTED	9:b9acb58ac958d9ada0fe12a5d4794ab1	createIndex indexName=IDX_PERM_TICKET_REQUESTER, tableName=RESOURCE_SERVER_PERM_TICKET; createIndex indexName=IDX_PERM_TICKET_OWNER, tableName=RESOURCE_SERVER_PERM_TICKET		\N	4.33.0	\N	\N	9391638388
26.0.0-org-alias	keycloak	META-INF/jpa-changelog-26.0.0.xml	2026-05-21 19:27:22.425366	143	EXECUTED	9:6ef7d63e4412b3c2d66ed179159886a4	addColumn tableName=ORG; update tableName=ORG; addNotNullConstraint columnName=ALIAS, tableName=ORG; addUniqueConstraint constraintName=UK_ORG_ALIAS, tableName=ORG		\N	4.33.0	\N	\N	9391638388
26.0.0-org-group	keycloak	META-INF/jpa-changelog-26.0.0.xml	2026-05-21 19:27:22.427783	144	EXECUTED	9:da8e8087d80ef2ace4f89d8c5b9ca223	addColumn tableName=KEYCLOAK_GROUP; update tableName=KEYCLOAK_GROUP; addNotNullConstraint columnName=TYPE, tableName=KEYCLOAK_GROUP; customChange		\N	4.33.0	\N	\N	9391638388
26.0.0-org-indexes	keycloak	META-INF/jpa-changelog-26.0.0.xml	2026-05-21 19:27:22.440537	145	EXECUTED	9:79b05dcd610a8c7f25ec05135eec0857	createIndex indexName=IDX_ORG_DOMAIN_ORG_ID, tableName=ORG_DOMAIN		\N	4.33.0	\N	\N	9391638388
26.0.0-org-group-membership	keycloak	META-INF/jpa-changelog-26.0.0.xml	2026-05-21 19:27:22.442126	146	EXECUTED	9:a6ace2ce583a421d89b01ba2a28dc2d4	addColumn tableName=USER_GROUP_MEMBERSHIP; update tableName=USER_GROUP_MEMBERSHIP; addNotNullConstraint columnName=MEMBERSHIP_TYPE, tableName=USER_GROUP_MEMBERSHIP		\N	4.33.0	\N	\N	9391638388
31296-persist-revoked-access-tokens	keycloak	META-INF/jpa-changelog-26.0.0.xml	2026-05-21 19:27:22.443604	147	EXECUTED	9:64ef94489d42a358e8304b0e245f0ed4	createTable tableName=REVOKED_TOKEN; addPrimaryKey constraintName=CONSTRAINT_RT, tableName=REVOKED_TOKEN		\N	4.33.0	\N	\N	9391638388
31725-index-persist-revoked-access-tokens	keycloak	META-INF/jpa-changelog-26.0.0.xml	2026-05-21 19:27:22.455296	148	EXECUTED	9:b994246ec2bf7c94da881e1d28782c7b	createIndex indexName=IDX_REV_TOKEN_ON_EXPIRE, tableName=REVOKED_TOKEN		\N	4.33.0	\N	\N	9391638388
26.0.0-idps-for-login	keycloak	META-INF/jpa-changelog-26.0.0.xml	2026-05-21 19:27:22.484169	149	EXECUTED	9:51f5fffadf986983d4bd59582c6c1604	addColumn tableName=IDENTITY_PROVIDER; createIndex indexName=IDX_IDP_REALM_ORG, tableName=IDENTITY_PROVIDER; createIndex indexName=IDX_IDP_FOR_LOGIN, tableName=IDENTITY_PROVIDER; customChange		\N	4.33.0	\N	\N	9391638388
26.0.0-32583-drop-redundant-index-on-client-session	keycloak	META-INF/jpa-changelog-26.0.0.xml	2026-05-21 19:27:22.486931	150	EXECUTED	9:24972d83bf27317a055d234187bb4af9	dropIndex indexName=IDX_US_SESS_ID_ON_CL_SESS, tableName=OFFLINE_CLIENT_SESSION		\N	4.33.0	\N	\N	9391638388
26.0.0.32582-remove-tables-user-session-user-session-note-and-client-session	keycloak	META-INF/jpa-changelog-26.0.0.xml	2026-05-21 19:27:22.491147	151	EXECUTED	9:febdc0f47f2ed241c59e60f58c3ceea5	dropTable tableName=CLIENT_SESSION_ROLE; dropTable tableName=CLIENT_SESSION_NOTE; dropTable tableName=CLIENT_SESSION_PROT_MAPPER; dropTable tableName=CLIENT_SESSION_AUTH_STATUS; dropTable tableName=CLIENT_USER_SESSION_NOTE; dropTable tableName=CLI...		\N	4.33.0	\N	\N	9391638388
26.0.0-33201-org-redirect-url	keycloak	META-INF/jpa-changelog-26.0.0.xml	2026-05-21 19:27:22.492251	152	EXECUTED	9:4d0e22b0ac68ebe9794fa9cb752ea660	addColumn tableName=ORG		\N	4.33.0	\N	\N	9391638388
29399-jdbc-ping-default	keycloak	META-INF/jpa-changelog-26.1.0.xml	2026-05-21 19:27:22.494328	153	EXECUTED	9:007dbe99d7203fca403b89d4edfdf21e	createTable tableName=JGROUPS_PING; addPrimaryKey constraintName=CONSTRAINT_JGROUPS_PING, tableName=JGROUPS_PING		\N	4.33.0	\N	\N	9391638388
26.1.0-34013	keycloak	META-INF/jpa-changelog-26.1.0.xml	2026-05-21 19:27:22.496087	154	EXECUTED	9:e6b686a15759aef99a6d758a5c4c6a26	addColumn tableName=ADMIN_EVENT_ENTITY		\N	4.33.0	\N	\N	9391638388
26.1.0-34380	keycloak	META-INF/jpa-changelog-26.1.0.xml	2026-05-21 19:27:22.498474	155	EXECUTED	9:ac8b9edb7c2b6c17a1c7a11fcf5ccf01	dropTable tableName=USERNAME_LOGIN_FAILURE		\N	4.33.0	\N	\N	9391638388
26.2.0-36750	keycloak	META-INF/jpa-changelog-26.2.0.xml	2026-05-21 19:27:22.500532	156	EXECUTED	9:b49ce951c22f7eb16480ff085640a33a	createTable tableName=SERVER_CONFIG		\N	4.33.0	\N	\N	9391638388
26.2.0-26106	keycloak	META-INF/jpa-changelog-26.2.0.xml	2026-05-21 19:27:22.501627	157	EXECUTED	9:b5877d5dab7d10ff3a9d209d7beb6680	addColumn tableName=CREDENTIAL		\N	4.33.0	\N	\N	9391638388
26.2.6-39866-duplicate	keycloak	META-INF/jpa-changelog-26.2.6.xml	2026-05-21 19:27:22.50313	158	EXECUTED	9:1dc67ccee24f30331db2cba4f372e40e	customChange		\N	4.33.0	\N	\N	9391638388
26.2.6-39866-uk	keycloak	META-INF/jpa-changelog-26.2.6.xml	2026-05-21 19:27:22.504552	159	EXECUTED	9:b70b76f47210cf0a5f4ef0e219eac7cd	addUniqueConstraint constraintName=UK_MIGRATION_VERSION, tableName=MIGRATION_MODEL		\N	4.33.0	\N	\N	9391638388
26.2.6-40088-duplicate	keycloak	META-INF/jpa-changelog-26.2.6.xml	2026-05-21 19:27:22.505963	160	EXECUTED	9:cc7e02ed69ab31979afb1982f9670e8f	customChange		\N	4.33.0	\N	\N	9391638388
26.2.6-40088-uk	keycloak	META-INF/jpa-changelog-26.2.6.xml	2026-05-21 19:27:22.506937	161	EXECUTED	9:5bb848128da7bc4595cc507383325241	addUniqueConstraint constraintName=UK_MIGRATION_UPDATE_TIME, tableName=MIGRATION_MODEL		\N	4.33.0	\N	\N	9391638388
26.3.0-groups-description	keycloak	META-INF/jpa-changelog-26.3.0.xml	2026-05-21 19:27:22.508527	162	EXECUTED	9:e1a3c05574326fb5b246b73b9a4c4d49	addColumn tableName=KEYCLOAK_GROUP		\N	4.33.0	\N	\N	9391638388
26.4.0-40933-saml-encryption-attributes	keycloak	META-INF/jpa-changelog-26.4.0.xml	2026-05-21 19:27:22.509815	163	EXECUTED	9:7e9eaba362ca105efdda202303a4fe49	customChange		\N	4.33.0	\N	\N	9391638388
26.4.0-51321	keycloak	META-INF/jpa-changelog-26.4.0.xml	2026-05-21 19:27:22.521753	164	EXECUTED	9:34bab2bc56f75ffd7e347c580874e306	createIndex indexName=IDX_EVENT_ENTITY_USER_ID_TYPE, tableName=EVENT_ENTITY		\N	4.33.0	\N	\N	9391638388
40343-workflow-state-table	keycloak	META-INF/jpa-changelog-26.4.0.xml	2026-05-21 19:27:22.544616	165	EXECUTED	9:ed3ab4723ceed210e5b5e60ac4562106	createTable tableName=WORKFLOW_STATE; addPrimaryKey constraintName=PK_WORKFLOW_STATE, tableName=WORKFLOW_STATE; addUniqueConstraint constraintName=UQ_WORKFLOW_RESOURCE, tableName=WORKFLOW_STATE; createIndex indexName=IDX_WORKFLOW_STATE_STEP, table...		\N	4.33.0	\N	\N	9391638388
26.5.0-index-offline-css-by-client	keycloak	META-INF/jpa-changelog-26.5.0.xml	2026-05-21 19:27:22.558525	166	EXECUTED	9:383e981ce95d16e32af757b7998820f7	createIndex indexName=IDX_OFFLINE_CSS_BY_CLIENT, tableName=OFFLINE_CLIENT_SESSION		\N	4.33.0	\N	\N	9391638388
26.5.0-index-offline-css-by-client-storage-provider	keycloak	META-INF/jpa-changelog-26.5.0.xml	2026-05-21 19:27:22.572588	167	EXECUTED	9:f5bc200e6fa7d7e483854dee535ca425	createIndex indexName=IDX_OFFLINE_CSS_BY_CLIENT_STORAGE_PROVIDER, tableName=OFFLINE_CLIENT_SESSION		\N	4.33.0	\N	\N	9391638388
26.5.0-idp-config-allow-null-fixed-drop-mssql-index	keycloak	META-INF/jpa-changelog-26.5.0.xml	2026-05-21 19:27:22.57315	168	MARK_RAN	9:50c51d2c98cd1d624eb1c485c3cf1f75	dropIndex indexName=IDX_IDP_FOR_LOGIN, tableName=IDENTITY_PROVIDER		\N	4.33.0	\N	\N	9391638388
26.5.0-idp-config-allow-null	keycloak	META-INF/jpa-changelog-26.5.0.xml	2026-05-21 19:27:22.575766	169	EXECUTED	9:b667fb087874303b324c1af7fae4f606	dropDefaultValue columnName=TRUST_EMAIL, tableName=IDENTITY_PROVIDER; dropNotNullConstraint columnName=TRUST_EMAIL, tableName=IDENTITY_PROVIDER; dropNotNullConstraint columnName=STORE_TOKEN, tableName=IDENTITY_PROVIDER; dropDefaultValue columnName...		\N	4.33.0	\N	\N	9391638388
26.5.0-idp-config-allow-null-fixed-create-mssql-index	keycloak	META-INF/jpa-changelog-26.5.0.xml	2026-05-21 19:27:22.576373	170	MARK_RAN	9:dcbbb24c151c3b0b59f12fede23cc94d	createIndex indexName=IDX_IDP_FOR_LOGIN, tableName=IDENTITY_PROVIDER		\N	4.33.0	\N	\N	9391638388
26.5.0-remove-workflow-provider-id-column	keycloak	META-INF/jpa-changelog-26.5.0.xml	2026-05-21 19:27:22.593471	171	EXECUTED	9:d8eeb324484d45e946d03b953e168b21	dropIndex indexName=IDX_WORKFLOW_STATE_PROVIDER, tableName=WORKFLOW_STATE; createIndex indexName=IDX_WORKFLOW_STATE_PROVIDER, tableName=WORKFLOW_STATE; dropColumn columnName=WORKFLOW_PROVIDER_ID, tableName=WORKFLOW_STATE		\N	4.33.0	\N	\N	9391638388
26.5.0-add-remember-me	keycloak	META-INF/jpa-changelog-26.5.0.xml	2026-05-21 19:27:22.595824	172	EXECUTED	9:a7273ea8b21bd2f674c9c49141999f05	addColumn tableName=OFFLINE_USER_SESSION		\N	4.33.0	\N	\N	9391638388
26.5.0-add-sess-refresh-idx	keycloak	META-INF/jpa-changelog-26.5.0.xml	2026-05-21 19:27:22.611032	173	EXECUTED	9:ce49383d317ccbcd3434d1f21172b0b7	createIndex indexName=IDX_USER_SESSION_EXPIRATION_CREATED, tableName=OFFLINE_USER_SESSION		\N	4.33.0	\N	\N	9391638388
26.5.0-add-sess-create-idx	keycloak	META-INF/jpa-changelog-26.5.0.xml	2026-05-21 19:27:22.624339	174	EXECUTED	9:aaee09e23a4d8468fbc5c51b7b314c58	createIndex indexName=IDX_USER_SESSION_EXPIRATION_LAST_REFRESH, tableName=OFFLINE_USER_SESSION		\N	4.33.0	\N	\N	9391638388
26.5.0-drop-sess-refresh-idx	keycloak	META-INF/jpa-changelog-26.5.0.xml	2026-05-21 19:27:22.626836	175	EXECUTED	9:f0082210b6ccbbaf81287c27aa23753c	dropIndex indexName=IDX_OFFLINE_USS_BY_LAST_SESSION_REFRESH, tableName=OFFLINE_USER_SESSION		\N	4.33.0	\N	\N	9391638388
26.5.0-mysql-mariadb-default-charset-collation	keycloak	META-INF/jpa-changelog-26.5.0.xml	2026-05-21 19:27:22.627286	176	MARK_RAN	9:1b383fa60d2db0a8952b365e725f9d16	customChange		\N	4.33.0	\N	\N	9391638388
26.5.0-invitations-table-fixed2	keycloak	META-INF/jpa-changelog-26.5.0.xml	2026-05-21 19:27:22.666076	177	EXECUTED	9:322cb11fc03181903dcd67a54f8b3cf0	createTable tableName=ORG_INVITATION; addForeignKeyConstraint baseTableName=ORG_INVITATION, constraintName=FK_ORG_INVITATION_ORG, referencedTableName=ORG; createIndex indexName=IDX_ORG_INVITATION_ORG_ID, tableName=ORG_INVITATION; createIndex index...		\N	4.33.0	\N	\N	9391638388
26.6.0-45009-broker-link-user-id	keycloak	META-INF/jpa-changelog-26.6.0.xml	2026-05-21 19:27:22.67893	178	EXECUTED	9:05026bbbc8d2ead5afcbda2f5fdf3a2b	createIndex indexName=IDX_BROKER_LINK_USER_ID, tableName=BROKER_LINK		\N	4.33.0	\N	\N	9391638388
26.6.0-45009-broker-link-identity-provider	keycloak	META-INF/jpa-changelog-26.6.0.xml	2026-05-21 19:27:22.69151	179	EXECUTED	9:7d9a0253c9de7be754efef8bba4265bd	createIndex indexName=IDX_BROKER_LINK_IDENTITY_PROVIDER, tableName=BROKER_LINK		\N	4.33.0	\N	\N	9391638388
\.


--
-- Data for Name: databasechangeloglock; Type: TABLE DATA; Schema: public; Owner: keycloak
--

COPY public.databasechangeloglock (id, locked, lockgranted, lockedby) FROM stdin;
1	f	\N	\N
1000	f	\N	\N
\.


--
-- Data for Name: default_client_scope; Type: TABLE DATA; Schema: public; Owner: keycloak
--

COPY public.default_client_scope (realm_id, scope_id, default_scope) FROM stdin;
86b2aa03-1225-4835-8758-60f4e03293c9	c6794528-0a18-4fce-9988-f5f85635837c	f
86b2aa03-1225-4835-8758-60f4e03293c9	e2ea9eef-0762-4ee6-8b90-04d1abd1316e	t
86b2aa03-1225-4835-8758-60f4e03293c9	2722ccf7-8558-45d3-bd06-84b43c572a3c	t
86b2aa03-1225-4835-8758-60f4e03293c9	94c8b8ed-2c5f-4bdf-ba43-aa08c5fe9192	t
86b2aa03-1225-4835-8758-60f4e03293c9	b1c22975-5e52-4a59-a2d5-c8b654fc6645	t
86b2aa03-1225-4835-8758-60f4e03293c9	2bd86ed4-1786-44b4-b0b6-01fd86b24565	f
86b2aa03-1225-4835-8758-60f4e03293c9	5337c14e-5172-43f9-a2a1-e1bb32385e7f	f
86b2aa03-1225-4835-8758-60f4e03293c9	c9b53021-3bba-4908-90d8-755f38d861c8	t
86b2aa03-1225-4835-8758-60f4e03293c9	4ebd35f2-be54-4a34-bb50-4c1c4f2382f6	t
86b2aa03-1225-4835-8758-60f4e03293c9	2b81c7e8-3993-456b-9341-05ecccfd5112	f
86b2aa03-1225-4835-8758-60f4e03293c9	85e82c50-2d25-4009-bdcf-765a62708f9f	t
86b2aa03-1225-4835-8758-60f4e03293c9	cdba92d9-0fd2-4209-9f7c-e1f6f7ffbec6	t
86b2aa03-1225-4835-8758-60f4e03293c9	e7bf5139-442c-419d-98b9-0833ce102d55	f
6f348afb-6f1f-428c-a4f9-5f8e2374a075	d797387e-1f5c-4232-8e68-f62892491073	t
6f348afb-6f1f-428c-a4f9-5f8e2374a075	337dc738-9720-42e4-8cfa-ca816f3a9c47	t
6f348afb-6f1f-428c-a4f9-5f8e2374a075	0ca5fed1-0041-4acc-b018-b7d4da4c2a9a	t
6f348afb-6f1f-428c-a4f9-5f8e2374a075	e217ed3a-3a19-4548-bbb5-19e9f2642ccd	t
6f348afb-6f1f-428c-a4f9-5f8e2374a075	c672e3cb-0646-46fb-887f-00be5de8a12e	t
6f348afb-6f1f-428c-a4f9-5f8e2374a075	f3daaa09-a5d5-4766-ae71-487c67fc99af	t
6f348afb-6f1f-428c-a4f9-5f8e2374a075	b0edc86e-8c20-4f94-be36-e4a6c7913929	t
6f348afb-6f1f-428c-a4f9-5f8e2374a075	52c605c5-9289-48c4-86bc-d6701a9008d1	f
6f348afb-6f1f-428c-a4f9-5f8e2374a075	49cae1f3-7c12-41d0-8e9a-189daa5b45ff	f
6f348afb-6f1f-428c-a4f9-5f8e2374a075	2bd35aef-70dd-4102-a8a9-f4c7e3135edc	f
6f348afb-6f1f-428c-a4f9-5f8e2374a075	ae433992-c6a6-46ed-89a5-75899f4edc99	f
\.


--
-- Data for Name: event_entity; Type: TABLE DATA; Schema: public; Owner: keycloak
--

COPY public.event_entity (id, client_id, details_json, error, ip_address, realm_id, session_id, event_time, type, user_id, details_json_long_value) FROM stdin;
\.


--
-- Data for Name: fed_user_attribute; Type: TABLE DATA; Schema: public; Owner: keycloak
--

COPY public.fed_user_attribute (id, name, user_id, realm_id, storage_provider_id, value, long_value_hash, long_value_hash_lower_case, long_value) FROM stdin;
\.


--
-- Data for Name: fed_user_consent; Type: TABLE DATA; Schema: public; Owner: keycloak
--

COPY public.fed_user_consent (id, client_id, user_id, realm_id, storage_provider_id, created_date, last_updated_date, client_storage_provider, external_client_id) FROM stdin;
\.


--
-- Data for Name: fed_user_consent_cl_scope; Type: TABLE DATA; Schema: public; Owner: keycloak
--

COPY public.fed_user_consent_cl_scope (user_consent_id, scope_id) FROM stdin;
\.


--
-- Data for Name: fed_user_credential; Type: TABLE DATA; Schema: public; Owner: keycloak
--

COPY public.fed_user_credential (id, salt, type, created_date, user_id, realm_id, storage_provider_id, user_label, secret_data, credential_data, priority) FROM stdin;
\.


--
-- Data for Name: fed_user_group_membership; Type: TABLE DATA; Schema: public; Owner: keycloak
--

COPY public.fed_user_group_membership (group_id, user_id, realm_id, storage_provider_id) FROM stdin;
\.


--
-- Data for Name: fed_user_required_action; Type: TABLE DATA; Schema: public; Owner: keycloak
--

COPY public.fed_user_required_action (required_action, user_id, realm_id, storage_provider_id) FROM stdin;
\.


--
-- Data for Name: fed_user_role_mapping; Type: TABLE DATA; Schema: public; Owner: keycloak
--

COPY public.fed_user_role_mapping (role_id, user_id, realm_id, storage_provider_id) FROM stdin;
\.


--
-- Data for Name: federated_identity; Type: TABLE DATA; Schema: public; Owner: keycloak
--

COPY public.federated_identity (identity_provider, realm_id, federated_user_id, federated_username, token, user_id) FROM stdin;
\.


--
-- Data for Name: federated_user; Type: TABLE DATA; Schema: public; Owner: keycloak
--

COPY public.federated_user (id, storage_provider_id, realm_id) FROM stdin;
\.


--
-- Data for Name: group_attribute; Type: TABLE DATA; Schema: public; Owner: keycloak
--

COPY public.group_attribute (id, name, value, group_id) FROM stdin;
\.


--
-- Data for Name: group_role_mapping; Type: TABLE DATA; Schema: public; Owner: keycloak
--

COPY public.group_role_mapping (role_id, group_id) FROM stdin;
\.


--
-- Data for Name: identity_provider; Type: TABLE DATA; Schema: public; Owner: keycloak
--

COPY public.identity_provider (internal_id, enabled, provider_alias, provider_id, store_token, authenticate_by_default, realm_id, add_token_role, trust_email, first_broker_login_flow_id, post_broker_login_flow_id, provider_display_name, link_only, organization_id, hide_on_login) FROM stdin;
dbb1cc58-03fc-4884-871f-737d7778caa0	t	LSAAI	oidc	f	f	6f348afb-6f1f-428c-a4f9-5f8e2374a075	f	t	c4a0ed65-c0be-4a58-b0a1-a68873949032	\N		f	\N	f
\.


--
-- Data for Name: identity_provider_config; Type: TABLE DATA; Schema: public; Owner: keycloak
--

COPY public.identity_provider_config (identity_provider_id, value, name) FROM stdin;
dbb1cc58-03fc-4884-871f-737d7778caa0	false	validateSignature
dbb1cc58-03fc-4884-871f-737d7778caa0	false	acceptsPromptNoneForwardFromClient
dbb1cc58-03fc-4884-871f-737d7778caa0	https://login.elixir-czech.org/oidc/token	tokenUrl
dbb1cc58-03fc-4884-871f-737d7778caa0	2d61a232-bb61-4844-a69c-53df3c169763	clientId
dbb1cc58-03fc-4884-871f-737d7778caa0	false	uiLocales
dbb1cc58-03fc-4884-871f-737d7778caa0	false	isAccessTokenJWT
dbb1cc58-03fc-4884-871f-737d7778caa0	false	filteredByClaim
dbb1cc58-03fc-4884-871f-737d7778caa0	false	backchannelSupported
dbb1cc58-03fc-4884-871f-737d7778caa0	false	disableNonce
dbb1cc58-03fc-4884-871f-737d7778caa0	false	loginHint
dbb1cc58-03fc-4884-871f-737d7778caa0	false	pkceEnabled
dbb1cc58-03fc-4884-871f-737d7778caa0	client_secret_post	clientAuthMethod
dbb1cc58-03fc-4884-871f-737d7778caa0	https://login.elixir-czech.org/oidc/authorize	authorizationUrl
dbb1cc58-03fc-4884-871f-737d7778caa0	false	disableUserInfo
dbb1cc58-03fc-4884-871f-737d7778caa0	FORCE	syncMode
dbb1cc58-03fc-4884-871f-737d7778caa0	**********	clientSecret
dbb1cc58-03fc-4884-871f-737d7778caa0	false	passMaxAge
dbb1cc58-03fc-4884-871f-737d7778caa0	0	allowedClockSkew
dbb1cc58-03fc-4884-871f-737d7778caa0	openid profile email	defaultScope
\.


--
-- Data for Name: identity_provider_mapper; Type: TABLE DATA; Schema: public; Owner: keycloak
--

COPY public.identity_provider_mapper (id, name, idp_alias, idp_mapper_name, realm_id) FROM stdin;
861afd67-8f5f-4f35-b278-31108f8ecf63	Elixir_ID	LSAAI	oidc-user-attribute-idp-mapper	6f348afb-6f1f-428c-a4f9-5f8e2374a075
\.


--
-- Data for Name: idp_mapper_config; Type: TABLE DATA; Schema: public; Owner: keycloak
--

COPY public.idp_mapper_config (idp_mapper_id, value, name) FROM stdin;
861afd67-8f5f-4f35-b278-31108f8ecf63	FORCE	syncMode
861afd67-8f5f-4f35-b278-31108f8ecf63	sub	claim
861afd67-8f5f-4f35-b278-31108f8ecf63	elixir_id	user.attribute
\.


--
-- Data for Name: jgroups_ping; Type: TABLE DATA; Schema: public; Owner: keycloak
--

COPY public.jgroups_ping (address, name, cluster_name, ip, coord) FROM stdin;
\.


--
-- Data for Name: keycloak_group; Type: TABLE DATA; Schema: public; Owner: keycloak
--

COPY public.keycloak_group (id, name, parent_group, realm_id, type, description) FROM stdin;
\.


--
-- Data for Name: keycloak_role; Type: TABLE DATA; Schema: public; Owner: keycloak
--

COPY public.keycloak_role (id, client_realm_constraint, client_role, description, name, realm_id, client, realm) FROM stdin;
b3054bb8-c40e-4a91-a086-c364629ce753	86b2aa03-1225-4835-8758-60f4e03293c9	f	${role_default-roles}	default-roles-master	86b2aa03-1225-4835-8758-60f4e03293c9	\N	\N
627d0135-adbd-49f5-97a5-3c4c5bd2f6cc	86b2aa03-1225-4835-8758-60f4e03293c9	f	${role_create-realm}	create-realm	86b2aa03-1225-4835-8758-60f4e03293c9	\N	\N
9ec7cdc9-cf2b-4d40-93dc-f89ed5c8a0f2	86b2aa03-1225-4835-8758-60f4e03293c9	f	${role_admin}	admin	86b2aa03-1225-4835-8758-60f4e03293c9	\N	\N
363ad2a8-5d38-4282-9d49-19598d47b3ce	4109f0ef-0360-401b-b3c4-8e8fff5a4c07	t	${role_create-client}	create-client	86b2aa03-1225-4835-8758-60f4e03293c9	4109f0ef-0360-401b-b3c4-8e8fff5a4c07	\N
e020d0c6-0787-442a-92e0-dcee50f7d1bb	4109f0ef-0360-401b-b3c4-8e8fff5a4c07	t	${role_view-realm}	view-realm	86b2aa03-1225-4835-8758-60f4e03293c9	4109f0ef-0360-401b-b3c4-8e8fff5a4c07	\N
59bdc687-35d3-44ed-849c-99c5565fa832	4109f0ef-0360-401b-b3c4-8e8fff5a4c07	t	${role_view-users}	view-users	86b2aa03-1225-4835-8758-60f4e03293c9	4109f0ef-0360-401b-b3c4-8e8fff5a4c07	\N
9c74ef5e-a565-4db3-8018-bdb3ae337878	4109f0ef-0360-401b-b3c4-8e8fff5a4c07	t	${role_view-clients}	view-clients	86b2aa03-1225-4835-8758-60f4e03293c9	4109f0ef-0360-401b-b3c4-8e8fff5a4c07	\N
22cf7b9b-ecf8-4a6b-940d-6e4e11e761b2	4109f0ef-0360-401b-b3c4-8e8fff5a4c07	t	${role_view-events}	view-events	86b2aa03-1225-4835-8758-60f4e03293c9	4109f0ef-0360-401b-b3c4-8e8fff5a4c07	\N
6e573cda-1c0e-4233-bdfa-db532f4b2e78	4109f0ef-0360-401b-b3c4-8e8fff5a4c07	t	${role_view-identity-providers}	view-identity-providers	86b2aa03-1225-4835-8758-60f4e03293c9	4109f0ef-0360-401b-b3c4-8e8fff5a4c07	\N
f209b1d7-2985-4e5a-a136-45998bb0a47c	4109f0ef-0360-401b-b3c4-8e8fff5a4c07	t	${role_view-authorization}	view-authorization	86b2aa03-1225-4835-8758-60f4e03293c9	4109f0ef-0360-401b-b3c4-8e8fff5a4c07	\N
c2c890f0-ae59-4b91-a392-6539dd867e22	4109f0ef-0360-401b-b3c4-8e8fff5a4c07	t	${role_manage-realm}	manage-realm	86b2aa03-1225-4835-8758-60f4e03293c9	4109f0ef-0360-401b-b3c4-8e8fff5a4c07	\N
cce7b2f5-7ae7-4bd0-a165-be70f177f598	4109f0ef-0360-401b-b3c4-8e8fff5a4c07	t	${role_manage-users}	manage-users	86b2aa03-1225-4835-8758-60f4e03293c9	4109f0ef-0360-401b-b3c4-8e8fff5a4c07	\N
2b8d745c-1800-4a8c-af99-ba9ac7c2352b	4109f0ef-0360-401b-b3c4-8e8fff5a4c07	t	${role_manage-clients}	manage-clients	86b2aa03-1225-4835-8758-60f4e03293c9	4109f0ef-0360-401b-b3c4-8e8fff5a4c07	\N
c45c9ec6-fcb9-489c-91e2-e0cbc9a34eaf	4109f0ef-0360-401b-b3c4-8e8fff5a4c07	t	${role_manage-events}	manage-events	86b2aa03-1225-4835-8758-60f4e03293c9	4109f0ef-0360-401b-b3c4-8e8fff5a4c07	\N
7ac34dd7-4e4b-4ad4-a1f8-777a697c21e5	4109f0ef-0360-401b-b3c4-8e8fff5a4c07	t	${role_manage-identity-providers}	manage-identity-providers	86b2aa03-1225-4835-8758-60f4e03293c9	4109f0ef-0360-401b-b3c4-8e8fff5a4c07	\N
c85932ab-602a-4992-9fde-cfa0894c5ed4	4109f0ef-0360-401b-b3c4-8e8fff5a4c07	t	${role_manage-authorization}	manage-authorization	86b2aa03-1225-4835-8758-60f4e03293c9	4109f0ef-0360-401b-b3c4-8e8fff5a4c07	\N
d7e46f98-ec59-4acd-9c52-46701c5df625	4109f0ef-0360-401b-b3c4-8e8fff5a4c07	t	${role_query-users}	query-users	86b2aa03-1225-4835-8758-60f4e03293c9	4109f0ef-0360-401b-b3c4-8e8fff5a4c07	\N
5a6efb0d-52b9-4660-93b7-76b64d5207cf	4109f0ef-0360-401b-b3c4-8e8fff5a4c07	t	${role_query-clients}	query-clients	86b2aa03-1225-4835-8758-60f4e03293c9	4109f0ef-0360-401b-b3c4-8e8fff5a4c07	\N
cb33c936-538e-4337-955a-bf678d83474b	4109f0ef-0360-401b-b3c4-8e8fff5a4c07	t	${role_query-realms}	query-realms	86b2aa03-1225-4835-8758-60f4e03293c9	4109f0ef-0360-401b-b3c4-8e8fff5a4c07	\N
532678c4-3481-4e05-af7d-13ed0d006686	4109f0ef-0360-401b-b3c4-8e8fff5a4c07	t	${role_query-groups}	query-groups	86b2aa03-1225-4835-8758-60f4e03293c9	4109f0ef-0360-401b-b3c4-8e8fff5a4c07	\N
4cbf279b-4ef4-47e7-acb7-02f05e32ed03	250d0061-d9ce-4ad2-888b-c5d151e2fe6d	t	${role_view-profile}	view-profile	86b2aa03-1225-4835-8758-60f4e03293c9	250d0061-d9ce-4ad2-888b-c5d151e2fe6d	\N
60193ccb-5aaf-4faa-a96f-0230790d6f02	250d0061-d9ce-4ad2-888b-c5d151e2fe6d	t	${role_manage-account}	manage-account	86b2aa03-1225-4835-8758-60f4e03293c9	250d0061-d9ce-4ad2-888b-c5d151e2fe6d	\N
526756d1-34f4-43a9-a640-3b79037e9e51	250d0061-d9ce-4ad2-888b-c5d151e2fe6d	t	${role_manage-account-links}	manage-account-links	86b2aa03-1225-4835-8758-60f4e03293c9	250d0061-d9ce-4ad2-888b-c5d151e2fe6d	\N
1758c45e-032f-4c57-af0e-8a025690a0b4	250d0061-d9ce-4ad2-888b-c5d151e2fe6d	t	${role_view-applications}	view-applications	86b2aa03-1225-4835-8758-60f4e03293c9	250d0061-d9ce-4ad2-888b-c5d151e2fe6d	\N
b4595704-0b60-43db-ba3c-d193af3b77b5	250d0061-d9ce-4ad2-888b-c5d151e2fe6d	t	${role_view-consent}	view-consent	86b2aa03-1225-4835-8758-60f4e03293c9	250d0061-d9ce-4ad2-888b-c5d151e2fe6d	\N
de4474d3-ee9a-47d7-b9a3-3ec5361bcccf	250d0061-d9ce-4ad2-888b-c5d151e2fe6d	t	${role_manage-consent}	manage-consent	86b2aa03-1225-4835-8758-60f4e03293c9	250d0061-d9ce-4ad2-888b-c5d151e2fe6d	\N
020d21aa-8890-4fc0-a62f-42f4c7787683	250d0061-d9ce-4ad2-888b-c5d151e2fe6d	t	${role_view-groups}	view-groups	86b2aa03-1225-4835-8758-60f4e03293c9	250d0061-d9ce-4ad2-888b-c5d151e2fe6d	\N
ba4fb85e-acfc-442d-b9c0-817480fe3b4c	250d0061-d9ce-4ad2-888b-c5d151e2fe6d	t	${role_delete-account}	delete-account	86b2aa03-1225-4835-8758-60f4e03293c9	250d0061-d9ce-4ad2-888b-c5d151e2fe6d	\N
de155c20-6671-456f-8aa4-30d982cfa060	65689518-2c8c-416b-9862-9acaaa6dbcd0	t	${role_read-token}	read-token	86b2aa03-1225-4835-8758-60f4e03293c9	65689518-2c8c-416b-9862-9acaaa6dbcd0	\N
d76c11c9-077f-47e8-bd55-10e6418fdee8	4109f0ef-0360-401b-b3c4-8e8fff5a4c07	t	${role_impersonation}	impersonation	86b2aa03-1225-4835-8758-60f4e03293c9	4109f0ef-0360-401b-b3c4-8e8fff5a4c07	\N
f9a0073f-89ef-423a-a038-d800c88c050f	86b2aa03-1225-4835-8758-60f4e03293c9	f	${role_offline-access}	offline_access	86b2aa03-1225-4835-8758-60f4e03293c9	\N	\N
b654bacc-6b9f-411b-a89c-bb2b3be56d23	86b2aa03-1225-4835-8758-60f4e03293c9	f	${role_uma_authorization}	uma_authorization	86b2aa03-1225-4835-8758-60f4e03293c9	\N	\N
93059c31-b7bc-4d3d-bc95-dc94a5ebb7ad	6f348afb-6f1f-428c-a4f9-5f8e2374a075	f	${role_default-roles}	default-roles-gdi	6f348afb-6f1f-428c-a4f9-5f8e2374a075	\N	\N
04f017d2-4f74-4b3d-96ee-2dcd863f616c	d9b73b9c-e8ac-4da7-aafb-9e39584eab85	t	${role_create-client}	create-client	86b2aa03-1225-4835-8758-60f4e03293c9	d9b73b9c-e8ac-4da7-aafb-9e39584eab85	\N
4cc75219-d276-4a8d-85b8-58e7ed57b701	d9b73b9c-e8ac-4da7-aafb-9e39584eab85	t	${role_view-realm}	view-realm	86b2aa03-1225-4835-8758-60f4e03293c9	d9b73b9c-e8ac-4da7-aafb-9e39584eab85	\N
af74d514-f774-4e52-92f9-d4aae1d7c95b	d9b73b9c-e8ac-4da7-aafb-9e39584eab85	t	${role_view-users}	view-users	86b2aa03-1225-4835-8758-60f4e03293c9	d9b73b9c-e8ac-4da7-aafb-9e39584eab85	\N
05df4622-81a9-42da-82fc-92d66938b618	d9b73b9c-e8ac-4da7-aafb-9e39584eab85	t	${role_view-clients}	view-clients	86b2aa03-1225-4835-8758-60f4e03293c9	d9b73b9c-e8ac-4da7-aafb-9e39584eab85	\N
1de32797-f085-472c-bb69-c2a1d3304e91	d9b73b9c-e8ac-4da7-aafb-9e39584eab85	t	${role_view-events}	view-events	86b2aa03-1225-4835-8758-60f4e03293c9	d9b73b9c-e8ac-4da7-aafb-9e39584eab85	\N
47e3ec31-a6c0-4051-94d8-1c624a63591f	ed6cb8f0-80e0-43a5-bade-3cb5f15f3cc5	t	${role_view-events}	view-events	6f348afb-6f1f-428c-a4f9-5f8e2374a075	ed6cb8f0-80e0-43a5-bade-3cb5f15f3cc5	\N
ebbb3a23-11f8-46e5-8bc9-d26e2e6ce33b	d9b73b9c-e8ac-4da7-aafb-9e39584eab85	t	${role_view-identity-providers}	view-identity-providers	86b2aa03-1225-4835-8758-60f4e03293c9	d9b73b9c-e8ac-4da7-aafb-9e39584eab85	\N
1cdf82a6-08f4-43c9-ae5d-1fb8a34464eb	d9b73b9c-e8ac-4da7-aafb-9e39584eab85	t	${role_view-authorization}	view-authorization	86b2aa03-1225-4835-8758-60f4e03293c9	d9b73b9c-e8ac-4da7-aafb-9e39584eab85	\N
a9fd9060-2531-45cd-b4de-33df64b73eb9	d9b73b9c-e8ac-4da7-aafb-9e39584eab85	t	${role_manage-realm}	manage-realm	86b2aa03-1225-4835-8758-60f4e03293c9	d9b73b9c-e8ac-4da7-aafb-9e39584eab85	\N
ea1e1e53-0570-4566-b3b3-8c165a0b97d3	d9b73b9c-e8ac-4da7-aafb-9e39584eab85	t	${role_manage-users}	manage-users	86b2aa03-1225-4835-8758-60f4e03293c9	d9b73b9c-e8ac-4da7-aafb-9e39584eab85	\N
275bf0fa-d9fe-4ee3-b686-155924ddfb12	d9b73b9c-e8ac-4da7-aafb-9e39584eab85	t	${role_manage-clients}	manage-clients	86b2aa03-1225-4835-8758-60f4e03293c9	d9b73b9c-e8ac-4da7-aafb-9e39584eab85	\N
85a8d42f-ec02-4194-918a-f7eea8d55997	d9b73b9c-e8ac-4da7-aafb-9e39584eab85	t	${role_manage-events}	manage-events	86b2aa03-1225-4835-8758-60f4e03293c9	d9b73b9c-e8ac-4da7-aafb-9e39584eab85	\N
d5d9adbf-b9ea-4aee-be3d-5797d2fe1557	d9b73b9c-e8ac-4da7-aafb-9e39584eab85	t	${role_manage-identity-providers}	manage-identity-providers	86b2aa03-1225-4835-8758-60f4e03293c9	d9b73b9c-e8ac-4da7-aafb-9e39584eab85	\N
a50956a8-e469-4e93-bf2e-460996cc411b	d9b73b9c-e8ac-4da7-aafb-9e39584eab85	t	${role_manage-authorization}	manage-authorization	86b2aa03-1225-4835-8758-60f4e03293c9	d9b73b9c-e8ac-4da7-aafb-9e39584eab85	\N
9f591e8d-22db-486a-910f-257effd9f0fd	d9b73b9c-e8ac-4da7-aafb-9e39584eab85	t	${role_query-users}	query-users	86b2aa03-1225-4835-8758-60f4e03293c9	d9b73b9c-e8ac-4da7-aafb-9e39584eab85	\N
5d4ba0d7-6685-436c-87bc-07511c4a657e	d9b73b9c-e8ac-4da7-aafb-9e39584eab85	t	${role_query-clients}	query-clients	86b2aa03-1225-4835-8758-60f4e03293c9	d9b73b9c-e8ac-4da7-aafb-9e39584eab85	\N
0903100d-742e-4f97-ba61-6dfc00b8cc8b	d9b73b9c-e8ac-4da7-aafb-9e39584eab85	t	${role_query-realms}	query-realms	86b2aa03-1225-4835-8758-60f4e03293c9	d9b73b9c-e8ac-4da7-aafb-9e39584eab85	\N
fccb989f-b8c9-4886-bd86-69552b08dfbf	d9b73b9c-e8ac-4da7-aafb-9e39584eab85	t	${role_query-groups}	query-groups	86b2aa03-1225-4835-8758-60f4e03293c9	d9b73b9c-e8ac-4da7-aafb-9e39584eab85	\N
cd273c77-3c3e-4673-bd40-1cf5b82e1c20	6f348afb-6f1f-428c-a4f9-5f8e2374a075	f	${role_uma_authorization}	uma_authorization	6f348afb-6f1f-428c-a4f9-5f8e2374a075	\N	\N
20d863dd-6c6a-4357-bea7-50ca195e9032	6f348afb-6f1f-428c-a4f9-5f8e2374a075	f	${role_offline-access}	offline_access	6f348afb-6f1f-428c-a4f9-5f8e2374a075	\N	\N
aface648-bf84-41d5-9498-77a06fb25376	6f348afb-6f1f-428c-a4f9-5f8e2374a075	f		ga4gh-visa-issuer	6f348afb-6f1f-428c-a4f9-5f8e2374a075	\N	\N
a2eba2cb-9d42-420b-a728-3ce37166d521	ed6cb8f0-80e0-43a5-bade-3cb5f15f3cc5	t	${role_view-realm}	view-realm	6f348afb-6f1f-428c-a4f9-5f8e2374a075	ed6cb8f0-80e0-43a5-bade-3cb5f15f3cc5	\N
9fad18b8-66e2-419f-82b9-48991dd49847	ed6cb8f0-80e0-43a5-bade-3cb5f15f3cc5	t	${role_query-clients}	query-clients	6f348afb-6f1f-428c-a4f9-5f8e2374a075	ed6cb8f0-80e0-43a5-bade-3cb5f15f3cc5	\N
a48e1955-b0ce-46d6-93ed-09ba372bb577	ed6cb8f0-80e0-43a5-bade-3cb5f15f3cc5	t	${role_impersonation}	impersonation	6f348afb-6f1f-428c-a4f9-5f8e2374a075	ed6cb8f0-80e0-43a5-bade-3cb5f15f3cc5	\N
08a5cb36-e078-404f-8ec8-adca98518bf2	ed6cb8f0-80e0-43a5-bade-3cb5f15f3cc5	t	${role_query-groups}	query-groups	6f348afb-6f1f-428c-a4f9-5f8e2374a075	ed6cb8f0-80e0-43a5-bade-3cb5f15f3cc5	\N
16c7221b-58a3-4670-b09f-de5bef4986a1	ed6cb8f0-80e0-43a5-bade-3cb5f15f3cc5	t	${role_manage-identity-providers}	manage-identity-providers	6f348afb-6f1f-428c-a4f9-5f8e2374a075	ed6cb8f0-80e0-43a5-bade-3cb5f15f3cc5	\N
26e2947c-84ac-41ed-8503-b284d157365d	ed6cb8f0-80e0-43a5-bade-3cb5f15f3cc5	t	${role_manage-clients}	manage-clients	6f348afb-6f1f-428c-a4f9-5f8e2374a075	ed6cb8f0-80e0-43a5-bade-3cb5f15f3cc5	\N
9ac6cf4f-02e1-463e-9034-cce441b97235	ed6cb8f0-80e0-43a5-bade-3cb5f15f3cc5	t	${role_view-authorization}	view-authorization	6f348afb-6f1f-428c-a4f9-5f8e2374a075	ed6cb8f0-80e0-43a5-bade-3cb5f15f3cc5	\N
1195a822-80fd-4810-883d-a9148b6dc49b	ed6cb8f0-80e0-43a5-bade-3cb5f15f3cc5	t	${role_manage-realm}	manage-realm	6f348afb-6f1f-428c-a4f9-5f8e2374a075	ed6cb8f0-80e0-43a5-bade-3cb5f15f3cc5	\N
9aefe793-abe0-4052-9826-00e4b8c18cc0	ed6cb8f0-80e0-43a5-bade-3cb5f15f3cc5	t	${role_manage-authorization}	manage-authorization	6f348afb-6f1f-428c-a4f9-5f8e2374a075	ed6cb8f0-80e0-43a5-bade-3cb5f15f3cc5	\N
8828f436-44ce-47c1-b357-4423fe0d9792	ed6cb8f0-80e0-43a5-bade-3cb5f15f3cc5	t	${role_view-identity-providers}	view-identity-providers	6f348afb-6f1f-428c-a4f9-5f8e2374a075	ed6cb8f0-80e0-43a5-bade-3cb5f15f3cc5	\N
db7cc3e4-b91d-422c-944d-8b38bad70d3a	ed6cb8f0-80e0-43a5-bade-3cb5f15f3cc5	t	${role_create-client}	create-client	6f348afb-6f1f-428c-a4f9-5f8e2374a075	ed6cb8f0-80e0-43a5-bade-3cb5f15f3cc5	\N
a61f4d23-5fd7-466d-8654-c515c4044f2a	ed6cb8f0-80e0-43a5-bade-3cb5f15f3cc5	t	${role_view-users}	view-users	6f348afb-6f1f-428c-a4f9-5f8e2374a075	ed6cb8f0-80e0-43a5-bade-3cb5f15f3cc5	\N
f9c888a1-2470-45e7-b2f9-b80fa4b1c30a	ed6cb8f0-80e0-43a5-bade-3cb5f15f3cc5	t	${role_realm-admin}	realm-admin	6f348afb-6f1f-428c-a4f9-5f8e2374a075	ed6cb8f0-80e0-43a5-bade-3cb5f15f3cc5	\N
aedfd698-0589-497b-996a-56b5488b2c90	ed6cb8f0-80e0-43a5-bade-3cb5f15f3cc5	t	${role_query-realms}	query-realms	6f348afb-6f1f-428c-a4f9-5f8e2374a075	ed6cb8f0-80e0-43a5-bade-3cb5f15f3cc5	\N
793fcba9-d7d9-4ee7-af7e-74c3fa4abf6c	ed6cb8f0-80e0-43a5-bade-3cb5f15f3cc5	t	${role_view-clients}	view-clients	6f348afb-6f1f-428c-a4f9-5f8e2374a075	ed6cb8f0-80e0-43a5-bade-3cb5f15f3cc5	\N
a8d15439-95e1-4241-b070-79f3014437a2	ed6cb8f0-80e0-43a5-bade-3cb5f15f3cc5	t	${role_manage-users}	manage-users	6f348afb-6f1f-428c-a4f9-5f8e2374a075	ed6cb8f0-80e0-43a5-bade-3cb5f15f3cc5	\N
4a894d73-6b48-4315-bbbc-51324ab59916	ed6cb8f0-80e0-43a5-bade-3cb5f15f3cc5	t	${role_manage-events}	manage-events	6f348afb-6f1f-428c-a4f9-5f8e2374a075	ed6cb8f0-80e0-43a5-bade-3cb5f15f3cc5	\N
6e0c16e4-1848-4675-8cfd-9029b941e703	ed6cb8f0-80e0-43a5-bade-3cb5f15f3cc5	t	${role_query-users}	query-users	6f348afb-6f1f-428c-a4f9-5f8e2374a075	ed6cb8f0-80e0-43a5-bade-3cb5f15f3cc5	\N
f73599ce-eec3-40a4-86c0-b1ccc4f51cf9	545c2160-f604-44d4-98c4-cf209d2d0b9d	t	\N	uma_protection	6f348afb-6f1f-428c-a4f9-5f8e2374a075	545c2160-f604-44d4-98c4-cf209d2d0b9d	\N
049b29fa-57fd-47c9-a202-566ec2733b23	97b39b11-142c-4dce-b109-917b76790017	t	${role_read-token}	read-token	6f348afb-6f1f-428c-a4f9-5f8e2374a075	97b39b11-142c-4dce-b109-917b76790017	\N
dd1ca63b-574d-431c-953b-f7de73438e86	49dfabcd-b980-414c-94a8-fdb65533ad2f	t		RESEARCHER	6f348afb-6f1f-428c-a4f9-5f8e2374a075	49dfabcd-b980-414c-94a8-fdb65533ad2f	\N
136c82ed-dc60-4c9f-9744-77c9a4cca1f1	476d5095-dbf9-4fe0-bef8-fde1730956f9	t	${role_view-groups}	view-groups	6f348afb-6f1f-428c-a4f9-5f8e2374a075	476d5095-dbf9-4fe0-bef8-fde1730956f9	\N
71504726-a8a7-47db-bc3b-ca07e310b0be	476d5095-dbf9-4fe0-bef8-fde1730956f9	t	${role_manage-account-links}	manage-account-links	6f348afb-6f1f-428c-a4f9-5f8e2374a075	476d5095-dbf9-4fe0-bef8-fde1730956f9	\N
112b6f3b-3904-421f-abf0-dda37752c236	476d5095-dbf9-4fe0-bef8-fde1730956f9	t	${role_manage-account}	manage-account	6f348afb-6f1f-428c-a4f9-5f8e2374a075	476d5095-dbf9-4fe0-bef8-fde1730956f9	\N
d11528f3-b7be-467b-b9b7-7698f5592c51	476d5095-dbf9-4fe0-bef8-fde1730956f9	t	${role_view-applications}	view-applications	6f348afb-6f1f-428c-a4f9-5f8e2374a075	476d5095-dbf9-4fe0-bef8-fde1730956f9	\N
4d0b20af-df72-49d4-b2ec-d6f82e92d4b1	476d5095-dbf9-4fe0-bef8-fde1730956f9	t	${role_manage-consent}	manage-consent	6f348afb-6f1f-428c-a4f9-5f8e2374a075	476d5095-dbf9-4fe0-bef8-fde1730956f9	\N
9bffb9ea-0141-46f1-8adb-ae91529d6813	476d5095-dbf9-4fe0-bef8-fde1730956f9	t	${role_view-consent}	view-consent	6f348afb-6f1f-428c-a4f9-5f8e2374a075	476d5095-dbf9-4fe0-bef8-fde1730956f9	\N
82bea49f-2846-4f28-9423-aae750454332	476d5095-dbf9-4fe0-bef8-fde1730956f9	t	${role_delete-account}	delete-account	6f348afb-6f1f-428c-a4f9-5f8e2374a075	476d5095-dbf9-4fe0-bef8-fde1730956f9	\N
39e06706-101b-42b6-adee-f5235743eda8	476d5095-dbf9-4fe0-bef8-fde1730956f9	t	${role_view-profile}	view-profile	6f348afb-6f1f-428c-a4f9-5f8e2374a075	476d5095-dbf9-4fe0-bef8-fde1730956f9	\N
fcd31082-864b-4ad4-8da7-84020e903166	d9b73b9c-e8ac-4da7-aafb-9e39584eab85	t	${role_impersonation}	impersonation	86b2aa03-1225-4835-8758-60f4e03293c9	d9b73b9c-e8ac-4da7-aafb-9e39584eab85	\N
\.


--
-- Data for Name: migration_model; Type: TABLE DATA; Schema: public; Owner: keycloak
--

COPY public.migration_model (id, version, update_time) FROM stdin;
pmx96	26.5.7	1779391643
\.


--
-- Data for Name: offline_client_session; Type: TABLE DATA; Schema: public; Owner: keycloak
--

COPY public.offline_client_session (user_session_id, client_id, offline_flag, "timestamp", data, client_storage_provider, external_client_id, version) FROM stdin;
wlOfGGOR8O7nzNiA_pZiFLoV	f6127f78-7990-4de5-8eba-6721209ae8d9	0	1779395094	{"authMethod":"openid-connect","redirectUri":"http://localhost:8080/admin/master/console/#/gdi/users/addddfb1-5606-4b7a-b6cc-925a36faece3/attributes","notes":{"clientId":"f6127f78-7990-4de5-8eba-6721209ae8d9","iss":"http://localhost:8080/realms/master","startedAt":"1779395094","response_type":"code","level-of-authentication":"-1","code_challenge_method":"S256","nonce":"f6deba59-6338-4dfe-9d2c-fc9ff07ec6f0","response_mode":"query","scope":"openid","userSessionStartedAt":"1779395094","redirect_uri":"http://localhost:8080/admin/master/console/#/gdi/users/addddfb1-5606-4b7a-b6cc-925a36faece3/attributes","state":"269d32b1-7203-45db-9271-3a31cb81252a","code_challenge":"UIfGHjAh_tmQQOOxLxK5jizjNXMxTgf9Mm4h4X5La2k"}}	local	local	0
\.


--
-- Data for Name: offline_user_session; Type: TABLE DATA; Schema: public; Owner: keycloak
--

COPY public.offline_user_session (user_session_id, user_id, realm_id, created_on, offline_flag, data, last_session_refresh, broker_session_id, version, remember_me) FROM stdin;
wlOfGGOR8O7nzNiA_pZiFLoV	6074dc87-06d6-40e0-b851-f702fe11d3c6	86b2aa03-1225-4835-8758-60f4e03293c9	1779395094	0	{"ipAddress":"192.168.127.1","authMethod":"openid-connect","rememberMe":false,"started":0,"notes":{"KC_DEVICE_NOTE":"eyJpcEFkZHJlc3MiOiIxOTIuMTY4LjEyNy4xIiwib3MiOiJNYWMgT1MgWCIsIm9zVmVyc2lvbiI6IjEwLjE1LjciLCJicm93c2VyIjoiRWRnZS8xNDguMC4wIiwiZGV2aWNlIjoiTWFjIiwibGFzdEFjY2VzcyI6MCwibW9iaWxlIjpmYWxzZX0=","AUTH_TIME":"1779395094","authenticators-completed":"{\\"565409a5-c21d-45c8-b9e0-e0aaba2b19cf\\":1779395094}"},"state":"LOGGED_IN"}	1779395094	\N	0	f
\.


--
-- Data for Name: org; Type: TABLE DATA; Schema: public; Owner: keycloak
--

COPY public.org (id, enabled, realm_id, group_id, name, description, alias, redirect_url) FROM stdin;
\.


--
-- Data for Name: org_domain; Type: TABLE DATA; Schema: public; Owner: keycloak
--

COPY public.org_domain (id, name, verified, org_id) FROM stdin;
\.


--
-- Data for Name: org_invitation; Type: TABLE DATA; Schema: public; Owner: keycloak
--

COPY public.org_invitation (id, organization_id, email, first_name, last_name, created_at, expires_at, invite_link) FROM stdin;
\.


--
-- Data for Name: policy_config; Type: TABLE DATA; Schema: public; Owner: keycloak
--

COPY public.policy_config (policy_id, name, value) FROM stdin;
\.


--
-- Data for Name: protocol_mapper; Type: TABLE DATA; Schema: public; Owner: keycloak
--

COPY public.protocol_mapper (id, name, protocol, protocol_mapper_name, client_id, client_scope_id) FROM stdin;
fa61742b-e7cd-4cd8-88ce-7a428d6259c3	audience resolve	openid-connect	oidc-audience-resolve-mapper	2a479066-384f-44a7-8ca2-7bb08a9c0b90	\N
e53d431c-6d2e-491f-b414-18fb55f489f8	locale	openid-connect	oidc-usermodel-attribute-mapper	f6127f78-7990-4de5-8eba-6721209ae8d9	\N
8630a334-4c47-4a89-89b8-14c4a434a87e	role list	saml	saml-role-list-mapper	\N	e2ea9eef-0762-4ee6-8b90-04d1abd1316e
115f5228-5ea7-4c59-8e74-7e56fd4b4461	organization	saml	saml-organization-membership-mapper	\N	2722ccf7-8558-45d3-bd06-84b43c572a3c
4292a6d4-211b-45e9-acd4-99e1310f9f76	full name	openid-connect	oidc-full-name-mapper	\N	94c8b8ed-2c5f-4bdf-ba43-aa08c5fe9192
60232d35-f888-4d16-9005-194035cca8f6	family name	openid-connect	oidc-usermodel-attribute-mapper	\N	94c8b8ed-2c5f-4bdf-ba43-aa08c5fe9192
ab6e81ff-75be-4179-ac83-46a3125552b8	given name	openid-connect	oidc-usermodel-attribute-mapper	\N	94c8b8ed-2c5f-4bdf-ba43-aa08c5fe9192
36d00acc-9b4c-415f-80bb-e16d383b6886	middle name	openid-connect	oidc-usermodel-attribute-mapper	\N	94c8b8ed-2c5f-4bdf-ba43-aa08c5fe9192
3179ae4e-595a-43f6-8f2d-b6909116e224	nickname	openid-connect	oidc-usermodel-attribute-mapper	\N	94c8b8ed-2c5f-4bdf-ba43-aa08c5fe9192
ea67f052-e964-4dbc-9622-abced04a9c2e	username	openid-connect	oidc-usermodel-attribute-mapper	\N	94c8b8ed-2c5f-4bdf-ba43-aa08c5fe9192
1237c9bb-fb68-4953-a4b6-baffdfa71086	profile	openid-connect	oidc-usermodel-attribute-mapper	\N	94c8b8ed-2c5f-4bdf-ba43-aa08c5fe9192
aca7d874-a06a-45af-92f0-053030052d4d	picture	openid-connect	oidc-usermodel-attribute-mapper	\N	94c8b8ed-2c5f-4bdf-ba43-aa08c5fe9192
a2ae84d4-c773-405c-9c54-f6d0365b6f74	website	openid-connect	oidc-usermodel-attribute-mapper	\N	94c8b8ed-2c5f-4bdf-ba43-aa08c5fe9192
46dfb319-727b-43d8-bf03-23b865b71382	gender	openid-connect	oidc-usermodel-attribute-mapper	\N	94c8b8ed-2c5f-4bdf-ba43-aa08c5fe9192
c3821338-5296-4223-bb53-35de9edab42a	birthdate	openid-connect	oidc-usermodel-attribute-mapper	\N	94c8b8ed-2c5f-4bdf-ba43-aa08c5fe9192
314c08eb-0640-49d4-923c-93e0d5cad59c	zoneinfo	openid-connect	oidc-usermodel-attribute-mapper	\N	94c8b8ed-2c5f-4bdf-ba43-aa08c5fe9192
1af018af-90aa-401e-9051-fc30ddfd86af	locale	openid-connect	oidc-usermodel-attribute-mapper	\N	94c8b8ed-2c5f-4bdf-ba43-aa08c5fe9192
f45f2f88-371c-4505-bb53-340ac78f1294	updated at	openid-connect	oidc-usermodel-attribute-mapper	\N	94c8b8ed-2c5f-4bdf-ba43-aa08c5fe9192
21dc2a54-fee8-40ff-815c-992db6d69593	email	openid-connect	oidc-usermodel-attribute-mapper	\N	b1c22975-5e52-4a59-a2d5-c8b654fc6645
07bcb879-9c1c-4d5a-9470-b8f6744e60b0	email verified	openid-connect	oidc-usermodel-property-mapper	\N	b1c22975-5e52-4a59-a2d5-c8b654fc6645
e7607f30-45a2-4201-bbc4-3abffb08ae9c	address	openid-connect	oidc-address-mapper	\N	2bd86ed4-1786-44b4-b0b6-01fd86b24565
45b6f972-adf7-4da4-a9da-6323e7b7deb6	phone number	openid-connect	oidc-usermodel-attribute-mapper	\N	5337c14e-5172-43f9-a2a1-e1bb32385e7f
895c5d00-42f7-4293-a06c-30021aca4580	phone number verified	openid-connect	oidc-usermodel-attribute-mapper	\N	5337c14e-5172-43f9-a2a1-e1bb32385e7f
5d44dbda-719d-44ce-9637-3aa18d485158	realm roles	openid-connect	oidc-usermodel-realm-role-mapper	\N	c9b53021-3bba-4908-90d8-755f38d861c8
037d1dca-8d16-4144-ad59-436f8c4be18d	client roles	openid-connect	oidc-usermodel-client-role-mapper	\N	c9b53021-3bba-4908-90d8-755f38d861c8
b93e7557-3d20-4a3e-8db4-4f146e15debe	audience resolve	openid-connect	oidc-audience-resolve-mapper	\N	c9b53021-3bba-4908-90d8-755f38d861c8
e24b8235-d120-4b2d-b734-eed9fe885b9e	allowed web origins	openid-connect	oidc-allowed-origins-mapper	\N	4ebd35f2-be54-4a34-bb50-4c1c4f2382f6
28879a80-1b1f-4602-a00d-f584ead3f9c9	upn	openid-connect	oidc-usermodel-attribute-mapper	\N	2b81c7e8-3993-456b-9341-05ecccfd5112
cc84ceaa-64b0-4d31-a90a-f6bfe565ee8c	groups	openid-connect	oidc-usermodel-realm-role-mapper	\N	2b81c7e8-3993-456b-9341-05ecccfd5112
16e3fd9f-e292-49cf-97e2-318898db3a66	acr loa level	openid-connect	oidc-acr-mapper	\N	85e82c50-2d25-4009-bdcf-765a62708f9f
ad9ccb25-d883-40f4-a0c7-e2a9edb042a8	auth_time	openid-connect	oidc-usersessionmodel-note-mapper	\N	cdba92d9-0fd2-4209-9f7c-e1f6f7ffbec6
c32e9149-7670-418c-91fb-eaf43f7f2f2f	sub	openid-connect	oidc-sub-mapper	\N	cdba92d9-0fd2-4209-9f7c-e1f6f7ffbec6
43afb46c-478b-4f49-a77c-4b39b555377c	Client ID	openid-connect	oidc-usersessionmodel-note-mapper	\N	df30f937-e897-416e-bf56-05fdd5acad60
8b06ca6c-31e6-4a6a-ae6d-488b1aa2a2e2	Client Host	openid-connect	oidc-usersessionmodel-note-mapper	\N	df30f937-e897-416e-bf56-05fdd5acad60
6ac892b1-3815-48c1-a331-03309d6f0867	Client IP Address	openid-connect	oidc-usersessionmodel-note-mapper	\N	df30f937-e897-416e-bf56-05fdd5acad60
9c7c2ae6-8824-4087-a642-6f081f1a6b86	organization	openid-connect	oidc-organization-membership-mapper	\N	e7bf5139-442c-419d-98b9-0833ce102d55
8308b1e8-783c-4a7d-8f7e-04f1e98686fc	address	openid-connect	oidc-address-mapper	\N	49cae1f3-7c12-41d0-8e9a-189daa5b45ff
44b8acd8-9363-4391-915f-cd0e602a469f	auth_time	openid-connect	oidc-usersessionmodel-note-mapper	\N	b0edc86e-8c20-4f94-be36-e4a6c7913929
c7a8f16f-64a2-4730-939b-f282739f5d03	sub	openid-connect	oidc-sub-mapper	\N	b0edc86e-8c20-4f94-be36-e4a6c7913929
a8ea96d0-7bb1-46d8-bb3d-87e238b42e8b	email verified	openid-connect	oidc-usermodel-property-mapper	\N	0ca5fed1-0041-4acc-b018-b7d4da4c2a9a
75ce3646-48cf-431e-b54b-2d88d943ebd6	email	openid-connect	oidc-usermodel-attribute-mapper	\N	0ca5fed1-0041-4acc-b018-b7d4da4c2a9a
8520db0d-2eb0-4c15-8d51-9e5031cc7ab0	Elixir ID mapper	openid-connect	oidc-usermodel-attribute-mapper	\N	bb63fc7c-63cb-4b73-b607-497727b563f2
f2419169-8d1a-42d6-a9e5-35c82f32c8b0	upn	openid-connect	oidc-usermodel-attribute-mapper	\N	ae433992-c6a6-46ed-89a5-75899f4edc99
25c91c90-20af-4c81-be19-fe560f9690f2	groups	openid-connect	oidc-usermodel-realm-role-mapper	\N	ae433992-c6a6-46ed-89a5-75899f4edc99
32a16dd0-b249-44a7-83b2-dd015c86cce8	allowed web origins	openid-connect	oidc-allowed-origins-mapper	\N	c672e3cb-0646-46fb-887f-00be5de8a12e
e6a1c822-779b-48e1-aadc-fb75f11b3bf2	phone number	openid-connect	oidc-usermodel-attribute-mapper	\N	2bd35aef-70dd-4102-a8a9-f4c7e3135edc
ca601f00-8cae-4159-acb3-85dca0a7521d	phone number verified	openid-connect	oidc-usermodel-attribute-mapper	\N	2bd35aef-70dd-4102-a8a9-f4c7e3135edc
2a559ea2-f543-4925-8ffa-9b1cfe502e5e	Client ID	openid-connect	oidc-usersessionmodel-note-mapper	\N	c5cd6971-f51b-4db8-a59a-3433c27d4882
17ba9a68-6ad6-459b-8ea1-79a3503204d6	Client Host	openid-connect	oidc-usersessionmodel-note-mapper	\N	c5cd6971-f51b-4db8-a59a-3433c27d4882
5e4d9a81-bdce-4da5-8151-5bc870ebaeef	Client IP Address	openid-connect	oidc-usersessionmodel-note-mapper	\N	c5cd6971-f51b-4db8-a59a-3433c27d4882
dd7addec-1976-477e-ba66-ee77869156d7	client roles	openid-connect	oidc-usermodel-client-role-mapper	\N	e217ed3a-3a19-4548-bbb5-19e9f2642ccd
15531919-9b88-4314-9393-2501c07ba6ea	audience resolve	openid-connect	oidc-audience-resolve-mapper	\N	e217ed3a-3a19-4548-bbb5-19e9f2642ccd
399d1e5f-f9c4-400f-81b5-397de8597ffb	realm roles	openid-connect	oidc-usermodel-realm-role-mapper	\N	e217ed3a-3a19-4548-bbb5-19e9f2642ccd
b7679e3c-23de-49e1-ae26-d58dac54b6cd	birthdate	openid-connect	oidc-usermodel-attribute-mapper	\N	337dc738-9720-42e4-8cfa-ca816f3a9c47
c2bede9d-9d79-4dc1-8ed0-7689baa4de73	username	openid-connect	oidc-usermodel-attribute-mapper	\N	337dc738-9720-42e4-8cfa-ca816f3a9c47
8d05a238-9c89-4548-bf77-ec690e826734	picture	openid-connect	oidc-usermodel-attribute-mapper	\N	337dc738-9720-42e4-8cfa-ca816f3a9c47
87f85b47-3189-4af2-8651-0663a4af6c4e	zoneinfo	openid-connect	oidc-usermodel-attribute-mapper	\N	337dc738-9720-42e4-8cfa-ca816f3a9c47
23510843-4c32-4bfe-848a-fed38392e1c5	profile	openid-connect	oidc-usermodel-attribute-mapper	\N	337dc738-9720-42e4-8cfa-ca816f3a9c47
344b9514-c119-4284-95da-9fb29e6e9f66	middle name	openid-connect	oidc-usermodel-attribute-mapper	\N	337dc738-9720-42e4-8cfa-ca816f3a9c47
18c4fae8-fdb8-476d-aea7-7b2384667a11	given name	openid-connect	oidc-usermodel-attribute-mapper	\N	337dc738-9720-42e4-8cfa-ca816f3a9c47
e8241ff5-2278-4172-9ba4-6d60548a78fd	nickname	openid-connect	oidc-usermodel-attribute-mapper	\N	337dc738-9720-42e4-8cfa-ca816f3a9c47
2e648938-e959-4e17-a208-861d8d4eacd5	locale	openid-connect	oidc-usermodel-attribute-mapper	\N	337dc738-9720-42e4-8cfa-ca816f3a9c47
97aefc80-f08e-4f41-807d-5236395ec89f	website	openid-connect	oidc-usermodel-attribute-mapper	\N	337dc738-9720-42e4-8cfa-ca816f3a9c47
438728ae-3c2a-4faa-83f7-97fda8802058	gender	openid-connect	oidc-usermodel-attribute-mapper	\N	337dc738-9720-42e4-8cfa-ca816f3a9c47
3b3c20dd-72c9-4898-90ca-bf4de8658e96	family name	openid-connect	oidc-usermodel-attribute-mapper	\N	337dc738-9720-42e4-8cfa-ca816f3a9c47
3d9f3f57-df77-470a-9ce1-a4a49cb6ea9c	full name	openid-connect	oidc-full-name-mapper	\N	337dc738-9720-42e4-8cfa-ca816f3a9c47
51d8af12-a61e-45ef-b1c7-8c0fb16dc835	updated at	openid-connect	oidc-usermodel-attribute-mapper	\N	337dc738-9720-42e4-8cfa-ca816f3a9c47
da7673c2-0335-402b-866b-70beb6805637	role list	saml	saml-role-list-mapper	\N	d797387e-1f5c-4232-8e68-f62892491073
d18e6224-a4a7-4cf3-8282-40e4706fc0c7	acr loa level	openid-connect	oidc-acr-mapper	\N	f3daaa09-a5d5-4766-ae71-487c67fc99af
b5c77dfe-292e-4f79-b993-d4b62b6f8b96	audience resolve	openid-connect	oidc-audience-resolve-mapper	632c3653-00fa-4b03-a4ed-81afbb16f16d	\N
d6504f0e-2480-4ad0-8156-18fef8a12e47	Client Host	openid-connect	oidc-usersessionmodel-note-mapper	49dfabcd-b980-414c-94a8-fdb65533ad2f	\N
3e6169b4-267d-48c4-9a98-a4c832686797	Client IP Address	openid-connect	oidc-usersessionmodel-note-mapper	49dfabcd-b980-414c-94a8-fdb65533ad2f	\N
2f1720aa-67b3-497e-8e38-eca0d3ddb067	Client ID	openid-connect	oidc-usersessionmodel-note-mapper	49dfabcd-b980-414c-94a8-fdb65533ad2f	\N
1adb53a6-597c-44a2-91aa-a15349f61efc	locale	openid-connect	oidc-usermodel-attribute-mapper	08d74ac1-49fc-469d-a687-9ab3b27b69b1	\N
\.


--
-- Data for Name: protocol_mapper_config; Type: TABLE DATA; Schema: public; Owner: keycloak
--

COPY public.protocol_mapper_config (protocol_mapper_id, value, name) FROM stdin;
e53d431c-6d2e-491f-b414-18fb55f489f8	true	introspection.token.claim
e53d431c-6d2e-491f-b414-18fb55f489f8	true	userinfo.token.claim
e53d431c-6d2e-491f-b414-18fb55f489f8	locale	user.attribute
e53d431c-6d2e-491f-b414-18fb55f489f8	true	id.token.claim
e53d431c-6d2e-491f-b414-18fb55f489f8	true	access.token.claim
e53d431c-6d2e-491f-b414-18fb55f489f8	locale	claim.name
e53d431c-6d2e-491f-b414-18fb55f489f8	String	jsonType.label
8630a334-4c47-4a89-89b8-14c4a434a87e	false	single
8630a334-4c47-4a89-89b8-14c4a434a87e	Basic	attribute.nameformat
8630a334-4c47-4a89-89b8-14c4a434a87e	Role	attribute.name
1237c9bb-fb68-4953-a4b6-baffdfa71086	true	introspection.token.claim
1237c9bb-fb68-4953-a4b6-baffdfa71086	true	userinfo.token.claim
1237c9bb-fb68-4953-a4b6-baffdfa71086	profile	user.attribute
1237c9bb-fb68-4953-a4b6-baffdfa71086	true	id.token.claim
1237c9bb-fb68-4953-a4b6-baffdfa71086	true	access.token.claim
1237c9bb-fb68-4953-a4b6-baffdfa71086	profile	claim.name
1237c9bb-fb68-4953-a4b6-baffdfa71086	String	jsonType.label
1af018af-90aa-401e-9051-fc30ddfd86af	true	introspection.token.claim
1af018af-90aa-401e-9051-fc30ddfd86af	true	userinfo.token.claim
1af018af-90aa-401e-9051-fc30ddfd86af	locale	user.attribute
1af018af-90aa-401e-9051-fc30ddfd86af	true	id.token.claim
1af018af-90aa-401e-9051-fc30ddfd86af	true	access.token.claim
1af018af-90aa-401e-9051-fc30ddfd86af	locale	claim.name
1af018af-90aa-401e-9051-fc30ddfd86af	String	jsonType.label
314c08eb-0640-49d4-923c-93e0d5cad59c	true	introspection.token.claim
314c08eb-0640-49d4-923c-93e0d5cad59c	true	userinfo.token.claim
314c08eb-0640-49d4-923c-93e0d5cad59c	zoneinfo	user.attribute
314c08eb-0640-49d4-923c-93e0d5cad59c	true	id.token.claim
314c08eb-0640-49d4-923c-93e0d5cad59c	true	access.token.claim
314c08eb-0640-49d4-923c-93e0d5cad59c	zoneinfo	claim.name
314c08eb-0640-49d4-923c-93e0d5cad59c	String	jsonType.label
3179ae4e-595a-43f6-8f2d-b6909116e224	true	introspection.token.claim
3179ae4e-595a-43f6-8f2d-b6909116e224	true	userinfo.token.claim
3179ae4e-595a-43f6-8f2d-b6909116e224	nickname	user.attribute
3179ae4e-595a-43f6-8f2d-b6909116e224	true	id.token.claim
3179ae4e-595a-43f6-8f2d-b6909116e224	true	access.token.claim
3179ae4e-595a-43f6-8f2d-b6909116e224	nickname	claim.name
3179ae4e-595a-43f6-8f2d-b6909116e224	String	jsonType.label
36d00acc-9b4c-415f-80bb-e16d383b6886	true	introspection.token.claim
36d00acc-9b4c-415f-80bb-e16d383b6886	true	userinfo.token.claim
36d00acc-9b4c-415f-80bb-e16d383b6886	middleName	user.attribute
36d00acc-9b4c-415f-80bb-e16d383b6886	true	id.token.claim
36d00acc-9b4c-415f-80bb-e16d383b6886	true	access.token.claim
36d00acc-9b4c-415f-80bb-e16d383b6886	middle_name	claim.name
36d00acc-9b4c-415f-80bb-e16d383b6886	String	jsonType.label
4292a6d4-211b-45e9-acd4-99e1310f9f76	true	introspection.token.claim
4292a6d4-211b-45e9-acd4-99e1310f9f76	true	userinfo.token.claim
4292a6d4-211b-45e9-acd4-99e1310f9f76	true	id.token.claim
4292a6d4-211b-45e9-acd4-99e1310f9f76	true	access.token.claim
46dfb319-727b-43d8-bf03-23b865b71382	true	introspection.token.claim
46dfb319-727b-43d8-bf03-23b865b71382	true	userinfo.token.claim
46dfb319-727b-43d8-bf03-23b865b71382	gender	user.attribute
46dfb319-727b-43d8-bf03-23b865b71382	true	id.token.claim
46dfb319-727b-43d8-bf03-23b865b71382	true	access.token.claim
46dfb319-727b-43d8-bf03-23b865b71382	gender	claim.name
46dfb319-727b-43d8-bf03-23b865b71382	String	jsonType.label
60232d35-f888-4d16-9005-194035cca8f6	true	introspection.token.claim
60232d35-f888-4d16-9005-194035cca8f6	true	userinfo.token.claim
60232d35-f888-4d16-9005-194035cca8f6	lastName	user.attribute
60232d35-f888-4d16-9005-194035cca8f6	true	id.token.claim
60232d35-f888-4d16-9005-194035cca8f6	true	access.token.claim
60232d35-f888-4d16-9005-194035cca8f6	family_name	claim.name
60232d35-f888-4d16-9005-194035cca8f6	String	jsonType.label
a2ae84d4-c773-405c-9c54-f6d0365b6f74	true	introspection.token.claim
a2ae84d4-c773-405c-9c54-f6d0365b6f74	true	userinfo.token.claim
a2ae84d4-c773-405c-9c54-f6d0365b6f74	website	user.attribute
a2ae84d4-c773-405c-9c54-f6d0365b6f74	true	id.token.claim
a2ae84d4-c773-405c-9c54-f6d0365b6f74	true	access.token.claim
a2ae84d4-c773-405c-9c54-f6d0365b6f74	website	claim.name
a2ae84d4-c773-405c-9c54-f6d0365b6f74	String	jsonType.label
ab6e81ff-75be-4179-ac83-46a3125552b8	true	introspection.token.claim
ab6e81ff-75be-4179-ac83-46a3125552b8	true	userinfo.token.claim
ab6e81ff-75be-4179-ac83-46a3125552b8	firstName	user.attribute
ab6e81ff-75be-4179-ac83-46a3125552b8	true	id.token.claim
ab6e81ff-75be-4179-ac83-46a3125552b8	true	access.token.claim
ab6e81ff-75be-4179-ac83-46a3125552b8	given_name	claim.name
ab6e81ff-75be-4179-ac83-46a3125552b8	String	jsonType.label
aca7d874-a06a-45af-92f0-053030052d4d	true	introspection.token.claim
aca7d874-a06a-45af-92f0-053030052d4d	true	userinfo.token.claim
aca7d874-a06a-45af-92f0-053030052d4d	picture	user.attribute
aca7d874-a06a-45af-92f0-053030052d4d	true	id.token.claim
aca7d874-a06a-45af-92f0-053030052d4d	true	access.token.claim
aca7d874-a06a-45af-92f0-053030052d4d	picture	claim.name
aca7d874-a06a-45af-92f0-053030052d4d	String	jsonType.label
c3821338-5296-4223-bb53-35de9edab42a	true	introspection.token.claim
c3821338-5296-4223-bb53-35de9edab42a	true	userinfo.token.claim
c3821338-5296-4223-bb53-35de9edab42a	birthdate	user.attribute
c3821338-5296-4223-bb53-35de9edab42a	true	id.token.claim
c3821338-5296-4223-bb53-35de9edab42a	true	access.token.claim
c3821338-5296-4223-bb53-35de9edab42a	birthdate	claim.name
c3821338-5296-4223-bb53-35de9edab42a	String	jsonType.label
ea67f052-e964-4dbc-9622-abced04a9c2e	true	introspection.token.claim
ea67f052-e964-4dbc-9622-abced04a9c2e	true	userinfo.token.claim
ea67f052-e964-4dbc-9622-abced04a9c2e	username	user.attribute
ea67f052-e964-4dbc-9622-abced04a9c2e	true	id.token.claim
ea67f052-e964-4dbc-9622-abced04a9c2e	true	access.token.claim
ea67f052-e964-4dbc-9622-abced04a9c2e	preferred_username	claim.name
ea67f052-e964-4dbc-9622-abced04a9c2e	String	jsonType.label
f45f2f88-371c-4505-bb53-340ac78f1294	true	introspection.token.claim
f45f2f88-371c-4505-bb53-340ac78f1294	true	userinfo.token.claim
f45f2f88-371c-4505-bb53-340ac78f1294	updatedAt	user.attribute
f45f2f88-371c-4505-bb53-340ac78f1294	true	id.token.claim
f45f2f88-371c-4505-bb53-340ac78f1294	true	access.token.claim
f45f2f88-371c-4505-bb53-340ac78f1294	updated_at	claim.name
f45f2f88-371c-4505-bb53-340ac78f1294	long	jsonType.label
07bcb879-9c1c-4d5a-9470-b8f6744e60b0	true	introspection.token.claim
07bcb879-9c1c-4d5a-9470-b8f6744e60b0	true	userinfo.token.claim
07bcb879-9c1c-4d5a-9470-b8f6744e60b0	emailVerified	user.attribute
07bcb879-9c1c-4d5a-9470-b8f6744e60b0	true	id.token.claim
07bcb879-9c1c-4d5a-9470-b8f6744e60b0	true	access.token.claim
07bcb879-9c1c-4d5a-9470-b8f6744e60b0	email_verified	claim.name
07bcb879-9c1c-4d5a-9470-b8f6744e60b0	boolean	jsonType.label
21dc2a54-fee8-40ff-815c-992db6d69593	true	introspection.token.claim
21dc2a54-fee8-40ff-815c-992db6d69593	true	userinfo.token.claim
21dc2a54-fee8-40ff-815c-992db6d69593	email	user.attribute
21dc2a54-fee8-40ff-815c-992db6d69593	true	id.token.claim
21dc2a54-fee8-40ff-815c-992db6d69593	true	access.token.claim
21dc2a54-fee8-40ff-815c-992db6d69593	email	claim.name
21dc2a54-fee8-40ff-815c-992db6d69593	String	jsonType.label
e7607f30-45a2-4201-bbc4-3abffb08ae9c	formatted	user.attribute.formatted
e7607f30-45a2-4201-bbc4-3abffb08ae9c	country	user.attribute.country
e7607f30-45a2-4201-bbc4-3abffb08ae9c	true	introspection.token.claim
e7607f30-45a2-4201-bbc4-3abffb08ae9c	postal_code	user.attribute.postal_code
e7607f30-45a2-4201-bbc4-3abffb08ae9c	true	userinfo.token.claim
e7607f30-45a2-4201-bbc4-3abffb08ae9c	street	user.attribute.street
e7607f30-45a2-4201-bbc4-3abffb08ae9c	true	id.token.claim
e7607f30-45a2-4201-bbc4-3abffb08ae9c	region	user.attribute.region
e7607f30-45a2-4201-bbc4-3abffb08ae9c	true	access.token.claim
e7607f30-45a2-4201-bbc4-3abffb08ae9c	locality	user.attribute.locality
45b6f972-adf7-4da4-a9da-6323e7b7deb6	true	introspection.token.claim
45b6f972-adf7-4da4-a9da-6323e7b7deb6	true	userinfo.token.claim
45b6f972-adf7-4da4-a9da-6323e7b7deb6	phoneNumber	user.attribute
45b6f972-adf7-4da4-a9da-6323e7b7deb6	true	id.token.claim
45b6f972-adf7-4da4-a9da-6323e7b7deb6	true	access.token.claim
45b6f972-adf7-4da4-a9da-6323e7b7deb6	phone_number	claim.name
45b6f972-adf7-4da4-a9da-6323e7b7deb6	String	jsonType.label
895c5d00-42f7-4293-a06c-30021aca4580	true	introspection.token.claim
895c5d00-42f7-4293-a06c-30021aca4580	true	userinfo.token.claim
895c5d00-42f7-4293-a06c-30021aca4580	phoneNumberVerified	user.attribute
895c5d00-42f7-4293-a06c-30021aca4580	true	id.token.claim
895c5d00-42f7-4293-a06c-30021aca4580	true	access.token.claim
895c5d00-42f7-4293-a06c-30021aca4580	phone_number_verified	claim.name
895c5d00-42f7-4293-a06c-30021aca4580	boolean	jsonType.label
037d1dca-8d16-4144-ad59-436f8c4be18d	true	introspection.token.claim
037d1dca-8d16-4144-ad59-436f8c4be18d	true	multivalued
037d1dca-8d16-4144-ad59-436f8c4be18d	foo	user.attribute
037d1dca-8d16-4144-ad59-436f8c4be18d	true	access.token.claim
037d1dca-8d16-4144-ad59-436f8c4be18d	resource_access.${client_id}.roles	claim.name
037d1dca-8d16-4144-ad59-436f8c4be18d	String	jsonType.label
5d44dbda-719d-44ce-9637-3aa18d485158	true	introspection.token.claim
5d44dbda-719d-44ce-9637-3aa18d485158	true	multivalued
5d44dbda-719d-44ce-9637-3aa18d485158	foo	user.attribute
5d44dbda-719d-44ce-9637-3aa18d485158	true	access.token.claim
5d44dbda-719d-44ce-9637-3aa18d485158	realm_access.roles	claim.name
5d44dbda-719d-44ce-9637-3aa18d485158	String	jsonType.label
b93e7557-3d20-4a3e-8db4-4f146e15debe	true	introspection.token.claim
b93e7557-3d20-4a3e-8db4-4f146e15debe	true	access.token.claim
e24b8235-d120-4b2d-b734-eed9fe885b9e	true	introspection.token.claim
e24b8235-d120-4b2d-b734-eed9fe885b9e	true	access.token.claim
28879a80-1b1f-4602-a00d-f584ead3f9c9	true	introspection.token.claim
28879a80-1b1f-4602-a00d-f584ead3f9c9	true	userinfo.token.claim
28879a80-1b1f-4602-a00d-f584ead3f9c9	username	user.attribute
28879a80-1b1f-4602-a00d-f584ead3f9c9	true	id.token.claim
28879a80-1b1f-4602-a00d-f584ead3f9c9	true	access.token.claim
28879a80-1b1f-4602-a00d-f584ead3f9c9	upn	claim.name
28879a80-1b1f-4602-a00d-f584ead3f9c9	String	jsonType.label
cc84ceaa-64b0-4d31-a90a-f6bfe565ee8c	true	introspection.token.claim
cc84ceaa-64b0-4d31-a90a-f6bfe565ee8c	true	multivalued
cc84ceaa-64b0-4d31-a90a-f6bfe565ee8c	foo	user.attribute
cc84ceaa-64b0-4d31-a90a-f6bfe565ee8c	true	id.token.claim
cc84ceaa-64b0-4d31-a90a-f6bfe565ee8c	true	access.token.claim
cc84ceaa-64b0-4d31-a90a-f6bfe565ee8c	groups	claim.name
cc84ceaa-64b0-4d31-a90a-f6bfe565ee8c	String	jsonType.label
16e3fd9f-e292-49cf-97e2-318898db3a66	true	introspection.token.claim
16e3fd9f-e292-49cf-97e2-318898db3a66	true	id.token.claim
16e3fd9f-e292-49cf-97e2-318898db3a66	true	access.token.claim
ad9ccb25-d883-40f4-a0c7-e2a9edb042a8	AUTH_TIME	user.session.note
ad9ccb25-d883-40f4-a0c7-e2a9edb042a8	true	introspection.token.claim
ad9ccb25-d883-40f4-a0c7-e2a9edb042a8	true	id.token.claim
ad9ccb25-d883-40f4-a0c7-e2a9edb042a8	true	access.token.claim
ad9ccb25-d883-40f4-a0c7-e2a9edb042a8	auth_time	claim.name
ad9ccb25-d883-40f4-a0c7-e2a9edb042a8	long	jsonType.label
c32e9149-7670-418c-91fb-eaf43f7f2f2f	true	introspection.token.claim
c32e9149-7670-418c-91fb-eaf43f7f2f2f	true	access.token.claim
43afb46c-478b-4f49-a77c-4b39b555377c	client_id	user.session.note
43afb46c-478b-4f49-a77c-4b39b555377c	true	introspection.token.claim
43afb46c-478b-4f49-a77c-4b39b555377c	true	id.token.claim
43afb46c-478b-4f49-a77c-4b39b555377c	true	access.token.claim
43afb46c-478b-4f49-a77c-4b39b555377c	client_id	claim.name
43afb46c-478b-4f49-a77c-4b39b555377c	String	jsonType.label
6ac892b1-3815-48c1-a331-03309d6f0867	clientAddress	user.session.note
6ac892b1-3815-48c1-a331-03309d6f0867	true	introspection.token.claim
6ac892b1-3815-48c1-a331-03309d6f0867	true	id.token.claim
6ac892b1-3815-48c1-a331-03309d6f0867	true	access.token.claim
6ac892b1-3815-48c1-a331-03309d6f0867	clientAddress	claim.name
6ac892b1-3815-48c1-a331-03309d6f0867	String	jsonType.label
8b06ca6c-31e6-4a6a-ae6d-488b1aa2a2e2	clientHost	user.session.note
8b06ca6c-31e6-4a6a-ae6d-488b1aa2a2e2	true	introspection.token.claim
8b06ca6c-31e6-4a6a-ae6d-488b1aa2a2e2	true	id.token.claim
8b06ca6c-31e6-4a6a-ae6d-488b1aa2a2e2	true	access.token.claim
8b06ca6c-31e6-4a6a-ae6d-488b1aa2a2e2	clientHost	claim.name
8b06ca6c-31e6-4a6a-ae6d-488b1aa2a2e2	String	jsonType.label
9c7c2ae6-8824-4087-a642-6f081f1a6b86	true	introspection.token.claim
9c7c2ae6-8824-4087-a642-6f081f1a6b86	true	multivalued
9c7c2ae6-8824-4087-a642-6f081f1a6b86	true	id.token.claim
9c7c2ae6-8824-4087-a642-6f081f1a6b86	true	access.token.claim
9c7c2ae6-8824-4087-a642-6f081f1a6b86	organization	claim.name
9c7c2ae6-8824-4087-a642-6f081f1a6b86	String	jsonType.label
8308b1e8-783c-4a7d-8f7e-04f1e98686fc	formatted	user.attribute.formatted
8308b1e8-783c-4a7d-8f7e-04f1e98686fc	country	user.attribute.country
8308b1e8-783c-4a7d-8f7e-04f1e98686fc	postal_code	user.attribute.postal_code
8308b1e8-783c-4a7d-8f7e-04f1e98686fc	true	userinfo.token.claim
8308b1e8-783c-4a7d-8f7e-04f1e98686fc	street	user.attribute.street
8308b1e8-783c-4a7d-8f7e-04f1e98686fc	true	id.token.claim
8308b1e8-783c-4a7d-8f7e-04f1e98686fc	region	user.attribute.region
8308b1e8-783c-4a7d-8f7e-04f1e98686fc	true	access.token.claim
8308b1e8-783c-4a7d-8f7e-04f1e98686fc	locality	user.attribute.locality
44b8acd8-9363-4391-915f-cd0e602a469f	AUTH_TIME	user.session.note
44b8acd8-9363-4391-915f-cd0e602a469f	true	introspection.token.claim
44b8acd8-9363-4391-915f-cd0e602a469f	true	userinfo.token.claim
44b8acd8-9363-4391-915f-cd0e602a469f	true	id.token.claim
44b8acd8-9363-4391-915f-cd0e602a469f	true	access.token.claim
44b8acd8-9363-4391-915f-cd0e602a469f	auth_time	claim.name
44b8acd8-9363-4391-915f-cd0e602a469f	long	jsonType.label
c7a8f16f-64a2-4730-939b-f282739f5d03	true	introspection.token.claim
c7a8f16f-64a2-4730-939b-f282739f5d03	true	access.token.claim
75ce3646-48cf-431e-b54b-2d88d943ebd6	email	user.attribute
75ce3646-48cf-431e-b54b-2d88d943ebd6	true	id.token.claim
75ce3646-48cf-431e-b54b-2d88d943ebd6	true	access.token.claim
75ce3646-48cf-431e-b54b-2d88d943ebd6	email	claim.name
75ce3646-48cf-431e-b54b-2d88d943ebd6	String	jsonType.label
75ce3646-48cf-431e-b54b-2d88d943ebd6	true	userinfo.token.claim
a8ea96d0-7bb1-46d8-bb3d-87e238b42e8b	emailVerified	user.attribute
a8ea96d0-7bb1-46d8-bb3d-87e238b42e8b	true	id.token.claim
a8ea96d0-7bb1-46d8-bb3d-87e238b42e8b	true	access.token.claim
a8ea96d0-7bb1-46d8-bb3d-87e238b42e8b	email_verified	claim.name
a8ea96d0-7bb1-46d8-bb3d-87e238b42e8b	boolean	jsonType.label
a8ea96d0-7bb1-46d8-bb3d-87e238b42e8b	true	userinfo.token.claim
8520db0d-2eb0-4c15-8d51-9e5031cc7ab0	true	introspection.token.claim
8520db0d-2eb0-4c15-8d51-9e5031cc7ab0	true	userinfo.token.claim
8520db0d-2eb0-4c15-8d51-9e5031cc7ab0	elixir_id	user.attribute
8520db0d-2eb0-4c15-8d51-9e5031cc7ab0	true	id.token.claim
8520db0d-2eb0-4c15-8d51-9e5031cc7ab0	true	access.token.claim
8520db0d-2eb0-4c15-8d51-9e5031cc7ab0	elixir_id	claim.name
8520db0d-2eb0-4c15-8d51-9e5031cc7ab0	String	jsonType.label
25c91c90-20af-4c81-be19-fe560f9690f2	true	multivalued
25c91c90-20af-4c81-be19-fe560f9690f2	true	userinfo.token.claim
25c91c90-20af-4c81-be19-fe560f9690f2	foo	user.attribute
25c91c90-20af-4c81-be19-fe560f9690f2	true	id.token.claim
25c91c90-20af-4c81-be19-fe560f9690f2	true	access.token.claim
25c91c90-20af-4c81-be19-fe560f9690f2	groups	claim.name
25c91c90-20af-4c81-be19-fe560f9690f2	String	jsonType.label
f2419169-8d1a-42d6-a9e5-35c82f32c8b0	username	user.attribute
f2419169-8d1a-42d6-a9e5-35c82f32c8b0	true	id.token.claim
f2419169-8d1a-42d6-a9e5-35c82f32c8b0	true	access.token.claim
f2419169-8d1a-42d6-a9e5-35c82f32c8b0	upn	claim.name
f2419169-8d1a-42d6-a9e5-35c82f32c8b0	String	jsonType.label
f2419169-8d1a-42d6-a9e5-35c82f32c8b0	true	userinfo.token.claim
ca601f00-8cae-4159-acb3-85dca0a7521d	phoneNumberVerified	user.attribute
ca601f00-8cae-4159-acb3-85dca0a7521d	true	id.token.claim
ca601f00-8cae-4159-acb3-85dca0a7521d	true	access.token.claim
ca601f00-8cae-4159-acb3-85dca0a7521d	phone_number_verified	claim.name
ca601f00-8cae-4159-acb3-85dca0a7521d	boolean	jsonType.label
ca601f00-8cae-4159-acb3-85dca0a7521d	true	userinfo.token.claim
e6a1c822-779b-48e1-aadc-fb75f11b3bf2	phoneNumber	user.attribute
e6a1c822-779b-48e1-aadc-fb75f11b3bf2	true	id.token.claim
e6a1c822-779b-48e1-aadc-fb75f11b3bf2	true	access.token.claim
e6a1c822-779b-48e1-aadc-fb75f11b3bf2	phone_number	claim.name
e6a1c822-779b-48e1-aadc-fb75f11b3bf2	String	jsonType.label
e6a1c822-779b-48e1-aadc-fb75f11b3bf2	true	userinfo.token.claim
17ba9a68-6ad6-459b-8ea1-79a3503204d6	clientHost	user.session.note
17ba9a68-6ad6-459b-8ea1-79a3503204d6	true	introspection.token.claim
17ba9a68-6ad6-459b-8ea1-79a3503204d6	true	userinfo.token.claim
17ba9a68-6ad6-459b-8ea1-79a3503204d6	true	id.token.claim
17ba9a68-6ad6-459b-8ea1-79a3503204d6	true	access.token.claim
17ba9a68-6ad6-459b-8ea1-79a3503204d6	clientHost	claim.name
17ba9a68-6ad6-459b-8ea1-79a3503204d6	String	jsonType.label
2a559ea2-f543-4925-8ffa-9b1cfe502e5e	client_id	user.session.note
2a559ea2-f543-4925-8ffa-9b1cfe502e5e	true	introspection.token.claim
2a559ea2-f543-4925-8ffa-9b1cfe502e5e	true	userinfo.token.claim
2a559ea2-f543-4925-8ffa-9b1cfe502e5e	true	id.token.claim
2a559ea2-f543-4925-8ffa-9b1cfe502e5e	true	access.token.claim
2a559ea2-f543-4925-8ffa-9b1cfe502e5e	client_id	claim.name
2a559ea2-f543-4925-8ffa-9b1cfe502e5e	String	jsonType.label
5e4d9a81-bdce-4da5-8151-5bc870ebaeef	clientAddress	user.session.note
5e4d9a81-bdce-4da5-8151-5bc870ebaeef	true	introspection.token.claim
5e4d9a81-bdce-4da5-8151-5bc870ebaeef	true	userinfo.token.claim
5e4d9a81-bdce-4da5-8151-5bc870ebaeef	true	id.token.claim
5e4d9a81-bdce-4da5-8151-5bc870ebaeef	true	access.token.claim
5e4d9a81-bdce-4da5-8151-5bc870ebaeef	clientAddress	claim.name
5e4d9a81-bdce-4da5-8151-5bc870ebaeef	String	jsonType.label
399d1e5f-f9c4-400f-81b5-397de8597ffb	foo	user.attribute
399d1e5f-f9c4-400f-81b5-397de8597ffb	true	access.token.claim
399d1e5f-f9c4-400f-81b5-397de8597ffb	realm_access.roles	claim.name
399d1e5f-f9c4-400f-81b5-397de8597ffb	String	jsonType.label
399d1e5f-f9c4-400f-81b5-397de8597ffb	true	multivalued
dd7addec-1976-477e-ba66-ee77869156d7	foo	user.attribute
dd7addec-1976-477e-ba66-ee77869156d7	true	access.token.claim
dd7addec-1976-477e-ba66-ee77869156d7	resource_access.${client_id}.roles	claim.name
dd7addec-1976-477e-ba66-ee77869156d7	String	jsonType.label
dd7addec-1976-477e-ba66-ee77869156d7	true	multivalued
18c4fae8-fdb8-476d-aea7-7b2384667a11	firstName	user.attribute
18c4fae8-fdb8-476d-aea7-7b2384667a11	true	id.token.claim
18c4fae8-fdb8-476d-aea7-7b2384667a11	true	access.token.claim
18c4fae8-fdb8-476d-aea7-7b2384667a11	given_name	claim.name
18c4fae8-fdb8-476d-aea7-7b2384667a11	String	jsonType.label
18c4fae8-fdb8-476d-aea7-7b2384667a11	true	userinfo.token.claim
23510843-4c32-4bfe-848a-fed38392e1c5	profile	user.attribute
23510843-4c32-4bfe-848a-fed38392e1c5	true	id.token.claim
23510843-4c32-4bfe-848a-fed38392e1c5	true	access.token.claim
23510843-4c32-4bfe-848a-fed38392e1c5	profile	claim.name
23510843-4c32-4bfe-848a-fed38392e1c5	String	jsonType.label
23510843-4c32-4bfe-848a-fed38392e1c5	true	userinfo.token.claim
2e648938-e959-4e17-a208-861d8d4eacd5	locale	user.attribute
2e648938-e959-4e17-a208-861d8d4eacd5	true	id.token.claim
2e648938-e959-4e17-a208-861d8d4eacd5	true	access.token.claim
2e648938-e959-4e17-a208-861d8d4eacd5	locale	claim.name
2e648938-e959-4e17-a208-861d8d4eacd5	String	jsonType.label
2e648938-e959-4e17-a208-861d8d4eacd5	true	userinfo.token.claim
344b9514-c119-4284-95da-9fb29e6e9f66	middleName	user.attribute
344b9514-c119-4284-95da-9fb29e6e9f66	true	id.token.claim
344b9514-c119-4284-95da-9fb29e6e9f66	true	access.token.claim
344b9514-c119-4284-95da-9fb29e6e9f66	middle_name	claim.name
344b9514-c119-4284-95da-9fb29e6e9f66	String	jsonType.label
344b9514-c119-4284-95da-9fb29e6e9f66	true	userinfo.token.claim
3b3c20dd-72c9-4898-90ca-bf4de8658e96	lastName	user.attribute
3b3c20dd-72c9-4898-90ca-bf4de8658e96	true	id.token.claim
3b3c20dd-72c9-4898-90ca-bf4de8658e96	true	access.token.claim
3b3c20dd-72c9-4898-90ca-bf4de8658e96	family_name	claim.name
3b3c20dd-72c9-4898-90ca-bf4de8658e96	String	jsonType.label
3b3c20dd-72c9-4898-90ca-bf4de8658e96	true	userinfo.token.claim
3d9f3f57-df77-470a-9ce1-a4a49cb6ea9c	true	id.token.claim
3d9f3f57-df77-470a-9ce1-a4a49cb6ea9c	true	access.token.claim
3d9f3f57-df77-470a-9ce1-a4a49cb6ea9c	true	userinfo.token.claim
438728ae-3c2a-4faa-83f7-97fda8802058	gender	user.attribute
438728ae-3c2a-4faa-83f7-97fda8802058	true	id.token.claim
438728ae-3c2a-4faa-83f7-97fda8802058	true	access.token.claim
438728ae-3c2a-4faa-83f7-97fda8802058	gender	claim.name
438728ae-3c2a-4faa-83f7-97fda8802058	String	jsonType.label
438728ae-3c2a-4faa-83f7-97fda8802058	true	userinfo.token.claim
51d8af12-a61e-45ef-b1c7-8c0fb16dc835	updatedAt	user.attribute
51d8af12-a61e-45ef-b1c7-8c0fb16dc835	true	id.token.claim
51d8af12-a61e-45ef-b1c7-8c0fb16dc835	true	access.token.claim
51d8af12-a61e-45ef-b1c7-8c0fb16dc835	updated_at	claim.name
51d8af12-a61e-45ef-b1c7-8c0fb16dc835	long	jsonType.label
51d8af12-a61e-45ef-b1c7-8c0fb16dc835	true	userinfo.token.claim
87f85b47-3189-4af2-8651-0663a4af6c4e	zoneinfo	user.attribute
87f85b47-3189-4af2-8651-0663a4af6c4e	true	id.token.claim
87f85b47-3189-4af2-8651-0663a4af6c4e	true	access.token.claim
87f85b47-3189-4af2-8651-0663a4af6c4e	zoneinfo	claim.name
87f85b47-3189-4af2-8651-0663a4af6c4e	String	jsonType.label
87f85b47-3189-4af2-8651-0663a4af6c4e	true	userinfo.token.claim
8d05a238-9c89-4548-bf77-ec690e826734	picture	user.attribute
8d05a238-9c89-4548-bf77-ec690e826734	true	id.token.claim
8d05a238-9c89-4548-bf77-ec690e826734	true	access.token.claim
8d05a238-9c89-4548-bf77-ec690e826734	picture	claim.name
8d05a238-9c89-4548-bf77-ec690e826734	String	jsonType.label
8d05a238-9c89-4548-bf77-ec690e826734	true	userinfo.token.claim
97aefc80-f08e-4f41-807d-5236395ec89f	website	user.attribute
97aefc80-f08e-4f41-807d-5236395ec89f	true	id.token.claim
97aefc80-f08e-4f41-807d-5236395ec89f	true	access.token.claim
97aefc80-f08e-4f41-807d-5236395ec89f	website	claim.name
97aefc80-f08e-4f41-807d-5236395ec89f	String	jsonType.label
97aefc80-f08e-4f41-807d-5236395ec89f	true	userinfo.token.claim
b7679e3c-23de-49e1-ae26-d58dac54b6cd	birthdate	user.attribute
b7679e3c-23de-49e1-ae26-d58dac54b6cd	true	id.token.claim
b7679e3c-23de-49e1-ae26-d58dac54b6cd	true	access.token.claim
b7679e3c-23de-49e1-ae26-d58dac54b6cd	birthdate	claim.name
b7679e3c-23de-49e1-ae26-d58dac54b6cd	String	jsonType.label
b7679e3c-23de-49e1-ae26-d58dac54b6cd	true	userinfo.token.claim
c2bede9d-9d79-4dc1-8ed0-7689baa4de73	username	user.attribute
c2bede9d-9d79-4dc1-8ed0-7689baa4de73	true	id.token.claim
c2bede9d-9d79-4dc1-8ed0-7689baa4de73	true	access.token.claim
c2bede9d-9d79-4dc1-8ed0-7689baa4de73	preferred_username	claim.name
c2bede9d-9d79-4dc1-8ed0-7689baa4de73	String	jsonType.label
c2bede9d-9d79-4dc1-8ed0-7689baa4de73	true	userinfo.token.claim
e8241ff5-2278-4172-9ba4-6d60548a78fd	nickname	user.attribute
e8241ff5-2278-4172-9ba4-6d60548a78fd	true	id.token.claim
e8241ff5-2278-4172-9ba4-6d60548a78fd	true	access.token.claim
e8241ff5-2278-4172-9ba4-6d60548a78fd	nickname	claim.name
e8241ff5-2278-4172-9ba4-6d60548a78fd	String	jsonType.label
e8241ff5-2278-4172-9ba4-6d60548a78fd	true	userinfo.token.claim
da7673c2-0335-402b-866b-70beb6805637	false	single
da7673c2-0335-402b-866b-70beb6805637	Basic	attribute.nameformat
da7673c2-0335-402b-866b-70beb6805637	Role	attribute.name
d18e6224-a4a7-4cf3-8282-40e4706fc0c7	true	id.token.claim
d18e6224-a4a7-4cf3-8282-40e4706fc0c7	true	access.token.claim
d18e6224-a4a7-4cf3-8282-40e4706fc0c7	true	userinfo.token.claim
2f1720aa-67b3-497e-8e38-eca0d3ddb067	client_id	user.session.note
2f1720aa-67b3-497e-8e38-eca0d3ddb067	true	id.token.claim
2f1720aa-67b3-497e-8e38-eca0d3ddb067	true	access.token.claim
2f1720aa-67b3-497e-8e38-eca0d3ddb067	client_id	claim.name
2f1720aa-67b3-497e-8e38-eca0d3ddb067	String	jsonType.label
2f1720aa-67b3-497e-8e38-eca0d3ddb067	true	userinfo.token.claim
3e6169b4-267d-48c4-9a98-a4c832686797	clientAddress	user.session.note
3e6169b4-267d-48c4-9a98-a4c832686797	true	id.token.claim
3e6169b4-267d-48c4-9a98-a4c832686797	true	access.token.claim
3e6169b4-267d-48c4-9a98-a4c832686797	clientAddress	claim.name
3e6169b4-267d-48c4-9a98-a4c832686797	String	jsonType.label
3e6169b4-267d-48c4-9a98-a4c832686797	true	userinfo.token.claim
d6504f0e-2480-4ad0-8156-18fef8a12e47	clientHost	user.session.note
d6504f0e-2480-4ad0-8156-18fef8a12e47	true	id.token.claim
d6504f0e-2480-4ad0-8156-18fef8a12e47	true	access.token.claim
d6504f0e-2480-4ad0-8156-18fef8a12e47	clientHost	claim.name
d6504f0e-2480-4ad0-8156-18fef8a12e47	String	jsonType.label
d6504f0e-2480-4ad0-8156-18fef8a12e47	true	userinfo.token.claim
1adb53a6-597c-44a2-91aa-a15349f61efc	locale	user.attribute
1adb53a6-597c-44a2-91aa-a15349f61efc	true	id.token.claim
1adb53a6-597c-44a2-91aa-a15349f61efc	true	access.token.claim
1adb53a6-597c-44a2-91aa-a15349f61efc	locale	claim.name
1adb53a6-597c-44a2-91aa-a15349f61efc	String	jsonType.label
1adb53a6-597c-44a2-91aa-a15349f61efc	true	userinfo.token.claim
\.


--
-- Data for Name: realm; Type: TABLE DATA; Schema: public; Owner: keycloak
--

COPY public.realm (id, access_code_lifespan, user_action_lifespan, access_token_lifespan, account_theme, admin_theme, email_theme, enabled, events_enabled, events_expiration, login_theme, name, not_before, password_policy, registration_allowed, remember_me, reset_password_allowed, social, ssl_required, sso_idle_timeout, sso_max_lifespan, update_profile_on_soc_login, verify_email, master_admin_client, login_lifespan, internationalization_enabled, default_locale, reg_email_as_username, admin_events_enabled, admin_events_details_enabled, edit_username_allowed, otp_policy_counter, otp_policy_window, otp_policy_period, otp_policy_digits, otp_policy_alg, otp_policy_type, browser_flow, registration_flow, direct_grant_flow, reset_credentials_flow, client_auth_flow, offline_session_idle_timeout, revoke_refresh_token, access_token_life_implicit, login_with_email_allowed, duplicate_emails_allowed, docker_auth_flow, refresh_token_max_reuse, allow_user_managed_access, sso_max_lifespan_remember_me, sso_idle_timeout_remember_me, default_role) FROM stdin;
86b2aa03-1225-4835-8758-60f4e03293c9	60	300	60	\N	\N	\N	t	f	0	\N	master	0	\N	f	f	f	f	EXTERNAL	1800	36000	f	f	4109f0ef-0360-401b-b3c4-8e8fff5a4c07	1800	f	\N	f	f	f	f	0	1	30	6	HmacSHA1	totp	5ee5265d-2b0a-4b44-8dfd-58462be34154	76fb239a-cf69-42ef-a4f4-a66400fdea0e	4876e118-2f71-4682-820b-d99a35ef1acb	d4cfa9ae-6a39-41c0-8c2c-62a11c3d2117	63e59bd2-5003-4b43-b979-d7d3de974e6e	2592000	f	900	t	f	863d9eec-c10b-48fc-8356-ef79b8c47c23	0	f	0	0	b3054bb8-c40e-4a91-a086-c364629ce753
6f348afb-6f1f-428c-a4f9-5f8e2374a075	60	300	300	\N	\N	\N	t	f	0	\N	gdi	0	\N	f	f	f	f	EXTERNAL	1800	36000	f	f	d9b73b9c-e8ac-4da7-aafb-9e39584eab85	1800	t	en	f	f	f	f	0	1	30	6	HmacSHA1	totp	d53e6878-4a08-4737-8ec8-a893c1a25055	16411ffa-cdf9-40bb-9d06-40de13d84c8e	d9478b18-9639-449e-85d6-56540f0803a1	f31bc3bf-8954-4ede-a514-84264864e7e3	27b45afc-dacc-42d2-b505-1cde88d20135	2592000	f	900	t	f	2c65eda3-a182-4a11-9ade-f61b78d78c6d	0	f	0	0	93059c31-b7bc-4d3d-bc95-dc94a5ebb7ad
\.


--
-- Data for Name: realm_attribute; Type: TABLE DATA; Schema: public; Owner: keycloak
--

COPY public.realm_attribute (name, realm_id, value) FROM stdin;
_browser_header.contentSecurityPolicyReportOnly	86b2aa03-1225-4835-8758-60f4e03293c9	
_browser_header.xContentTypeOptions	86b2aa03-1225-4835-8758-60f4e03293c9	nosniff
_browser_header.referrerPolicy	86b2aa03-1225-4835-8758-60f4e03293c9	no-referrer
_browser_header.xRobotsTag	86b2aa03-1225-4835-8758-60f4e03293c9	none
_browser_header.xFrameOptions	86b2aa03-1225-4835-8758-60f4e03293c9	SAMEORIGIN
_browser_header.contentSecurityPolicy	86b2aa03-1225-4835-8758-60f4e03293c9	frame-src 'self'; frame-ancestors 'self'; object-src 'none';
_browser_header.strictTransportSecurity	86b2aa03-1225-4835-8758-60f4e03293c9	max-age=31536000; includeSubDomains
bruteForceProtected	86b2aa03-1225-4835-8758-60f4e03293c9	false
permanentLockout	86b2aa03-1225-4835-8758-60f4e03293c9	false
maxTemporaryLockouts	86b2aa03-1225-4835-8758-60f4e03293c9	0
bruteForceStrategy	86b2aa03-1225-4835-8758-60f4e03293c9	MULTIPLE
maxFailureWaitSeconds	86b2aa03-1225-4835-8758-60f4e03293c9	900
minimumQuickLoginWaitSeconds	86b2aa03-1225-4835-8758-60f4e03293c9	60
waitIncrementSeconds	86b2aa03-1225-4835-8758-60f4e03293c9	60
quickLoginCheckMilliSeconds	86b2aa03-1225-4835-8758-60f4e03293c9	1000
maxDeltaTimeSeconds	86b2aa03-1225-4835-8758-60f4e03293c9	43200
failureFactor	86b2aa03-1225-4835-8758-60f4e03293c9	30
realmReusableOtpCode	86b2aa03-1225-4835-8758-60f4e03293c9	false
firstBrokerLoginFlowId	86b2aa03-1225-4835-8758-60f4e03293c9	04b6912a-4ca7-42ac-8801-cacea86234f3
displayName	86b2aa03-1225-4835-8758-60f4e03293c9	Keycloak
displayNameHtml	86b2aa03-1225-4835-8758-60f4e03293c9	<div class="kc-logo-text"><span>Keycloak</span></div>
defaultSignatureAlgorithm	86b2aa03-1225-4835-8758-60f4e03293c9	RS256
offlineSessionMaxLifespanEnabled	86b2aa03-1225-4835-8758-60f4e03293c9	false
offlineSessionMaxLifespan	86b2aa03-1225-4835-8758-60f4e03293c9	5184000
_browser_header.contentSecurityPolicyReportOnly	6f348afb-6f1f-428c-a4f9-5f8e2374a075	
_browser_header.xContentTypeOptions	6f348afb-6f1f-428c-a4f9-5f8e2374a075	nosniff
_browser_header.referrerPolicy	6f348afb-6f1f-428c-a4f9-5f8e2374a075	no-referrer
_browser_header.xRobotsTag	6f348afb-6f1f-428c-a4f9-5f8e2374a075	none
_browser_header.xFrameOptions	6f348afb-6f1f-428c-a4f9-5f8e2374a075	SAMEORIGIN
_browser_header.contentSecurityPolicy	6f348afb-6f1f-428c-a4f9-5f8e2374a075	frame-src 'self'; frame-ancestors 'self'; object-src 'none';
_browser_header.strictTransportSecurity	6f348afb-6f1f-428c-a4f9-5f8e2374a075	max-age=31536000; includeSubDomains
bruteForceProtected	6f348afb-6f1f-428c-a4f9-5f8e2374a075	false
permanentLockout	6f348afb-6f1f-428c-a4f9-5f8e2374a075	false
maxTemporaryLockouts	6f348afb-6f1f-428c-a4f9-5f8e2374a075	0
bruteForceStrategy	6f348afb-6f1f-428c-a4f9-5f8e2374a075	MULTIPLE
maxFailureWaitSeconds	6f348afb-6f1f-428c-a4f9-5f8e2374a075	900
minimumQuickLoginWaitSeconds	6f348afb-6f1f-428c-a4f9-5f8e2374a075	60
waitIncrementSeconds	6f348afb-6f1f-428c-a4f9-5f8e2374a075	60
quickLoginCheckMilliSeconds	6f348afb-6f1f-428c-a4f9-5f8e2374a075	1000
maxDeltaTimeSeconds	6f348afb-6f1f-428c-a4f9-5f8e2374a075	43200
failureFactor	6f348afb-6f1f-428c-a4f9-5f8e2374a075	30
realmReusableOtpCode	6f348afb-6f1f-428c-a4f9-5f8e2374a075	false
defaultSignatureAlgorithm	6f348afb-6f1f-428c-a4f9-5f8e2374a075	RS256
offlineSessionMaxLifespanEnabled	6f348afb-6f1f-428c-a4f9-5f8e2374a075	false
offlineSessionMaxLifespan	6f348afb-6f1f-428c-a4f9-5f8e2374a075	5184000
clientSessionIdleTimeout	6f348afb-6f1f-428c-a4f9-5f8e2374a075	0
clientSessionMaxLifespan	6f348afb-6f1f-428c-a4f9-5f8e2374a075	0
clientOfflineSessionIdleTimeout	6f348afb-6f1f-428c-a4f9-5f8e2374a075	0
clientOfflineSessionMaxLifespan	6f348afb-6f1f-428c-a4f9-5f8e2374a075	0
actionTokenGeneratedByAdminLifespan	6f348afb-6f1f-428c-a4f9-5f8e2374a075	43200
actionTokenGeneratedByUserLifespan	6f348afb-6f1f-428c-a4f9-5f8e2374a075	300
oauth2DeviceCodeLifespan	6f348afb-6f1f-428c-a4f9-5f8e2374a075	600
oauth2DevicePollingInterval	6f348afb-6f1f-428c-a4f9-5f8e2374a075	5
organizationsEnabled	6f348afb-6f1f-428c-a4f9-5f8e2374a075	false
adminPermissionsEnabled	6f348afb-6f1f-428c-a4f9-5f8e2374a075	false
webAuthnPolicyRpEntityName	6f348afb-6f1f-428c-a4f9-5f8e2374a075	keycloak
webAuthnPolicySignatureAlgorithms	6f348afb-6f1f-428c-a4f9-5f8e2374a075	ES256
webAuthnPolicyRpId	6f348afb-6f1f-428c-a4f9-5f8e2374a075	
webAuthnPolicyAttestationConveyancePreference	6f348afb-6f1f-428c-a4f9-5f8e2374a075	not specified
webAuthnPolicyAuthenticatorAttachment	6f348afb-6f1f-428c-a4f9-5f8e2374a075	not specified
webAuthnPolicyRequireResidentKey	6f348afb-6f1f-428c-a4f9-5f8e2374a075	not specified
webAuthnPolicyUserVerificationRequirement	6f348afb-6f1f-428c-a4f9-5f8e2374a075	not specified
webAuthnPolicyCreateTimeout	6f348afb-6f1f-428c-a4f9-5f8e2374a075	0
webAuthnPolicyAvoidSameAuthenticatorRegister	6f348afb-6f1f-428c-a4f9-5f8e2374a075	false
webAuthnPolicyRpEntityNamePasswordless	6f348afb-6f1f-428c-a4f9-5f8e2374a075	keycloak
webAuthnPolicySignatureAlgorithmsPasswordless	6f348afb-6f1f-428c-a4f9-5f8e2374a075	ES256
webAuthnPolicyRpIdPasswordless	6f348afb-6f1f-428c-a4f9-5f8e2374a075	
webAuthnPolicyAttestationConveyancePreferencePasswordless	6f348afb-6f1f-428c-a4f9-5f8e2374a075	not specified
webAuthnPolicyAuthenticatorAttachmentPasswordless	6f348afb-6f1f-428c-a4f9-5f8e2374a075	not specified
webAuthnPolicyRequireResidentKeyPasswordless	6f348afb-6f1f-428c-a4f9-5f8e2374a075	not specified
webAuthnPolicyUserVerificationRequirementPasswordless	6f348afb-6f1f-428c-a4f9-5f8e2374a075	not specified
webAuthnPolicyCreateTimeoutPasswordless	6f348afb-6f1f-428c-a4f9-5f8e2374a075	0
webAuthnPolicyAvoidSameAuthenticatorRegisterPasswordless	6f348afb-6f1f-428c-a4f9-5f8e2374a075	false
cibaBackchannelTokenDeliveryMode	6f348afb-6f1f-428c-a4f9-5f8e2374a075	poll
cibaExpiresIn	6f348afb-6f1f-428c-a4f9-5f8e2374a075	120
cibaInterval	6f348afb-6f1f-428c-a4f9-5f8e2374a075	5
cibaAuthRequestedUserHint	6f348afb-6f1f-428c-a4f9-5f8e2374a075	login_hint
parRequestUriLifespan	6f348afb-6f1f-428c-a4f9-5f8e2374a075	60
firstBrokerLoginFlowId	6f348afb-6f1f-428c-a4f9-5f8e2374a075	c4a0ed65-c0be-4a58-b0a1-a68873949032
_browser_header.xXSSProtection	6f348afb-6f1f-428c-a4f9-5f8e2374a075	1; mode=block
verifiableCredentialsEnabled	6f348afb-6f1f-428c-a4f9-5f8e2374a075	false
client-policies.profiles	6f348afb-6f1f-428c-a4f9-5f8e2374a075	{"profiles":[]}
client-policies.policies	6f348afb-6f1f-428c-a4f9-5f8e2374a075	{"policies":[]}
\.


--
-- Data for Name: realm_default_groups; Type: TABLE DATA; Schema: public; Owner: keycloak
--

COPY public.realm_default_groups (realm_id, group_id) FROM stdin;
\.


--
-- Data for Name: realm_enabled_event_types; Type: TABLE DATA; Schema: public; Owner: keycloak
--

COPY public.realm_enabled_event_types (realm_id, value) FROM stdin;
\.


--
-- Data for Name: realm_events_listeners; Type: TABLE DATA; Schema: public; Owner: keycloak
--

COPY public.realm_events_listeners (realm_id, value) FROM stdin;
86b2aa03-1225-4835-8758-60f4e03293c9	jboss-logging
6f348afb-6f1f-428c-a4f9-5f8e2374a075	jboss-logging
\.


--
-- Data for Name: realm_localizations; Type: TABLE DATA; Schema: public; Owner: keycloak
--

COPY public.realm_localizations (realm_id, locale, texts) FROM stdin;
6f348afb-6f1f-428c-a4f9-5f8e2374a075	en	{"termsText":"Terms & Conditions v1"}
\.


--
-- Data for Name: realm_required_credential; Type: TABLE DATA; Schema: public; Owner: keycloak
--

COPY public.realm_required_credential (type, form_label, input, secret, realm_id) FROM stdin;
password	password	t	t	86b2aa03-1225-4835-8758-60f4e03293c9
password	password	t	t	6f348afb-6f1f-428c-a4f9-5f8e2374a075
\.


--
-- Data for Name: realm_smtp_config; Type: TABLE DATA; Schema: public; Owner: keycloak
--

COPY public.realm_smtp_config (realm_id, value, name) FROM stdin;
\.


--
-- Data for Name: realm_supported_locales; Type: TABLE DATA; Schema: public; Owner: keycloak
--

COPY public.realm_supported_locales (realm_id, value) FROM stdin;
6f348afb-6f1f-428c-a4f9-5f8e2374a075	en
\.


--
-- Data for Name: redirect_uris; Type: TABLE DATA; Schema: public; Owner: keycloak
--

COPY public.redirect_uris (client_id, value) FROM stdin;
250d0061-d9ce-4ad2-888b-c5d151e2fe6d	/realms/master/account/*
2a479066-384f-44a7-8ca2-7bb08a9c0b90	/realms/master/account/*
f6127f78-7990-4de5-8eba-6721209ae8d9	/admin/master/console/*
476d5095-dbf9-4fe0-bef8-fde1730956f9	/realms/gdi/account/*
632c3653-00fa-4b03-a4ed-81afbb16f16d	/realms/gdi/account/*
49dfabcd-b980-414c-94a8-fdb65533ad2f	http://catalogue.local.onemilliongenomes.eu/*
49dfabcd-b980-414c-94a8-fdb65533ad2f	http://daam.local.onemilliongenomes.eu/*
49dfabcd-b980-414c-94a8-fdb65533ad2f	http://discover.local.onemilliongenomes.eu/*
49dfabcd-b980-414c-94a8-fdb65533ad2f	https://oauth.pstmn.io/v1/callback
545c2160-f604-44d4-98c4-cf209d2d0b9d	/*
08d74ac1-49fc-469d-a687-9ab3b27b69b1	/admin/gdi/console/*
\.


--
-- Data for Name: required_action_config; Type: TABLE DATA; Schema: public; Owner: keycloak
--

COPY public.required_action_config (required_action_id, value, name) FROM stdin;
\.


--
-- Data for Name: required_action_provider; Type: TABLE DATA; Schema: public; Owner: keycloak
--

COPY public.required_action_provider (id, alias, name, realm_id, enabled, default_action, provider_id, priority) FROM stdin;
df1fdab2-00df-410a-89ef-eb053fb10000	VERIFY_EMAIL	Verify Email	86b2aa03-1225-4835-8758-60f4e03293c9	t	f	VERIFY_EMAIL	50
56f368aa-cac9-4586-ac0f-a03c26d4b786	UPDATE_PROFILE	Update Profile	86b2aa03-1225-4835-8758-60f4e03293c9	t	f	UPDATE_PROFILE	40
52948214-d862-49f8-b1b8-71fabcdffade	CONFIGURE_TOTP	Configure OTP	86b2aa03-1225-4835-8758-60f4e03293c9	t	f	CONFIGURE_TOTP	10
e2f72c84-09ae-4fb2-b6db-eb0f9a4c756b	UPDATE_PASSWORD	Update Password	86b2aa03-1225-4835-8758-60f4e03293c9	t	f	UPDATE_PASSWORD	30
1d68a223-2a51-4c4d-a763-9a641852fe4b	TERMS_AND_CONDITIONS	Terms and Conditions	86b2aa03-1225-4835-8758-60f4e03293c9	f	f	TERMS_AND_CONDITIONS	20
b4c01aee-797b-4167-b300-7a515840d2ae	delete_account	Delete Account	86b2aa03-1225-4835-8758-60f4e03293c9	f	f	delete_account	60
716f778a-f3fd-4402-9aec-c5ae34fe3ba1	delete_credential	Delete Credential	86b2aa03-1225-4835-8758-60f4e03293c9	t	f	delete_credential	110
46eefd94-0cdf-4f60-b84c-408d556aa49b	update_user_locale	Update User Locale	86b2aa03-1225-4835-8758-60f4e03293c9	t	f	update_user_locale	1000
5e6a4dbd-c065-4481-811c-f9a50abf2a6f	UPDATE_EMAIL	Update Email	86b2aa03-1225-4835-8758-60f4e03293c9	f	f	UPDATE_EMAIL	70
4fd973bf-7591-419b-bfb6-e12b21c1cdc4	CONFIGURE_RECOVERY_AUTHN_CODES	Recovery Authentication Codes	86b2aa03-1225-4835-8758-60f4e03293c9	t	f	CONFIGURE_RECOVERY_AUTHN_CODES	130
d3cee58c-6e3e-442f-af10-0a7c564c6b60	webauthn-register	Webauthn Register	86b2aa03-1225-4835-8758-60f4e03293c9	t	f	webauthn-register	80
59be194c-ef79-4a60-b61a-e2b3e1b1c4f2	webauthn-register-passwordless	Webauthn Register Passwordless	86b2aa03-1225-4835-8758-60f4e03293c9	t	f	webauthn-register-passwordless	90
535d9d7c-d7e4-4c59-927b-7b2d8a0d3074	VERIFY_PROFILE	Verify Profile	86b2aa03-1225-4835-8758-60f4e03293c9	t	f	VERIFY_PROFILE	100
8bb41ea0-0724-4976-b7e5-e503b6c06fd0	idp_link	Linking Identity Provider	86b2aa03-1225-4835-8758-60f4e03293c9	t	f	idp_link	120
ce4d382a-5da5-48de-9f4c-19f70c7b0d68	CONFIGURE_TOTP	Configure OTP	6f348afb-6f1f-428c-a4f9-5f8e2374a075	t	f	CONFIGURE_TOTP	10
d3f9d748-9e3e-4ade-940b-5cf09fa56909	TERMS_AND_CONDITIONS	Terms and Conditions	6f348afb-6f1f-428c-a4f9-5f8e2374a075	t	t	TERMS_AND_CONDITIONS	20
9eec243a-89b8-4305-b87d-1f70c5f5a7b5	UPDATE_PASSWORD	Update Password	6f348afb-6f1f-428c-a4f9-5f8e2374a075	t	f	UPDATE_PASSWORD	30
e61c3250-e57d-4535-b6c4-616e84c002e2	UPDATE_PROFILE	Update Profile	6f348afb-6f1f-428c-a4f9-5f8e2374a075	t	f	UPDATE_PROFILE	40
7a0acfb3-225e-474f-a956-e0abf8957847	VERIFY_EMAIL	Verify Email	6f348afb-6f1f-428c-a4f9-5f8e2374a075	t	f	VERIFY_EMAIL	50
6b93e5c2-23e9-4ed8-8ad7-1d9593691469	delete_account	Delete Account	6f348afb-6f1f-428c-a4f9-5f8e2374a075	f	f	delete_account	60
9c2b4287-5c60-430a-a344-9fe9c5bd3ac5	webauthn-register	Webauthn Register	6f348afb-6f1f-428c-a4f9-5f8e2374a075	t	f	webauthn-register	70
dd21c785-2e42-4393-84fc-6e5942d45100	webauthn-register-passwordless	Webauthn Register Passwordless	6f348afb-6f1f-428c-a4f9-5f8e2374a075	t	f	webauthn-register-passwordless	80
264f7653-26a7-446c-a651-5052f09ad6ae	delete_credential	Delete Credential	6f348afb-6f1f-428c-a4f9-5f8e2374a075	t	f	delete_credential	110
8e809f29-2f12-4160-9f65-efd1833b65c6	idp_link	Linking Identity Provider	6f348afb-6f1f-428c-a4f9-5f8e2374a075	t	f	idp_link	120
607401dc-cbb0-4955-b1df-aa317b3b1a48	update_user_locale	Update User Locale	6f348afb-6f1f-428c-a4f9-5f8e2374a075	t	f	update_user_locale	1000
\.


--
-- Data for Name: resource_attribute; Type: TABLE DATA; Schema: public; Owner: keycloak
--

COPY public.resource_attribute (id, name, value, resource_id) FROM stdin;
\.


--
-- Data for Name: resource_policy; Type: TABLE DATA; Schema: public; Owner: keycloak
--

COPY public.resource_policy (resource_id, policy_id) FROM stdin;
\.


--
-- Data for Name: resource_scope; Type: TABLE DATA; Schema: public; Owner: keycloak
--

COPY public.resource_scope (resource_id, scope_id) FROM stdin;
\.


--
-- Data for Name: resource_server; Type: TABLE DATA; Schema: public; Owner: keycloak
--

COPY public.resource_server (id, allow_rs_remote_mgmt, policy_enforce_mode, decision_strategy) FROM stdin;
545c2160-f604-44d4-98c4-cf209d2d0b9d	t	0	1
\.


--
-- Data for Name: resource_server_perm_ticket; Type: TABLE DATA; Schema: public; Owner: keycloak
--

COPY public.resource_server_perm_ticket (id, owner, requester, created_timestamp, granted_timestamp, resource_id, scope_id, resource_server_id, policy_id) FROM stdin;
\.


--
-- Data for Name: resource_server_policy; Type: TABLE DATA; Schema: public; Owner: keycloak
--

COPY public.resource_server_policy (id, name, description, type, decision_strategy, logic, resource_server_id, owner) FROM stdin;
\.


--
-- Data for Name: resource_server_resource; Type: TABLE DATA; Schema: public; Owner: keycloak
--

COPY public.resource_server_resource (id, name, type, icon_uri, owner, resource_server_id, owner_managed_access, display_name) FROM stdin;
\.


--
-- Data for Name: resource_server_scope; Type: TABLE DATA; Schema: public; Owner: keycloak
--

COPY public.resource_server_scope (id, name, icon_uri, resource_server_id, display_name) FROM stdin;
\.


--
-- Data for Name: resource_uris; Type: TABLE DATA; Schema: public; Owner: keycloak
--

COPY public.resource_uris (resource_id, value) FROM stdin;
\.


--
-- Data for Name: revoked_token; Type: TABLE DATA; Schema: public; Owner: keycloak
--

COPY public.revoked_token (id, expire) FROM stdin;
\.


--
-- Data for Name: role_attribute; Type: TABLE DATA; Schema: public; Owner: keycloak
--

COPY public.role_attribute (id, role_id, name, value) FROM stdin;
\.


--
-- Data for Name: scope_mapping; Type: TABLE DATA; Schema: public; Owner: keycloak
--

COPY public.scope_mapping (client_id, role_id) FROM stdin;
2a479066-384f-44a7-8ca2-7bb08a9c0b90	020d21aa-8890-4fc0-a62f-42f4c7787683
2a479066-384f-44a7-8ca2-7bb08a9c0b90	60193ccb-5aaf-4faa-a96f-0230790d6f02
632c3653-00fa-4b03-a4ed-81afbb16f16d	136c82ed-dc60-4c9f-9744-77c9a4cca1f1
632c3653-00fa-4b03-a4ed-81afbb16f16d	112b6f3b-3904-421f-abf0-dda37752c236
\.


--
-- Data for Name: scope_policy; Type: TABLE DATA; Schema: public; Owner: keycloak
--

COPY public.scope_policy (scope_id, policy_id) FROM stdin;
\.


--
-- Data for Name: server_config; Type: TABLE DATA; Schema: public; Owner: keycloak
--

COPY public.server_config (server_config_key, value, version) FROM stdin;
\.


--
-- Data for Name: user_attribute; Type: TABLE DATA; Schema: public; Owner: keycloak
--

COPY public.user_attribute (name, value, user_id, id, long_value_hash, long_value_hash_lower_case, long_value) FROM stdin;
is_temporary_admin	true	6074dc87-06d6-40e0-b851-f702fe11d3c6	900c71d4-0eff-4d60-b21c-10b517f706cf	\N	\N	\N
terms_and_conditions	1779392221	addddfb1-5606-4b7a-b6cc-925a36faece3	a445d32c-258c-4655-b235-23931678e93a	\N	\N	\N
elixir_id	dummy	addddfb1-5606-4b7a-b6cc-925a36faece3	071ec252-19ee-4ded-9194-b0fd78e6640a	\N	\N	\N
\.


--
-- Data for Name: user_consent; Type: TABLE DATA; Schema: public; Owner: keycloak
--

COPY public.user_consent (id, client_id, user_id, created_date, last_updated_date, client_storage_provider, external_client_id) FROM stdin;
\.


--
-- Data for Name: user_consent_client_scope; Type: TABLE DATA; Schema: public; Owner: keycloak
--

COPY public.user_consent_client_scope (user_consent_id, scope_id) FROM stdin;
\.


--
-- Data for Name: user_entity; Type: TABLE DATA; Schema: public; Owner: keycloak
--

COPY public.user_entity (id, email, email_constraint, email_verified, enabled, federation_link, first_name, last_name, realm_id, username, created_timestamp, service_account_client_link, not_before) FROM stdin;
535a18d0-5243-41a9-a9b2-156fdd45afb7	\N	5c7e880f-9195-4de8-a22c-1657d06db0b3	f	t	\N	\N	\N	6f348afb-6f1f-428c-a4f9-5f8e2374a075	service-account-ls-aai-service-account	1770675589448	545c2160-f604-44d4-98c4-cf209d2d0b9d	0
6074dc87-06d6-40e0-b851-f702fe11d3c6	\N	12cbc00f-0726-4258-a208-2ecc506b8e82	f	t	\N	\N	\N	86b2aa03-1225-4835-8758-60f4e03293c9	admin	1779391645233	\N	0
addddfb1-5606-4b7a-b6cc-925a36faece3	admin@gdi.eu	admin@gdi.eu	f	t	\N	\N	\N	6f348afb-6f1f-428c-a4f9-5f8e2374a075	gdi_admin	1779392188267	\N	0
\.


--
-- Data for Name: user_federation_config; Type: TABLE DATA; Schema: public; Owner: keycloak
--

COPY public.user_federation_config (user_federation_provider_id, value, name) FROM stdin;
\.


--
-- Data for Name: user_federation_mapper; Type: TABLE DATA; Schema: public; Owner: keycloak
--

COPY public.user_federation_mapper (id, name, federation_provider_id, federation_mapper_type, realm_id) FROM stdin;
\.


--
-- Data for Name: user_federation_mapper_config; Type: TABLE DATA; Schema: public; Owner: keycloak
--

COPY public.user_federation_mapper_config (user_federation_mapper_id, value, name) FROM stdin;
\.


--
-- Data for Name: user_federation_provider; Type: TABLE DATA; Schema: public; Owner: keycloak
--

COPY public.user_federation_provider (id, changed_sync_period, display_name, full_sync_period, last_sync, priority, provider_name, realm_id) FROM stdin;
\.


--
-- Data for Name: user_group_membership; Type: TABLE DATA; Schema: public; Owner: keycloak
--

COPY public.user_group_membership (group_id, user_id, membership_type) FROM stdin;
\.


--
-- Data for Name: user_required_action; Type: TABLE DATA; Schema: public; Owner: keycloak
--

COPY public.user_required_action (user_id, required_action) FROM stdin;
\.


--
-- Data for Name: user_role_mapping; Type: TABLE DATA; Schema: public; Owner: keycloak
--

COPY public.user_role_mapping (role_id, user_id) FROM stdin;
93059c31-b7bc-4d3d-bc95-dc94a5ebb7ad	535a18d0-5243-41a9-a9b2-156fdd45afb7
aface648-bf84-41d5-9498-77a06fb25376	535a18d0-5243-41a9-a9b2-156fdd45afb7
f73599ce-eec3-40a4-86c0-b1ccc4f51cf9	535a18d0-5243-41a9-a9b2-156fdd45afb7
b3054bb8-c40e-4a91-a086-c364629ce753	6074dc87-06d6-40e0-b851-f702fe11d3c6
9ec7cdc9-cf2b-4d40-93dc-f89ed5c8a0f2	6074dc87-06d6-40e0-b851-f702fe11d3c6
93059c31-b7bc-4d3d-bc95-dc94a5ebb7ad	addddfb1-5606-4b7a-b6cc-925a36faece3
dd1ca63b-574d-431c-953b-f7de73438e86	addddfb1-5606-4b7a-b6cc-925a36faece3
\.


--
-- Data for Name: web_origins; Type: TABLE DATA; Schema: public; Owner: keycloak
--

COPY public.web_origins (client_id, value) FROM stdin;
f6127f78-7990-4de5-8eba-6721209ae8d9	+
49dfabcd-b980-414c-94a8-fdb65533ad2f	+
545c2160-f604-44d4-98c4-cf209d2d0b9d	/*
08d74ac1-49fc-469d-a687-9ab3b27b69b1	+
\.


--
-- Data for Name: workflow_state; Type: TABLE DATA; Schema: public; Owner: keycloak
--

COPY public.workflow_state (execution_id, resource_id, workflow_id, resource_type, scheduled_step_id, scheduled_step_timestamp) FROM stdin;
\.


--
-- Name: org_domain ORG_DOMAIN_pkey; Type: CONSTRAINT; Schema: public; Owner: keycloak
--

ALTER TABLE ONLY public.org_domain
    ADD CONSTRAINT "ORG_DOMAIN_pkey" PRIMARY KEY (id, name);


--
-- Name: org ORG_pkey; Type: CONSTRAINT; Schema: public; Owner: keycloak
--

ALTER TABLE ONLY public.org
    ADD CONSTRAINT "ORG_pkey" PRIMARY KEY (id);


--
-- Name: server_config SERVER_CONFIG_pkey; Type: CONSTRAINT; Schema: public; Owner: keycloak
--

ALTER TABLE ONLY public.server_config
    ADD CONSTRAINT "SERVER_CONFIG_pkey" PRIMARY KEY (server_config_key);


--
-- Name: keycloak_role UK_J3RWUVD56ONTGSUHOGM184WW2-2; Type: CONSTRAINT; Schema: public; Owner: keycloak
--

ALTER TABLE ONLY public.keycloak_role
    ADD CONSTRAINT "UK_J3RWUVD56ONTGSUHOGM184WW2-2" UNIQUE (name, client_realm_constraint);


--
-- Name: client_auth_flow_bindings c_cli_flow_bind; Type: CONSTRAINT; Schema: public; Owner: keycloak
--

ALTER TABLE ONLY public.client_auth_flow_bindings
    ADD CONSTRAINT c_cli_flow_bind PRIMARY KEY (client_id, binding_name);


--
-- Name: client_scope_client c_cli_scope_bind; Type: CONSTRAINT; Schema: public; Owner: keycloak
--

ALTER TABLE ONLY public.client_scope_client
    ADD CONSTRAINT c_cli_scope_bind PRIMARY KEY (client_id, scope_id);


--
-- Name: client_initial_access cnstr_client_init_acc_pk; Type: CONSTRAINT; Schema: public; Owner: keycloak
--

ALTER TABLE ONLY public.client_initial_access
    ADD CONSTRAINT cnstr_client_init_acc_pk PRIMARY KEY (id);


--
-- Name: realm_default_groups con_group_id_def_groups; Type: CONSTRAINT; Schema: public; Owner: keycloak
--

ALTER TABLE ONLY public.realm_default_groups
    ADD CONSTRAINT con_group_id_def_groups UNIQUE (group_id);


--
-- Name: broker_link constr_broker_link_pk; Type: CONSTRAINT; Schema: public; Owner: keycloak
--

ALTER TABLE ONLY public.broker_link
    ADD CONSTRAINT constr_broker_link_pk PRIMARY KEY (identity_provider, user_id);


--
-- Name: component_config constr_component_config_pk; Type: CONSTRAINT; Schema: public; Owner: keycloak
--

ALTER TABLE ONLY public.component_config
    ADD CONSTRAINT constr_component_config_pk PRIMARY KEY (id);


--
-- Name: component constr_component_pk; Type: CONSTRAINT; Schema: public; Owner: keycloak
--

ALTER TABLE ONLY public.component
    ADD CONSTRAINT constr_component_pk PRIMARY KEY (id);


--
-- Name: fed_user_required_action constr_fed_required_action; Type: CONSTRAINT; Schema: public; Owner: keycloak
--

ALTER TABLE ONLY public.fed_user_required_action
    ADD CONSTRAINT constr_fed_required_action PRIMARY KEY (required_action, user_id);


--
-- Name: fed_user_attribute constr_fed_user_attr_pk; Type: CONSTRAINT; Schema: public; Owner: keycloak
--

ALTER TABLE ONLY public.fed_user_attribute
    ADD CONSTRAINT constr_fed_user_attr_pk PRIMARY KEY (id);


--
-- Name: fed_user_consent constr_fed_user_consent_pk; Type: CONSTRAINT; Schema: public; Owner: keycloak
--

ALTER TABLE ONLY public.fed_user_consent
    ADD CONSTRAINT constr_fed_user_consent_pk PRIMARY KEY (id);


--
-- Name: fed_user_credential constr_fed_user_cred_pk; Type: CONSTRAINT; Schema: public; Owner: keycloak
--

ALTER TABLE ONLY public.fed_user_credential
    ADD CONSTRAINT constr_fed_user_cred_pk PRIMARY KEY (id);


--
-- Name: fed_user_group_membership constr_fed_user_group; Type: CONSTRAINT; Schema: public; Owner: keycloak
--

ALTER TABLE ONLY public.fed_user_group_membership
    ADD CONSTRAINT constr_fed_user_group PRIMARY KEY (group_id, user_id);


--
-- Name: fed_user_role_mapping constr_fed_user_role; Type: CONSTRAINT; Schema: public; Owner: keycloak
--

ALTER TABLE ONLY public.fed_user_role_mapping
    ADD CONSTRAINT constr_fed_user_role PRIMARY KEY (role_id, user_id);


--
-- Name: federated_user constr_federated_user; Type: CONSTRAINT; Schema: public; Owner: keycloak
--

ALTER TABLE ONLY public.federated_user
    ADD CONSTRAINT constr_federated_user PRIMARY KEY (id);


--
-- Name: realm_default_groups constr_realm_default_groups; Type: CONSTRAINT; Schema: public; Owner: keycloak
--

ALTER TABLE ONLY public.realm_default_groups
    ADD CONSTRAINT constr_realm_default_groups PRIMARY KEY (realm_id, group_id);


--
-- Name: realm_enabled_event_types constr_realm_enabl_event_types; Type: CONSTRAINT; Schema: public; Owner: keycloak
--

ALTER TABLE ONLY public.realm_enabled_event_types
    ADD CONSTRAINT constr_realm_enabl_event_types PRIMARY KEY (realm_id, value);


--
-- Name: realm_events_listeners constr_realm_events_listeners; Type: CONSTRAINT; Schema: public; Owner: keycloak
--

ALTER TABLE ONLY public.realm_events_listeners
    ADD CONSTRAINT constr_realm_events_listeners PRIMARY KEY (realm_id, value);


--
-- Name: realm_supported_locales constr_realm_supported_locales; Type: CONSTRAINT; Schema: public; Owner: keycloak
--

ALTER TABLE ONLY public.realm_supported_locales
    ADD CONSTRAINT constr_realm_supported_locales PRIMARY KEY (realm_id, value);


--
-- Name: identity_provider constraint_2b; Type: CONSTRAINT; Schema: public; Owner: keycloak
--

ALTER TABLE ONLY public.identity_provider
    ADD CONSTRAINT constraint_2b PRIMARY KEY (internal_id);


--
-- Name: client_attributes constraint_3c; Type: CONSTRAINT; Schema: public; Owner: keycloak
--

ALTER TABLE ONLY public.client_attributes
    ADD CONSTRAINT constraint_3c PRIMARY KEY (client_id, name);


--
-- Name: event_entity constraint_4; Type: CONSTRAINT; Schema: public; Owner: keycloak
--

ALTER TABLE ONLY public.event_entity
    ADD CONSTRAINT constraint_4 PRIMARY KEY (id);


--
-- Name: federated_identity constraint_40; Type: CONSTRAINT; Schema: public; Owner: keycloak
--

ALTER TABLE ONLY public.federated_identity
    ADD CONSTRAINT constraint_40 PRIMARY KEY (identity_provider, user_id);


--
-- Name: realm constraint_4a; Type: CONSTRAINT; Schema: public; Owner: keycloak
--

ALTER TABLE ONLY public.realm
    ADD CONSTRAINT constraint_4a PRIMARY KEY (id);


--
-- Name: user_federation_provider constraint_5c; Type: CONSTRAINT; Schema: public; Owner: keycloak
--

ALTER TABLE ONLY public.user_federation_provider
    ADD CONSTRAINT constraint_5c PRIMARY KEY (id);


--
-- Name: client constraint_7; Type: CONSTRAINT; Schema: public; Owner: keycloak
--

ALTER TABLE ONLY public.client
    ADD CONSTRAINT constraint_7 PRIMARY KEY (id);


--
-- Name: scope_mapping constraint_81; Type: CONSTRAINT; Schema: public; Owner: keycloak
--

ALTER TABLE ONLY public.scope_mapping
    ADD CONSTRAINT constraint_81 PRIMARY KEY (client_id, role_id);


--
-- Name: client_node_registrations constraint_84; Type: CONSTRAINT; Schema: public; Owner: keycloak
--

ALTER TABLE ONLY public.client_node_registrations
    ADD CONSTRAINT constraint_84 PRIMARY KEY (client_id, name);


--
-- Name: realm_attribute constraint_9; Type: CONSTRAINT; Schema: public; Owner: keycloak
--

ALTER TABLE ONLY public.realm_attribute
    ADD CONSTRAINT constraint_9 PRIMARY KEY (name, realm_id);


--
-- Name: realm_required_credential constraint_92; Type: CONSTRAINT; Schema: public; Owner: keycloak
--

ALTER TABLE ONLY public.realm_required_credential
    ADD CONSTRAINT constraint_92 PRIMARY KEY (realm_id, type);


--
-- Name: keycloak_role constraint_a; Type: CONSTRAINT; Schema: public; Owner: keycloak
--

ALTER TABLE ONLY public.keycloak_role
    ADD CONSTRAINT constraint_a PRIMARY KEY (id);


--
-- Name: admin_event_entity constraint_admin_event_entity; Type: CONSTRAINT; Schema: public; Owner: keycloak
--

ALTER TABLE ONLY public.admin_event_entity
    ADD CONSTRAINT constraint_admin_event_entity PRIMARY KEY (id);


--
-- Name: authenticator_config_entry constraint_auth_cfg_pk; Type: CONSTRAINT; Schema: public; Owner: keycloak
--

ALTER TABLE ONLY public.authenticator_config_entry
    ADD CONSTRAINT constraint_auth_cfg_pk PRIMARY KEY (authenticator_id, name);


--
-- Name: authentication_execution constraint_auth_exec_pk; Type: CONSTRAINT; Schema: public; Owner: keycloak
--

ALTER TABLE ONLY public.authentication_execution
    ADD CONSTRAINT constraint_auth_exec_pk PRIMARY KEY (id);


--
-- Name: authentication_flow constraint_auth_flow_pk; Type: CONSTRAINT; Schema: public; Owner: keycloak
--

ALTER TABLE ONLY public.authentication_flow
    ADD CONSTRAINT constraint_auth_flow_pk PRIMARY KEY (id);


--
-- Name: authenticator_config constraint_auth_pk; Type: CONSTRAINT; Schema: public; Owner: keycloak
--

ALTER TABLE ONLY public.authenticator_config
    ADD CONSTRAINT constraint_auth_pk PRIMARY KEY (id);


--
-- Name: user_role_mapping constraint_c; Type: CONSTRAINT; Schema: public; Owner: keycloak
--

ALTER TABLE ONLY public.user_role_mapping
    ADD CONSTRAINT constraint_c PRIMARY KEY (role_id, user_id);


--
-- Name: composite_role constraint_composite_role; Type: CONSTRAINT; Schema: public; Owner: keycloak
--

ALTER TABLE ONLY public.composite_role
    ADD CONSTRAINT constraint_composite_role PRIMARY KEY (composite, child_role);


--
-- Name: identity_provider_config constraint_d; Type: CONSTRAINT; Schema: public; Owner: keycloak
--

ALTER TABLE ONLY public.identity_provider_config
    ADD CONSTRAINT constraint_d PRIMARY KEY (identity_provider_id, name);


--
-- Name: policy_config constraint_dpc; Type: CONSTRAINT; Schema: public; Owner: keycloak
--

ALTER TABLE ONLY public.policy_config
    ADD CONSTRAINT constraint_dpc PRIMARY KEY (policy_id, name);


--
-- Name: realm_smtp_config constraint_e; Type: CONSTRAINT; Schema: public; Owner: keycloak
--

ALTER TABLE ONLY public.realm_smtp_config
    ADD CONSTRAINT constraint_e PRIMARY KEY (realm_id, name);


--
-- Name: credential constraint_f; Type: CONSTRAINT; Schema: public; Owner: keycloak
--

ALTER TABLE ONLY public.credential
    ADD CONSTRAINT constraint_f PRIMARY KEY (id);


--
-- Name: user_federation_config constraint_f9; Type: CONSTRAINT; Schema: public; Owner: keycloak
--

ALTER TABLE ONLY public.user_federation_config
    ADD CONSTRAINT constraint_f9 PRIMARY KEY (user_federation_provider_id, name);


--
-- Name: resource_server_perm_ticket constraint_fapmt; Type: CONSTRAINT; Schema: public; Owner: keycloak
--

ALTER TABLE ONLY public.resource_server_perm_ticket
    ADD CONSTRAINT constraint_fapmt PRIMARY KEY (id);


--
-- Name: resource_server_resource constraint_farsr; Type: CONSTRAINT; Schema: public; Owner: keycloak
--

ALTER TABLE ONLY public.resource_server_resource
    ADD CONSTRAINT constraint_farsr PRIMARY KEY (id);


--
-- Name: resource_server_policy constraint_farsrp; Type: CONSTRAINT; Schema: public; Owner: keycloak
--

ALTER TABLE ONLY public.resource_server_policy
    ADD CONSTRAINT constraint_farsrp PRIMARY KEY (id);


--
-- Name: associated_policy constraint_farsrpap; Type: CONSTRAINT; Schema: public; Owner: keycloak
--

ALTER TABLE ONLY public.associated_policy
    ADD CONSTRAINT constraint_farsrpap PRIMARY KEY (policy_id, associated_policy_id);


--
-- Name: resource_policy constraint_farsrpp; Type: CONSTRAINT; Schema: public; Owner: keycloak
--

ALTER TABLE ONLY public.resource_policy
    ADD CONSTRAINT constraint_farsrpp PRIMARY KEY (resource_id, policy_id);


--
-- Name: resource_server_scope constraint_farsrs; Type: CONSTRAINT; Schema: public; Owner: keycloak
--

ALTER TABLE ONLY public.resource_server_scope
    ADD CONSTRAINT constraint_farsrs PRIMARY KEY (id);


--
-- Name: resource_scope constraint_farsrsp; Type: CONSTRAINT; Schema: public; Owner: keycloak
--

ALTER TABLE ONLY public.resource_scope
    ADD CONSTRAINT constraint_farsrsp PRIMARY KEY (resource_id, scope_id);


--
-- Name: scope_policy constraint_farsrsps; Type: CONSTRAINT; Schema: public; Owner: keycloak
--

ALTER TABLE ONLY public.scope_policy
    ADD CONSTRAINT constraint_farsrsps PRIMARY KEY (scope_id, policy_id);


--
-- Name: user_entity constraint_fb; Type: CONSTRAINT; Schema: public; Owner: keycloak
--

ALTER TABLE ONLY public.user_entity
    ADD CONSTRAINT constraint_fb PRIMARY KEY (id);


--
-- Name: user_federation_mapper_config constraint_fedmapper_cfg_pm; Type: CONSTRAINT; Schema: public; Owner: keycloak
--

ALTER TABLE ONLY public.user_federation_mapper_config
    ADD CONSTRAINT constraint_fedmapper_cfg_pm PRIMARY KEY (user_federation_mapper_id, name);


--
-- Name: user_federation_mapper constraint_fedmapperpm; Type: CONSTRAINT; Schema: public; Owner: keycloak
--

ALTER TABLE ONLY public.user_federation_mapper
    ADD CONSTRAINT constraint_fedmapperpm PRIMARY KEY (id);


--
-- Name: fed_user_consent_cl_scope constraint_fgrntcsnt_clsc_pm; Type: CONSTRAINT; Schema: public; Owner: keycloak
--

ALTER TABLE ONLY public.fed_user_consent_cl_scope
    ADD CONSTRAINT constraint_fgrntcsnt_clsc_pm PRIMARY KEY (user_consent_id, scope_id);


--
-- Name: user_consent_client_scope constraint_grntcsnt_clsc_pm; Type: CONSTRAINT; Schema: public; Owner: keycloak
--

ALTER TABLE ONLY public.user_consent_client_scope
    ADD CONSTRAINT constraint_grntcsnt_clsc_pm PRIMARY KEY (user_consent_id, scope_id);


--
-- Name: user_consent constraint_grntcsnt_pm; Type: CONSTRAINT; Schema: public; Owner: keycloak
--

ALTER TABLE ONLY public.user_consent
    ADD CONSTRAINT constraint_grntcsnt_pm PRIMARY KEY (id);


--
-- Name: keycloak_group constraint_group; Type: CONSTRAINT; Schema: public; Owner: keycloak
--

ALTER TABLE ONLY public.keycloak_group
    ADD CONSTRAINT constraint_group PRIMARY KEY (id);


--
-- Name: group_attribute constraint_group_attribute_pk; Type: CONSTRAINT; Schema: public; Owner: keycloak
--

ALTER TABLE ONLY public.group_attribute
    ADD CONSTRAINT constraint_group_attribute_pk PRIMARY KEY (id);


--
-- Name: group_role_mapping constraint_group_role; Type: CONSTRAINT; Schema: public; Owner: keycloak
--

ALTER TABLE ONLY public.group_role_mapping
    ADD CONSTRAINT constraint_group_role PRIMARY KEY (role_id, group_id);


--
-- Name: identity_provider_mapper constraint_idpm; Type: CONSTRAINT; Schema: public; Owner: keycloak
--

ALTER TABLE ONLY public.identity_provider_mapper
    ADD CONSTRAINT constraint_idpm PRIMARY KEY (id);


--
-- Name: idp_mapper_config constraint_idpmconfig; Type: CONSTRAINT; Schema: public; Owner: keycloak
--

ALTER TABLE ONLY public.idp_mapper_config
    ADD CONSTRAINT constraint_idpmconfig PRIMARY KEY (idp_mapper_id, name);


--
-- Name: jgroups_ping constraint_jgroups_ping; Type: CONSTRAINT; Schema: public; Owner: keycloak
--

ALTER TABLE ONLY public.jgroups_ping
    ADD CONSTRAINT constraint_jgroups_ping PRIMARY KEY (address);


--
-- Name: migration_model constraint_migmod; Type: CONSTRAINT; Schema: public; Owner: keycloak
--

ALTER TABLE ONLY public.migration_model
    ADD CONSTRAINT constraint_migmod PRIMARY KEY (id);


--
-- Name: offline_client_session constraint_offl_cl_ses_pk3; Type: CONSTRAINT; Schema: public; Owner: keycloak
--

ALTER TABLE ONLY public.offline_client_session
    ADD CONSTRAINT constraint_offl_cl_ses_pk3 PRIMARY KEY (user_session_id, client_id, client_storage_provider, external_client_id, offline_flag);


--
-- Name: offline_user_session constraint_offl_us_ses_pk2; Type: CONSTRAINT; Schema: public; Owner: keycloak
--

ALTER TABLE ONLY public.offline_user_session
    ADD CONSTRAINT constraint_offl_us_ses_pk2 PRIMARY KEY (user_session_id, offline_flag);


--
-- Name: org_invitation constraint_org_invitation; Type: CONSTRAINT; Schema: public; Owner: keycloak
--

ALTER TABLE ONLY public.org_invitation
    ADD CONSTRAINT constraint_org_invitation PRIMARY KEY (id);


--
-- Name: protocol_mapper constraint_pcm; Type: CONSTRAINT; Schema: public; Owner: keycloak
--

ALTER TABLE ONLY public.protocol_mapper
    ADD CONSTRAINT constraint_pcm PRIMARY KEY (id);


--
-- Name: protocol_mapper_config constraint_pmconfig; Type: CONSTRAINT; Schema: public; Owner: keycloak
--

ALTER TABLE ONLY public.protocol_mapper_config
    ADD CONSTRAINT constraint_pmconfig PRIMARY KEY (protocol_mapper_id, name);


--
-- Name: redirect_uris constraint_redirect_uris; Type: CONSTRAINT; Schema: public; Owner: keycloak
--

ALTER TABLE ONLY public.redirect_uris
    ADD CONSTRAINT constraint_redirect_uris PRIMARY KEY (client_id, value);


--
-- Name: required_action_config constraint_req_act_cfg_pk; Type: CONSTRAINT; Schema: public; Owner: keycloak
--

ALTER TABLE ONLY public.required_action_config
    ADD CONSTRAINT constraint_req_act_cfg_pk PRIMARY KEY (required_action_id, name);


--
-- Name: required_action_provider constraint_req_act_prv_pk; Type: CONSTRAINT; Schema: public; Owner: keycloak
--

ALTER TABLE ONLY public.required_action_provider
    ADD CONSTRAINT constraint_req_act_prv_pk PRIMARY KEY (id);


--
-- Name: user_required_action constraint_required_action; Type: CONSTRAINT; Schema: public; Owner: keycloak
--

ALTER TABLE ONLY public.user_required_action
    ADD CONSTRAINT constraint_required_action PRIMARY KEY (required_action, user_id);


--
-- Name: resource_uris constraint_resour_uris_pk; Type: CONSTRAINT; Schema: public; Owner: keycloak
--

ALTER TABLE ONLY public.resource_uris
    ADD CONSTRAINT constraint_resour_uris_pk PRIMARY KEY (resource_id, value);


--
-- Name: role_attribute constraint_role_attribute_pk; Type: CONSTRAINT; Schema: public; Owner: keycloak
--

ALTER TABLE ONLY public.role_attribute
    ADD CONSTRAINT constraint_role_attribute_pk PRIMARY KEY (id);


--
-- Name: revoked_token constraint_rt; Type: CONSTRAINT; Schema: public; Owner: keycloak
--

ALTER TABLE ONLY public.revoked_token
    ADD CONSTRAINT constraint_rt PRIMARY KEY (id);


--
-- Name: user_attribute constraint_user_attribute_pk; Type: CONSTRAINT; Schema: public; Owner: keycloak
--

ALTER TABLE ONLY public.user_attribute
    ADD CONSTRAINT constraint_user_attribute_pk PRIMARY KEY (id);


--
-- Name: user_group_membership constraint_user_group; Type: CONSTRAINT; Schema: public; Owner: keycloak
--

ALTER TABLE ONLY public.user_group_membership
    ADD CONSTRAINT constraint_user_group PRIMARY KEY (group_id, user_id);


--
-- Name: web_origins constraint_web_origins; Type: CONSTRAINT; Schema: public; Owner: keycloak
--

ALTER TABLE ONLY public.web_origins
    ADD CONSTRAINT constraint_web_origins PRIMARY KEY (client_id, value);


--
-- Name: databasechangeloglock databasechangeloglock_pkey; Type: CONSTRAINT; Schema: public; Owner: keycloak
--

ALTER TABLE ONLY public.databasechangeloglock
    ADD CONSTRAINT databasechangeloglock_pkey PRIMARY KEY (id);


--
-- Name: client_scope_attributes pk_cl_tmpl_attr; Type: CONSTRAINT; Schema: public; Owner: keycloak
--

ALTER TABLE ONLY public.client_scope_attributes
    ADD CONSTRAINT pk_cl_tmpl_attr PRIMARY KEY (scope_id, name);


--
-- Name: client_scope pk_cli_template; Type: CONSTRAINT; Schema: public; Owner: keycloak
--

ALTER TABLE ONLY public.client_scope
    ADD CONSTRAINT pk_cli_template PRIMARY KEY (id);


--
-- Name: resource_server pk_resource_server; Type: CONSTRAINT; Schema: public; Owner: keycloak
--

ALTER TABLE ONLY public.resource_server
    ADD CONSTRAINT pk_resource_server PRIMARY KEY (id);


--
-- Name: client_scope_role_mapping pk_template_scope; Type: CONSTRAINT; Schema: public; Owner: keycloak
--

ALTER TABLE ONLY public.client_scope_role_mapping
    ADD CONSTRAINT pk_template_scope PRIMARY KEY (scope_id, role_id);


--
-- Name: workflow_state pk_workflow_state; Type: CONSTRAINT; Schema: public; Owner: keycloak
--

ALTER TABLE ONLY public.workflow_state
    ADD CONSTRAINT pk_workflow_state PRIMARY KEY (execution_id);


--
-- Name: default_client_scope r_def_cli_scope_bind; Type: CONSTRAINT; Schema: public; Owner: keycloak
--

ALTER TABLE ONLY public.default_client_scope
    ADD CONSTRAINT r_def_cli_scope_bind PRIMARY KEY (realm_id, scope_id);


--
-- Name: realm_localizations realm_localizations_pkey; Type: CONSTRAINT; Schema: public; Owner: keycloak
--

ALTER TABLE ONLY public.realm_localizations
    ADD CONSTRAINT realm_localizations_pkey PRIMARY KEY (realm_id, locale);


--
-- Name: resource_attribute res_attr_pk; Type: CONSTRAINT; Schema: public; Owner: keycloak
--

ALTER TABLE ONLY public.resource_attribute
    ADD CONSTRAINT res_attr_pk PRIMARY KEY (id);


--
-- Name: keycloak_group sibling_names; Type: CONSTRAINT; Schema: public; Owner: keycloak
--

ALTER TABLE ONLY public.keycloak_group
    ADD CONSTRAINT sibling_names UNIQUE (realm_id, parent_group, name);


--
-- Name: identity_provider uk_2daelwnibji49avxsrtuf6xj33; Type: CONSTRAINT; Schema: public; Owner: keycloak
--

ALTER TABLE ONLY public.identity_provider
    ADD CONSTRAINT uk_2daelwnibji49avxsrtuf6xj33 UNIQUE (provider_alias, realm_id);


--
-- Name: client uk_b71cjlbenv945rb6gcon438at; Type: CONSTRAINT; Schema: public; Owner: keycloak
--

ALTER TABLE ONLY public.client
    ADD CONSTRAINT uk_b71cjlbenv945rb6gcon438at UNIQUE (realm_id, client_id);


--
-- Name: client_scope uk_cli_scope; Type: CONSTRAINT; Schema: public; Owner: keycloak
--

ALTER TABLE ONLY public.client_scope
    ADD CONSTRAINT uk_cli_scope UNIQUE (realm_id, name);


--
-- Name: user_entity uk_dykn684sl8up1crfei6eckhd7; Type: CONSTRAINT; Schema: public; Owner: keycloak
--

ALTER TABLE ONLY public.user_entity
    ADD CONSTRAINT uk_dykn684sl8up1crfei6eckhd7 UNIQUE (realm_id, email_constraint);


--
-- Name: user_consent uk_external_consent; Type: CONSTRAINT; Schema: public; Owner: keycloak
--

ALTER TABLE ONLY public.user_consent
    ADD CONSTRAINT uk_external_consent UNIQUE (client_storage_provider, external_client_id, user_id);


--
-- Name: resource_server_resource uk_frsr6t700s9v50bu18ws5ha6; Type: CONSTRAINT; Schema: public; Owner: keycloak
--

ALTER TABLE ONLY public.resource_server_resource
    ADD CONSTRAINT uk_frsr6t700s9v50bu18ws5ha6 UNIQUE (name, owner, resource_server_id);


--
-- Name: resource_server_perm_ticket uk_frsr6t700s9v50bu18ws5pmt; Type: CONSTRAINT; Schema: public; Owner: keycloak
--

ALTER TABLE ONLY public.resource_server_perm_ticket
    ADD CONSTRAINT uk_frsr6t700s9v50bu18ws5pmt UNIQUE (owner, requester, resource_server_id, resource_id, scope_id);


--
-- Name: resource_server_policy uk_frsrpt700s9v50bu18ws5ha6; Type: CONSTRAINT; Schema: public; Owner: keycloak
--

ALTER TABLE ONLY public.resource_server_policy
    ADD CONSTRAINT uk_frsrpt700s9v50bu18ws5ha6 UNIQUE (name, resource_server_id);


--
-- Name: resource_server_scope uk_frsrst700s9v50bu18ws5ha6; Type: CONSTRAINT; Schema: public; Owner: keycloak
--

ALTER TABLE ONLY public.resource_server_scope
    ADD CONSTRAINT uk_frsrst700s9v50bu18ws5ha6 UNIQUE (name, resource_server_id);


--
-- Name: user_consent uk_local_consent; Type: CONSTRAINT; Schema: public; Owner: keycloak
--

ALTER TABLE ONLY public.user_consent
    ADD CONSTRAINT uk_local_consent UNIQUE (client_id, user_id);


--
-- Name: migration_model uk_migration_update_time; Type: CONSTRAINT; Schema: public; Owner: keycloak
--

ALTER TABLE ONLY public.migration_model
    ADD CONSTRAINT uk_migration_update_time UNIQUE (update_time);


--
-- Name: migration_model uk_migration_version; Type: CONSTRAINT; Schema: public; Owner: keycloak
--

ALTER TABLE ONLY public.migration_model
    ADD CONSTRAINT uk_migration_version UNIQUE (version);


--
-- Name: org uk_org_alias; Type: CONSTRAINT; Schema: public; Owner: keycloak
--

ALTER TABLE ONLY public.org
    ADD CONSTRAINT uk_org_alias UNIQUE (realm_id, alias);


--
-- Name: org uk_org_group; Type: CONSTRAINT; Schema: public; Owner: keycloak
--

ALTER TABLE ONLY public.org
    ADD CONSTRAINT uk_org_group UNIQUE (group_id);


--
-- Name: org_invitation uk_org_invitation_email; Type: CONSTRAINT; Schema: public; Owner: keycloak
--

ALTER TABLE ONLY public.org_invitation
    ADD CONSTRAINT uk_org_invitation_email UNIQUE (organization_id, email);


--
-- Name: org uk_org_name; Type: CONSTRAINT; Schema: public; Owner: keycloak
--

ALTER TABLE ONLY public.org
    ADD CONSTRAINT uk_org_name UNIQUE (realm_id, name);


--
-- Name: realm uk_orvsdmla56612eaefiq6wl5oi; Type: CONSTRAINT; Schema: public; Owner: keycloak
--

ALTER TABLE ONLY public.realm
    ADD CONSTRAINT uk_orvsdmla56612eaefiq6wl5oi UNIQUE (name);


--
-- Name: user_entity uk_ru8tt6t700s9v50bu18ws5ha6; Type: CONSTRAINT; Schema: public; Owner: keycloak
--

ALTER TABLE ONLY public.user_entity
    ADD CONSTRAINT uk_ru8tt6t700s9v50bu18ws5ha6 UNIQUE (realm_id, username);


--
-- Name: workflow_state uq_workflow_resource; Type: CONSTRAINT; Schema: public; Owner: keycloak
--

ALTER TABLE ONLY public.workflow_state
    ADD CONSTRAINT uq_workflow_resource UNIQUE (workflow_id, resource_id);


--
-- Name: fed_user_attr_long_values; Type: INDEX; Schema: public; Owner: keycloak
--

CREATE INDEX fed_user_attr_long_values ON public.fed_user_attribute USING btree (long_value_hash, name);


--
-- Name: fed_user_attr_long_values_lower_case; Type: INDEX; Schema: public; Owner: keycloak
--

CREATE INDEX fed_user_attr_long_values_lower_case ON public.fed_user_attribute USING btree (long_value_hash_lower_case, name);


--
-- Name: idx_admin_event_time; Type: INDEX; Schema: public; Owner: keycloak
--

CREATE INDEX idx_admin_event_time ON public.admin_event_entity USING btree (realm_id, admin_event_time);


--
-- Name: idx_assoc_pol_assoc_pol_id; Type: INDEX; Schema: public; Owner: keycloak
--

CREATE INDEX idx_assoc_pol_assoc_pol_id ON public.associated_policy USING btree (associated_policy_id);


--
-- Name: idx_auth_config_realm; Type: INDEX; Schema: public; Owner: keycloak
--

CREATE INDEX idx_auth_config_realm ON public.authenticator_config USING btree (realm_id);


--
-- Name: idx_auth_exec_flow; Type: INDEX; Schema: public; Owner: keycloak
--

CREATE INDEX idx_auth_exec_flow ON public.authentication_execution USING btree (flow_id);


--
-- Name: idx_auth_exec_realm_flow; Type: INDEX; Schema: public; Owner: keycloak
--

CREATE INDEX idx_auth_exec_realm_flow ON public.authentication_execution USING btree (realm_id, flow_id);


--
-- Name: idx_auth_flow_realm; Type: INDEX; Schema: public; Owner: keycloak
--

CREATE INDEX idx_auth_flow_realm ON public.authentication_flow USING btree (realm_id);


--
-- Name: idx_broker_link_identity_provider; Type: INDEX; Schema: public; Owner: keycloak
--

CREATE INDEX idx_broker_link_identity_provider ON public.broker_link USING btree (realm_id, identity_provider, broker_user_id);


--
-- Name: idx_broker_link_user_id; Type: INDEX; Schema: public; Owner: keycloak
--

CREATE INDEX idx_broker_link_user_id ON public.broker_link USING btree (user_id);


--
-- Name: idx_cl_clscope; Type: INDEX; Schema: public; Owner: keycloak
--

CREATE INDEX idx_cl_clscope ON public.client_scope_client USING btree (scope_id);


--
-- Name: idx_client_att_by_name_value; Type: INDEX; Schema: public; Owner: keycloak
--

CREATE INDEX idx_client_att_by_name_value ON public.client_attributes USING btree (name, substr(value, 1, 255));


--
-- Name: idx_client_id; Type: INDEX; Schema: public; Owner: keycloak
--

CREATE INDEX idx_client_id ON public.client USING btree (client_id);


--
-- Name: idx_client_init_acc_realm; Type: INDEX; Schema: public; Owner: keycloak
--

CREATE INDEX idx_client_init_acc_realm ON public.client_initial_access USING btree (realm_id);


--
-- Name: idx_clscope_attrs; Type: INDEX; Schema: public; Owner: keycloak
--

CREATE INDEX idx_clscope_attrs ON public.client_scope_attributes USING btree (scope_id);


--
-- Name: idx_clscope_cl; Type: INDEX; Schema: public; Owner: keycloak
--

CREATE INDEX idx_clscope_cl ON public.client_scope_client USING btree (client_id);


--
-- Name: idx_clscope_protmap; Type: INDEX; Schema: public; Owner: keycloak
--

CREATE INDEX idx_clscope_protmap ON public.protocol_mapper USING btree (client_scope_id);


--
-- Name: idx_clscope_role; Type: INDEX; Schema: public; Owner: keycloak
--

CREATE INDEX idx_clscope_role ON public.client_scope_role_mapping USING btree (scope_id);


--
-- Name: idx_compo_config_compo; Type: INDEX; Schema: public; Owner: keycloak
--

CREATE INDEX idx_compo_config_compo ON public.component_config USING btree (component_id);


--
-- Name: idx_component_provider_type; Type: INDEX; Schema: public; Owner: keycloak
--

CREATE INDEX idx_component_provider_type ON public.component USING btree (provider_type);


--
-- Name: idx_component_realm; Type: INDEX; Schema: public; Owner: keycloak
--

CREATE INDEX idx_component_realm ON public.component USING btree (realm_id);


--
-- Name: idx_composite; Type: INDEX; Schema: public; Owner: keycloak
--

CREATE INDEX idx_composite ON public.composite_role USING btree (composite);


--
-- Name: idx_composite_child; Type: INDEX; Schema: public; Owner: keycloak
--

CREATE INDEX idx_composite_child ON public.composite_role USING btree (child_role);


--
-- Name: idx_defcls_realm; Type: INDEX; Schema: public; Owner: keycloak
--

CREATE INDEX idx_defcls_realm ON public.default_client_scope USING btree (realm_id);


--
-- Name: idx_defcls_scope; Type: INDEX; Schema: public; Owner: keycloak
--

CREATE INDEX idx_defcls_scope ON public.default_client_scope USING btree (scope_id);


--
-- Name: idx_event_entity_user_id_type; Type: INDEX; Schema: public; Owner: keycloak
--

CREATE INDEX idx_event_entity_user_id_type ON public.event_entity USING btree (user_id, type, event_time);


--
-- Name: idx_event_time; Type: INDEX; Schema: public; Owner: keycloak
--

CREATE INDEX idx_event_time ON public.event_entity USING btree (realm_id, event_time);


--
-- Name: idx_fedidentity_feduser; Type: INDEX; Schema: public; Owner: keycloak
--

CREATE INDEX idx_fedidentity_feduser ON public.federated_identity USING btree (federated_user_id);


--
-- Name: idx_fedidentity_user; Type: INDEX; Schema: public; Owner: keycloak
--

CREATE INDEX idx_fedidentity_user ON public.federated_identity USING btree (user_id);


--
-- Name: idx_fu_attribute; Type: INDEX; Schema: public; Owner: keycloak
--

CREATE INDEX idx_fu_attribute ON public.fed_user_attribute USING btree (user_id, realm_id, name);


--
-- Name: idx_fu_cnsnt_ext; Type: INDEX; Schema: public; Owner: keycloak
--

CREATE INDEX idx_fu_cnsnt_ext ON public.fed_user_consent USING btree (user_id, client_storage_provider, external_client_id);


--
-- Name: idx_fu_consent; Type: INDEX; Schema: public; Owner: keycloak
--

CREATE INDEX idx_fu_consent ON public.fed_user_consent USING btree (user_id, client_id);


--
-- Name: idx_fu_consent_ru; Type: INDEX; Schema: public; Owner: keycloak
--

CREATE INDEX idx_fu_consent_ru ON public.fed_user_consent USING btree (realm_id, user_id);


--
-- Name: idx_fu_credential; Type: INDEX; Schema: public; Owner: keycloak
--

CREATE INDEX idx_fu_credential ON public.fed_user_credential USING btree (user_id, type);


--
-- Name: idx_fu_credential_ru; Type: INDEX; Schema: public; Owner: keycloak
--

CREATE INDEX idx_fu_credential_ru ON public.fed_user_credential USING btree (realm_id, user_id);


--
-- Name: idx_fu_group_membership; Type: INDEX; Schema: public; Owner: keycloak
--

CREATE INDEX idx_fu_group_membership ON public.fed_user_group_membership USING btree (user_id, group_id);


--
-- Name: idx_fu_group_membership_ru; Type: INDEX; Schema: public; Owner: keycloak
--

CREATE INDEX idx_fu_group_membership_ru ON public.fed_user_group_membership USING btree (realm_id, user_id);


--
-- Name: idx_fu_required_action; Type: INDEX; Schema: public; Owner: keycloak
--

CREATE INDEX idx_fu_required_action ON public.fed_user_required_action USING btree (user_id, required_action);


--
-- Name: idx_fu_required_action_ru; Type: INDEX; Schema: public; Owner: keycloak
--

CREATE INDEX idx_fu_required_action_ru ON public.fed_user_required_action USING btree (realm_id, user_id);


--
-- Name: idx_fu_role_mapping; Type: INDEX; Schema: public; Owner: keycloak
--

CREATE INDEX idx_fu_role_mapping ON public.fed_user_role_mapping USING btree (user_id, role_id);


--
-- Name: idx_fu_role_mapping_ru; Type: INDEX; Schema: public; Owner: keycloak
--

CREATE INDEX idx_fu_role_mapping_ru ON public.fed_user_role_mapping USING btree (realm_id, user_id);


--
-- Name: idx_group_att_by_name_value; Type: INDEX; Schema: public; Owner: keycloak
--

CREATE INDEX idx_group_att_by_name_value ON public.group_attribute USING btree (name, ((value)::character varying(250)));


--
-- Name: idx_group_attr_group; Type: INDEX; Schema: public; Owner: keycloak
--

CREATE INDEX idx_group_attr_group ON public.group_attribute USING btree (group_id);


--
-- Name: idx_group_role_mapp_group; Type: INDEX; Schema: public; Owner: keycloak
--

CREATE INDEX idx_group_role_mapp_group ON public.group_role_mapping USING btree (group_id);


--
-- Name: idx_id_prov_mapp_realm; Type: INDEX; Schema: public; Owner: keycloak
--

CREATE INDEX idx_id_prov_mapp_realm ON public.identity_provider_mapper USING btree (realm_id);


--
-- Name: idx_ident_prov_realm; Type: INDEX; Schema: public; Owner: keycloak
--

CREATE INDEX idx_ident_prov_realm ON public.identity_provider USING btree (realm_id);


--
-- Name: idx_idp_for_login; Type: INDEX; Schema: public; Owner: keycloak
--

CREATE INDEX idx_idp_for_login ON public.identity_provider USING btree (realm_id, enabled, link_only, hide_on_login, organization_id);


--
-- Name: idx_idp_realm_org; Type: INDEX; Schema: public; Owner: keycloak
--

CREATE INDEX idx_idp_realm_org ON public.identity_provider USING btree (realm_id, organization_id);


--
-- Name: idx_keycloak_role_client; Type: INDEX; Schema: public; Owner: keycloak
--

CREATE INDEX idx_keycloak_role_client ON public.keycloak_role USING btree (client);


--
-- Name: idx_keycloak_role_realm; Type: INDEX; Schema: public; Owner: keycloak
--

CREATE INDEX idx_keycloak_role_realm ON public.keycloak_role USING btree (realm);


--
-- Name: idx_offline_css_by_client; Type: INDEX; Schema: public; Owner: keycloak
--

CREATE INDEX idx_offline_css_by_client ON public.offline_client_session USING btree (client_id, offline_flag) WHERE ((client_id)::text <> 'external'::text);


--
-- Name: idx_offline_css_by_client_storage_provider; Type: INDEX; Schema: public; Owner: keycloak
--

CREATE INDEX idx_offline_css_by_client_storage_provider ON public.offline_client_session USING btree (client_storage_provider, external_client_id, offline_flag) WHERE ((client_storage_provider)::text <> 'internal'::text);


--
-- Name: idx_offline_uss_by_broker_session_id; Type: INDEX; Schema: public; Owner: keycloak
--

CREATE INDEX idx_offline_uss_by_broker_session_id ON public.offline_user_session USING btree (broker_session_id, realm_id);


--
-- Name: idx_offline_uss_by_user; Type: INDEX; Schema: public; Owner: keycloak
--

CREATE INDEX idx_offline_uss_by_user ON public.offline_user_session USING btree (user_id, realm_id, offline_flag);


--
-- Name: idx_org_domain_org_id; Type: INDEX; Schema: public; Owner: keycloak
--

CREATE INDEX idx_org_domain_org_id ON public.org_domain USING btree (org_id);


--
-- Name: idx_org_invitation_email; Type: INDEX; Schema: public; Owner: keycloak
--

CREATE INDEX idx_org_invitation_email ON public.org_invitation USING btree (email);


--
-- Name: idx_org_invitation_expires; Type: INDEX; Schema: public; Owner: keycloak
--

CREATE INDEX idx_org_invitation_expires ON public.org_invitation USING btree (expires_at);


--
-- Name: idx_org_invitation_org_id; Type: INDEX; Schema: public; Owner: keycloak
--

CREATE INDEX idx_org_invitation_org_id ON public.org_invitation USING btree (organization_id);


--
-- Name: idx_perm_ticket_owner; Type: INDEX; Schema: public; Owner: keycloak
--

CREATE INDEX idx_perm_ticket_owner ON public.resource_server_perm_ticket USING btree (owner);


--
-- Name: idx_perm_ticket_requester; Type: INDEX; Schema: public; Owner: keycloak
--

CREATE INDEX idx_perm_ticket_requester ON public.resource_server_perm_ticket USING btree (requester);


--
-- Name: idx_protocol_mapper_client; Type: INDEX; Schema: public; Owner: keycloak
--

CREATE INDEX idx_protocol_mapper_client ON public.protocol_mapper USING btree (client_id);


--
-- Name: idx_realm_attr_realm; Type: INDEX; Schema: public; Owner: keycloak
--

CREATE INDEX idx_realm_attr_realm ON public.realm_attribute USING btree (realm_id);


--
-- Name: idx_realm_clscope; Type: INDEX; Schema: public; Owner: keycloak
--

CREATE INDEX idx_realm_clscope ON public.client_scope USING btree (realm_id);


--
-- Name: idx_realm_def_grp_realm; Type: INDEX; Schema: public; Owner: keycloak
--

CREATE INDEX idx_realm_def_grp_realm ON public.realm_default_groups USING btree (realm_id);


--
-- Name: idx_realm_evt_list_realm; Type: INDEX; Schema: public; Owner: keycloak
--

CREATE INDEX idx_realm_evt_list_realm ON public.realm_events_listeners USING btree (realm_id);


--
-- Name: idx_realm_evt_types_realm; Type: INDEX; Schema: public; Owner: keycloak
--

CREATE INDEX idx_realm_evt_types_realm ON public.realm_enabled_event_types USING btree (realm_id);


--
-- Name: idx_realm_master_adm_cli; Type: INDEX; Schema: public; Owner: keycloak
--

CREATE INDEX idx_realm_master_adm_cli ON public.realm USING btree (master_admin_client);


--
-- Name: idx_realm_supp_local_realm; Type: INDEX; Schema: public; Owner: keycloak
--

CREATE INDEX idx_realm_supp_local_realm ON public.realm_supported_locales USING btree (realm_id);


--
-- Name: idx_redir_uri_client; Type: INDEX; Schema: public; Owner: keycloak
--

CREATE INDEX idx_redir_uri_client ON public.redirect_uris USING btree (client_id);


--
-- Name: idx_req_act_prov_realm; Type: INDEX; Schema: public; Owner: keycloak
--

CREATE INDEX idx_req_act_prov_realm ON public.required_action_provider USING btree (realm_id);


--
-- Name: idx_res_policy_policy; Type: INDEX; Schema: public; Owner: keycloak
--

CREATE INDEX idx_res_policy_policy ON public.resource_policy USING btree (policy_id);


--
-- Name: idx_res_scope_scope; Type: INDEX; Schema: public; Owner: keycloak
--

CREATE INDEX idx_res_scope_scope ON public.resource_scope USING btree (scope_id);


--
-- Name: idx_res_serv_pol_res_serv; Type: INDEX; Schema: public; Owner: keycloak
--

CREATE INDEX idx_res_serv_pol_res_serv ON public.resource_server_policy USING btree (resource_server_id);


--
-- Name: idx_res_srv_res_res_srv; Type: INDEX; Schema: public; Owner: keycloak
--

CREATE INDEX idx_res_srv_res_res_srv ON public.resource_server_resource USING btree (resource_server_id);


--
-- Name: idx_res_srv_scope_res_srv; Type: INDEX; Schema: public; Owner: keycloak
--

CREATE INDEX idx_res_srv_scope_res_srv ON public.resource_server_scope USING btree (resource_server_id);


--
-- Name: idx_rev_token_on_expire; Type: INDEX; Schema: public; Owner: keycloak
--

CREATE INDEX idx_rev_token_on_expire ON public.revoked_token USING btree (expire);


--
-- Name: idx_role_attribute; Type: INDEX; Schema: public; Owner: keycloak
--

CREATE INDEX idx_role_attribute ON public.role_attribute USING btree (role_id);


--
-- Name: idx_role_clscope; Type: INDEX; Schema: public; Owner: keycloak
--

CREATE INDEX idx_role_clscope ON public.client_scope_role_mapping USING btree (role_id);


--
-- Name: idx_scope_mapping_role; Type: INDEX; Schema: public; Owner: keycloak
--

CREATE INDEX idx_scope_mapping_role ON public.scope_mapping USING btree (role_id);


--
-- Name: idx_scope_policy_policy; Type: INDEX; Schema: public; Owner: keycloak
--

CREATE INDEX idx_scope_policy_policy ON public.scope_policy USING btree (policy_id);


--
-- Name: idx_update_time; Type: INDEX; Schema: public; Owner: keycloak
--

CREATE INDEX idx_update_time ON public.migration_model USING btree (update_time);


--
-- Name: idx_usconsent_clscope; Type: INDEX; Schema: public; Owner: keycloak
--

CREATE INDEX idx_usconsent_clscope ON public.user_consent_client_scope USING btree (user_consent_id);


--
-- Name: idx_usconsent_scope_id; Type: INDEX; Schema: public; Owner: keycloak
--

CREATE INDEX idx_usconsent_scope_id ON public.user_consent_client_scope USING btree (scope_id);


--
-- Name: idx_user_attribute; Type: INDEX; Schema: public; Owner: keycloak
--

CREATE INDEX idx_user_attribute ON public.user_attribute USING btree (user_id);


--
-- Name: idx_user_attribute_name; Type: INDEX; Schema: public; Owner: keycloak
--

CREATE INDEX idx_user_attribute_name ON public.user_attribute USING btree (name, value);


--
-- Name: idx_user_consent; Type: INDEX; Schema: public; Owner: keycloak
--

CREATE INDEX idx_user_consent ON public.user_consent USING btree (user_id);


--
-- Name: idx_user_credential; Type: INDEX; Schema: public; Owner: keycloak
--

CREATE INDEX idx_user_credential ON public.credential USING btree (user_id);


--
-- Name: idx_user_email; Type: INDEX; Schema: public; Owner: keycloak
--

CREATE INDEX idx_user_email ON public.user_entity USING btree (email);


--
-- Name: idx_user_group_mapping; Type: INDEX; Schema: public; Owner: keycloak
--

CREATE INDEX idx_user_group_mapping ON public.user_group_membership USING btree (user_id);


--
-- Name: idx_user_reqactions; Type: INDEX; Schema: public; Owner: keycloak
--

CREATE INDEX idx_user_reqactions ON public.user_required_action USING btree (user_id);


--
-- Name: idx_user_role_mapping; Type: INDEX; Schema: public; Owner: keycloak
--

CREATE INDEX idx_user_role_mapping ON public.user_role_mapping USING btree (user_id);


--
-- Name: idx_user_service_account; Type: INDEX; Schema: public; Owner: keycloak
--

CREATE INDEX idx_user_service_account ON public.user_entity USING btree (realm_id, service_account_client_link);


--
-- Name: idx_user_session_expiration_created; Type: INDEX; Schema: public; Owner: keycloak
--

CREATE INDEX idx_user_session_expiration_created ON public.offline_user_session USING btree (realm_id, offline_flag, remember_me, created_on, user_session_id, user_id);


--
-- Name: idx_user_session_expiration_last_refresh; Type: INDEX; Schema: public; Owner: keycloak
--

CREATE INDEX idx_user_session_expiration_last_refresh ON public.offline_user_session USING btree (realm_id, offline_flag, remember_me, last_session_refresh, user_session_id, user_id);


--
-- Name: idx_usr_fed_map_fed_prv; Type: INDEX; Schema: public; Owner: keycloak
--

CREATE INDEX idx_usr_fed_map_fed_prv ON public.user_federation_mapper USING btree (federation_provider_id);


--
-- Name: idx_usr_fed_map_realm; Type: INDEX; Schema: public; Owner: keycloak
--

CREATE INDEX idx_usr_fed_map_realm ON public.user_federation_mapper USING btree (realm_id);


--
-- Name: idx_usr_fed_prv_realm; Type: INDEX; Schema: public; Owner: keycloak
--

CREATE INDEX idx_usr_fed_prv_realm ON public.user_federation_provider USING btree (realm_id);


--
-- Name: idx_web_orig_client; Type: INDEX; Schema: public; Owner: keycloak
--

CREATE INDEX idx_web_orig_client ON public.web_origins USING btree (client_id);


--
-- Name: idx_workflow_state_provider; Type: INDEX; Schema: public; Owner: keycloak
--

CREATE INDEX idx_workflow_state_provider ON public.workflow_state USING btree (resource_id);


--
-- Name: idx_workflow_state_step; Type: INDEX; Schema: public; Owner: keycloak
--

CREATE INDEX idx_workflow_state_step ON public.workflow_state USING btree (workflow_id, scheduled_step_id);


--
-- Name: user_attr_long_values; Type: INDEX; Schema: public; Owner: keycloak
--

CREATE INDEX user_attr_long_values ON public.user_attribute USING btree (long_value_hash, name);


--
-- Name: user_attr_long_values_lower_case; Type: INDEX; Schema: public; Owner: keycloak
--

CREATE INDEX user_attr_long_values_lower_case ON public.user_attribute USING btree (long_value_hash_lower_case, name);


--
-- Name: identity_provider fk2b4ebc52ae5c3b34; Type: FK CONSTRAINT; Schema: public; Owner: keycloak
--

ALTER TABLE ONLY public.identity_provider
    ADD CONSTRAINT fk2b4ebc52ae5c3b34 FOREIGN KEY (realm_id) REFERENCES public.realm(id);


--
-- Name: client_attributes fk3c47c64beacca966; Type: FK CONSTRAINT; Schema: public; Owner: keycloak
--

ALTER TABLE ONLY public.client_attributes
    ADD CONSTRAINT fk3c47c64beacca966 FOREIGN KEY (client_id) REFERENCES public.client(id);


--
-- Name: federated_identity fk404288b92ef007a6; Type: FK CONSTRAINT; Schema: public; Owner: keycloak
--

ALTER TABLE ONLY public.federated_identity
    ADD CONSTRAINT fk404288b92ef007a6 FOREIGN KEY (user_id) REFERENCES public.user_entity(id);


--
-- Name: client_node_registrations fk4129723ba992f594; Type: FK CONSTRAINT; Schema: public; Owner: keycloak
--

ALTER TABLE ONLY public.client_node_registrations
    ADD CONSTRAINT fk4129723ba992f594 FOREIGN KEY (client_id) REFERENCES public.client(id);


--
-- Name: redirect_uris fk_1burs8pb4ouj97h5wuppahv9f; Type: FK CONSTRAINT; Schema: public; Owner: keycloak
--

ALTER TABLE ONLY public.redirect_uris
    ADD CONSTRAINT fk_1burs8pb4ouj97h5wuppahv9f FOREIGN KEY (client_id) REFERENCES public.client(id);


--
-- Name: user_federation_provider fk_1fj32f6ptolw2qy60cd8n01e8; Type: FK CONSTRAINT; Schema: public; Owner: keycloak
--

ALTER TABLE ONLY public.user_federation_provider
    ADD CONSTRAINT fk_1fj32f6ptolw2qy60cd8n01e8 FOREIGN KEY (realm_id) REFERENCES public.realm(id);


--
-- Name: realm_required_credential fk_5hg65lybevavkqfki3kponh9v; Type: FK CONSTRAINT; Schema: public; Owner: keycloak
--

ALTER TABLE ONLY public.realm_required_credential
    ADD CONSTRAINT fk_5hg65lybevavkqfki3kponh9v FOREIGN KEY (realm_id) REFERENCES public.realm(id);


--
-- Name: resource_attribute fk_5hrm2vlf9ql5fu022kqepovbr; Type: FK CONSTRAINT; Schema: public; Owner: keycloak
--

ALTER TABLE ONLY public.resource_attribute
    ADD CONSTRAINT fk_5hrm2vlf9ql5fu022kqepovbr FOREIGN KEY (resource_id) REFERENCES public.resource_server_resource(id);


--
-- Name: user_attribute fk_5hrm2vlf9ql5fu043kqepovbr; Type: FK CONSTRAINT; Schema: public; Owner: keycloak
--

ALTER TABLE ONLY public.user_attribute
    ADD CONSTRAINT fk_5hrm2vlf9ql5fu043kqepovbr FOREIGN KEY (user_id) REFERENCES public.user_entity(id);


--
-- Name: user_required_action fk_6qj3w1jw9cvafhe19bwsiuvmd; Type: FK CONSTRAINT; Schema: public; Owner: keycloak
--

ALTER TABLE ONLY public.user_required_action
    ADD CONSTRAINT fk_6qj3w1jw9cvafhe19bwsiuvmd FOREIGN KEY (user_id) REFERENCES public.user_entity(id);


--
-- Name: keycloak_role fk_6vyqfe4cn4wlq8r6kt5vdsj5c; Type: FK CONSTRAINT; Schema: public; Owner: keycloak
--

ALTER TABLE ONLY public.keycloak_role
    ADD CONSTRAINT fk_6vyqfe4cn4wlq8r6kt5vdsj5c FOREIGN KEY (realm) REFERENCES public.realm(id);


--
-- Name: realm_smtp_config fk_70ej8xdxgxd0b9hh6180irr0o; Type: FK CONSTRAINT; Schema: public; Owner: keycloak
--

ALTER TABLE ONLY public.realm_smtp_config
    ADD CONSTRAINT fk_70ej8xdxgxd0b9hh6180irr0o FOREIGN KEY (realm_id) REFERENCES public.realm(id);


--
-- Name: realm_attribute fk_8shxd6l3e9atqukacxgpffptw; Type: FK CONSTRAINT; Schema: public; Owner: keycloak
--

ALTER TABLE ONLY public.realm_attribute
    ADD CONSTRAINT fk_8shxd6l3e9atqukacxgpffptw FOREIGN KEY (realm_id) REFERENCES public.realm(id);


--
-- Name: composite_role fk_a63wvekftu8jo1pnj81e7mce2; Type: FK CONSTRAINT; Schema: public; Owner: keycloak
--

ALTER TABLE ONLY public.composite_role
    ADD CONSTRAINT fk_a63wvekftu8jo1pnj81e7mce2 FOREIGN KEY (composite) REFERENCES public.keycloak_role(id);


--
-- Name: authentication_execution fk_auth_exec_flow; Type: FK CONSTRAINT; Schema: public; Owner: keycloak
--

ALTER TABLE ONLY public.authentication_execution
    ADD CONSTRAINT fk_auth_exec_flow FOREIGN KEY (flow_id) REFERENCES public.authentication_flow(id);


--
-- Name: authentication_execution fk_auth_exec_realm; Type: FK CONSTRAINT; Schema: public; Owner: keycloak
--

ALTER TABLE ONLY public.authentication_execution
    ADD CONSTRAINT fk_auth_exec_realm FOREIGN KEY (realm_id) REFERENCES public.realm(id);


--
-- Name: authentication_flow fk_auth_flow_realm; Type: FK CONSTRAINT; Schema: public; Owner: keycloak
--

ALTER TABLE ONLY public.authentication_flow
    ADD CONSTRAINT fk_auth_flow_realm FOREIGN KEY (realm_id) REFERENCES public.realm(id);


--
-- Name: authenticator_config fk_auth_realm; Type: FK CONSTRAINT; Schema: public; Owner: keycloak
--

ALTER TABLE ONLY public.authenticator_config
    ADD CONSTRAINT fk_auth_realm FOREIGN KEY (realm_id) REFERENCES public.realm(id);


--
-- Name: user_role_mapping fk_c4fqv34p1mbylloxang7b1q3l; Type: FK CONSTRAINT; Schema: public; Owner: keycloak
--

ALTER TABLE ONLY public.user_role_mapping
    ADD CONSTRAINT fk_c4fqv34p1mbylloxang7b1q3l FOREIGN KEY (user_id) REFERENCES public.user_entity(id);


--
-- Name: client_scope_attributes fk_cl_scope_attr_scope; Type: FK CONSTRAINT; Schema: public; Owner: keycloak
--

ALTER TABLE ONLY public.client_scope_attributes
    ADD CONSTRAINT fk_cl_scope_attr_scope FOREIGN KEY (scope_id) REFERENCES public.client_scope(id);


--
-- Name: client_scope_role_mapping fk_cl_scope_rm_scope; Type: FK CONSTRAINT; Schema: public; Owner: keycloak
--

ALTER TABLE ONLY public.client_scope_role_mapping
    ADD CONSTRAINT fk_cl_scope_rm_scope FOREIGN KEY (scope_id) REFERENCES public.client_scope(id);


--
-- Name: protocol_mapper fk_cli_scope_mapper; Type: FK CONSTRAINT; Schema: public; Owner: keycloak
--

ALTER TABLE ONLY public.protocol_mapper
    ADD CONSTRAINT fk_cli_scope_mapper FOREIGN KEY (client_scope_id) REFERENCES public.client_scope(id);


--
-- Name: client_initial_access fk_client_init_acc_realm; Type: FK CONSTRAINT; Schema: public; Owner: keycloak
--

ALTER TABLE ONLY public.client_initial_access
    ADD CONSTRAINT fk_client_init_acc_realm FOREIGN KEY (realm_id) REFERENCES public.realm(id);


--
-- Name: component_config fk_component_config; Type: FK CONSTRAINT; Schema: public; Owner: keycloak
--

ALTER TABLE ONLY public.component_config
    ADD CONSTRAINT fk_component_config FOREIGN KEY (component_id) REFERENCES public.component(id);


--
-- Name: component fk_component_realm; Type: FK CONSTRAINT; Schema: public; Owner: keycloak
--

ALTER TABLE ONLY public.component
    ADD CONSTRAINT fk_component_realm FOREIGN KEY (realm_id) REFERENCES public.realm(id);


--
-- Name: realm_default_groups fk_def_groups_realm; Type: FK CONSTRAINT; Schema: public; Owner: keycloak
--

ALTER TABLE ONLY public.realm_default_groups
    ADD CONSTRAINT fk_def_groups_realm FOREIGN KEY (realm_id) REFERENCES public.realm(id);


--
-- Name: user_federation_mapper_config fk_fedmapper_cfg; Type: FK CONSTRAINT; Schema: public; Owner: keycloak
--

ALTER TABLE ONLY public.user_federation_mapper_config
    ADD CONSTRAINT fk_fedmapper_cfg FOREIGN KEY (user_federation_mapper_id) REFERENCES public.user_federation_mapper(id);


--
-- Name: user_federation_mapper fk_fedmapperpm_fedprv; Type: FK CONSTRAINT; Schema: public; Owner: keycloak
--

ALTER TABLE ONLY public.user_federation_mapper
    ADD CONSTRAINT fk_fedmapperpm_fedprv FOREIGN KEY (federation_provider_id) REFERENCES public.user_federation_provider(id);


--
-- Name: user_federation_mapper fk_fedmapperpm_realm; Type: FK CONSTRAINT; Schema: public; Owner: keycloak
--

ALTER TABLE ONLY public.user_federation_mapper
    ADD CONSTRAINT fk_fedmapperpm_realm FOREIGN KEY (realm_id) REFERENCES public.realm(id);


--
-- Name: associated_policy fk_frsr5s213xcx4wnkog82ssrfy; Type: FK CONSTRAINT; Schema: public; Owner: keycloak
--

ALTER TABLE ONLY public.associated_policy
    ADD CONSTRAINT fk_frsr5s213xcx4wnkog82ssrfy FOREIGN KEY (associated_policy_id) REFERENCES public.resource_server_policy(id);


--
-- Name: scope_policy fk_frsrasp13xcx4wnkog82ssrfy; Type: FK CONSTRAINT; Schema: public; Owner: keycloak
--

ALTER TABLE ONLY public.scope_policy
    ADD CONSTRAINT fk_frsrasp13xcx4wnkog82ssrfy FOREIGN KEY (policy_id) REFERENCES public.resource_server_policy(id);


--
-- Name: resource_server_perm_ticket fk_frsrho213xcx4wnkog82sspmt; Type: FK CONSTRAINT; Schema: public; Owner: keycloak
--

ALTER TABLE ONLY public.resource_server_perm_ticket
    ADD CONSTRAINT fk_frsrho213xcx4wnkog82sspmt FOREIGN KEY (resource_server_id) REFERENCES public.resource_server(id);


--
-- Name: resource_server_resource fk_frsrho213xcx4wnkog82ssrfy; Type: FK CONSTRAINT; Schema: public; Owner: keycloak
--

ALTER TABLE ONLY public.resource_server_resource
    ADD CONSTRAINT fk_frsrho213xcx4wnkog82ssrfy FOREIGN KEY (resource_server_id) REFERENCES public.resource_server(id);


--
-- Name: resource_server_perm_ticket fk_frsrho213xcx4wnkog83sspmt; Type: FK CONSTRAINT; Schema: public; Owner: keycloak
--

ALTER TABLE ONLY public.resource_server_perm_ticket
    ADD CONSTRAINT fk_frsrho213xcx4wnkog83sspmt FOREIGN KEY (resource_id) REFERENCES public.resource_server_resource(id);


--
-- Name: resource_server_perm_ticket fk_frsrho213xcx4wnkog84sspmt; Type: FK CONSTRAINT; Schema: public; Owner: keycloak
--

ALTER TABLE ONLY public.resource_server_perm_ticket
    ADD CONSTRAINT fk_frsrho213xcx4wnkog84sspmt FOREIGN KEY (scope_id) REFERENCES public.resource_server_scope(id);


--
-- Name: associated_policy fk_frsrpas14xcx4wnkog82ssrfy; Type: FK CONSTRAINT; Schema: public; Owner: keycloak
--

ALTER TABLE ONLY public.associated_policy
    ADD CONSTRAINT fk_frsrpas14xcx4wnkog82ssrfy FOREIGN KEY (policy_id) REFERENCES public.resource_server_policy(id);


--
-- Name: scope_policy fk_frsrpass3xcx4wnkog82ssrfy; Type: FK CONSTRAINT; Schema: public; Owner: keycloak
--

ALTER TABLE ONLY public.scope_policy
    ADD CONSTRAINT fk_frsrpass3xcx4wnkog82ssrfy FOREIGN KEY (scope_id) REFERENCES public.resource_server_scope(id);


--
-- Name: resource_server_perm_ticket fk_frsrpo2128cx4wnkog82ssrfy; Type: FK CONSTRAINT; Schema: public; Owner: keycloak
--

ALTER TABLE ONLY public.resource_server_perm_ticket
    ADD CONSTRAINT fk_frsrpo2128cx4wnkog82ssrfy FOREIGN KEY (policy_id) REFERENCES public.resource_server_policy(id);


--
-- Name: resource_server_policy fk_frsrpo213xcx4wnkog82ssrfy; Type: FK CONSTRAINT; Schema: public; Owner: keycloak
--

ALTER TABLE ONLY public.resource_server_policy
    ADD CONSTRAINT fk_frsrpo213xcx4wnkog82ssrfy FOREIGN KEY (resource_server_id) REFERENCES public.resource_server(id);


--
-- Name: resource_scope fk_frsrpos13xcx4wnkog82ssrfy; Type: FK CONSTRAINT; Schema: public; Owner: keycloak
--

ALTER TABLE ONLY public.resource_scope
    ADD CONSTRAINT fk_frsrpos13xcx4wnkog82ssrfy FOREIGN KEY (resource_id) REFERENCES public.resource_server_resource(id);


--
-- Name: resource_policy fk_frsrpos53xcx4wnkog82ssrfy; Type: FK CONSTRAINT; Schema: public; Owner: keycloak
--

ALTER TABLE ONLY public.resource_policy
    ADD CONSTRAINT fk_frsrpos53xcx4wnkog82ssrfy FOREIGN KEY (resource_id) REFERENCES public.resource_server_resource(id);


--
-- Name: resource_policy fk_frsrpp213xcx4wnkog82ssrfy; Type: FK CONSTRAINT; Schema: public; Owner: keycloak
--

ALTER TABLE ONLY public.resource_policy
    ADD CONSTRAINT fk_frsrpp213xcx4wnkog82ssrfy FOREIGN KEY (policy_id) REFERENCES public.resource_server_policy(id);


--
-- Name: resource_scope fk_frsrps213xcx4wnkog82ssrfy; Type: FK CONSTRAINT; Schema: public; Owner: keycloak
--

ALTER TABLE ONLY public.resource_scope
    ADD CONSTRAINT fk_frsrps213xcx4wnkog82ssrfy FOREIGN KEY (scope_id) REFERENCES public.resource_server_scope(id);


--
-- Name: resource_server_scope fk_frsrso213xcx4wnkog82ssrfy; Type: FK CONSTRAINT; Schema: public; Owner: keycloak
--

ALTER TABLE ONLY public.resource_server_scope
    ADD CONSTRAINT fk_frsrso213xcx4wnkog82ssrfy FOREIGN KEY (resource_server_id) REFERENCES public.resource_server(id);


--
-- Name: composite_role fk_gr7thllb9lu8q4vqa4524jjy8; Type: FK CONSTRAINT; Schema: public; Owner: keycloak
--

ALTER TABLE ONLY public.composite_role
    ADD CONSTRAINT fk_gr7thllb9lu8q4vqa4524jjy8 FOREIGN KEY (child_role) REFERENCES public.keycloak_role(id);


--
-- Name: user_consent_client_scope fk_grntcsnt_clsc_usc; Type: FK CONSTRAINT; Schema: public; Owner: keycloak
--

ALTER TABLE ONLY public.user_consent_client_scope
    ADD CONSTRAINT fk_grntcsnt_clsc_usc FOREIGN KEY (user_consent_id) REFERENCES public.user_consent(id);


--
-- Name: user_consent fk_grntcsnt_user; Type: FK CONSTRAINT; Schema: public; Owner: keycloak
--

ALTER TABLE ONLY public.user_consent
    ADD CONSTRAINT fk_grntcsnt_user FOREIGN KEY (user_id) REFERENCES public.user_entity(id);


--
-- Name: group_attribute fk_group_attribute_group; Type: FK CONSTRAINT; Schema: public; Owner: keycloak
--

ALTER TABLE ONLY public.group_attribute
    ADD CONSTRAINT fk_group_attribute_group FOREIGN KEY (group_id) REFERENCES public.keycloak_group(id);


--
-- Name: group_role_mapping fk_group_role_group; Type: FK CONSTRAINT; Schema: public; Owner: keycloak
--

ALTER TABLE ONLY public.group_role_mapping
    ADD CONSTRAINT fk_group_role_group FOREIGN KEY (group_id) REFERENCES public.keycloak_group(id);


--
-- Name: realm_enabled_event_types fk_h846o4h0w8epx5nwedrf5y69j; Type: FK CONSTRAINT; Schema: public; Owner: keycloak
--

ALTER TABLE ONLY public.realm_enabled_event_types
    ADD CONSTRAINT fk_h846o4h0w8epx5nwedrf5y69j FOREIGN KEY (realm_id) REFERENCES public.realm(id);


--
-- Name: realm_events_listeners fk_h846o4h0w8epx5nxev9f5y69j; Type: FK CONSTRAINT; Schema: public; Owner: keycloak
--

ALTER TABLE ONLY public.realm_events_listeners
    ADD CONSTRAINT fk_h846o4h0w8epx5nxev9f5y69j FOREIGN KEY (realm_id) REFERENCES public.realm(id);


--
-- Name: identity_provider_mapper fk_idpm_realm; Type: FK CONSTRAINT; Schema: public; Owner: keycloak
--

ALTER TABLE ONLY public.identity_provider_mapper
    ADD CONSTRAINT fk_idpm_realm FOREIGN KEY (realm_id) REFERENCES public.realm(id);


--
-- Name: idp_mapper_config fk_idpmconfig; Type: FK CONSTRAINT; Schema: public; Owner: keycloak
--

ALTER TABLE ONLY public.idp_mapper_config
    ADD CONSTRAINT fk_idpmconfig FOREIGN KEY (idp_mapper_id) REFERENCES public.identity_provider_mapper(id);


--
-- Name: web_origins fk_lojpho213xcx4wnkog82ssrfy; Type: FK CONSTRAINT; Schema: public; Owner: keycloak
--

ALTER TABLE ONLY public.web_origins
    ADD CONSTRAINT fk_lojpho213xcx4wnkog82ssrfy FOREIGN KEY (client_id) REFERENCES public.client(id);


--
-- Name: org_invitation fk_org_invitation_org; Type: FK CONSTRAINT; Schema: public; Owner: keycloak
--

ALTER TABLE ONLY public.org_invitation
    ADD CONSTRAINT fk_org_invitation_org FOREIGN KEY (organization_id) REFERENCES public.org(id) ON DELETE CASCADE;


--
-- Name: scope_mapping fk_ouse064plmlr732lxjcn1q5f1; Type: FK CONSTRAINT; Schema: public; Owner: keycloak
--

ALTER TABLE ONLY public.scope_mapping
    ADD CONSTRAINT fk_ouse064plmlr732lxjcn1q5f1 FOREIGN KEY (client_id) REFERENCES public.client(id);


--
-- Name: protocol_mapper fk_pcm_realm; Type: FK CONSTRAINT; Schema: public; Owner: keycloak
--

ALTER TABLE ONLY public.protocol_mapper
    ADD CONSTRAINT fk_pcm_realm FOREIGN KEY (client_id) REFERENCES public.client(id);


--
-- Name: credential fk_pfyr0glasqyl0dei3kl69r6v0; Type: FK CONSTRAINT; Schema: public; Owner: keycloak
--

ALTER TABLE ONLY public.credential
    ADD CONSTRAINT fk_pfyr0glasqyl0dei3kl69r6v0 FOREIGN KEY (user_id) REFERENCES public.user_entity(id);


--
-- Name: protocol_mapper_config fk_pmconfig; Type: FK CONSTRAINT; Schema: public; Owner: keycloak
--

ALTER TABLE ONLY public.protocol_mapper_config
    ADD CONSTRAINT fk_pmconfig FOREIGN KEY (protocol_mapper_id) REFERENCES public.protocol_mapper(id);


--
-- Name: default_client_scope fk_r_def_cli_scope_realm; Type: FK CONSTRAINT; Schema: public; Owner: keycloak
--

ALTER TABLE ONLY public.default_client_scope
    ADD CONSTRAINT fk_r_def_cli_scope_realm FOREIGN KEY (realm_id) REFERENCES public.realm(id);


--
-- Name: required_action_provider fk_req_act_realm; Type: FK CONSTRAINT; Schema: public; Owner: keycloak
--

ALTER TABLE ONLY public.required_action_provider
    ADD CONSTRAINT fk_req_act_realm FOREIGN KEY (realm_id) REFERENCES public.realm(id);


--
-- Name: resource_uris fk_resource_server_uris; Type: FK CONSTRAINT; Schema: public; Owner: keycloak
--

ALTER TABLE ONLY public.resource_uris
    ADD CONSTRAINT fk_resource_server_uris FOREIGN KEY (resource_id) REFERENCES public.resource_server_resource(id);


--
-- Name: role_attribute fk_role_attribute_id; Type: FK CONSTRAINT; Schema: public; Owner: keycloak
--

ALTER TABLE ONLY public.role_attribute
    ADD CONSTRAINT fk_role_attribute_id FOREIGN KEY (role_id) REFERENCES public.keycloak_role(id);


--
-- Name: realm_supported_locales fk_supported_locales_realm; Type: FK CONSTRAINT; Schema: public; Owner: keycloak
--

ALTER TABLE ONLY public.realm_supported_locales
    ADD CONSTRAINT fk_supported_locales_realm FOREIGN KEY (realm_id) REFERENCES public.realm(id);


--
-- Name: user_federation_config fk_t13hpu1j94r2ebpekr39x5eu5; Type: FK CONSTRAINT; Schema: public; Owner: keycloak
--

ALTER TABLE ONLY public.user_federation_config
    ADD CONSTRAINT fk_t13hpu1j94r2ebpekr39x5eu5 FOREIGN KEY (user_federation_provider_id) REFERENCES public.user_federation_provider(id);


--
-- Name: user_group_membership fk_user_group_user; Type: FK CONSTRAINT; Schema: public; Owner: keycloak
--

ALTER TABLE ONLY public.user_group_membership
    ADD CONSTRAINT fk_user_group_user FOREIGN KEY (user_id) REFERENCES public.user_entity(id);


--
-- Name: policy_config fkdc34197cf864c4e43; Type: FK CONSTRAINT; Schema: public; Owner: keycloak
--

ALTER TABLE ONLY public.policy_config
    ADD CONSTRAINT fkdc34197cf864c4e43 FOREIGN KEY (policy_id) REFERENCES public.resource_server_policy(id);


--
-- Name: identity_provider_config fkdc4897cf864c4e43; Type: FK CONSTRAINT; Schema: public; Owner: keycloak
--

ALTER TABLE ONLY public.identity_provider_config
    ADD CONSTRAINT fkdc4897cf864c4e43 FOREIGN KEY (identity_provider_id) REFERENCES public.identity_provider(internal_id);


--
-- PostgreSQL database dump complete
--

\unrestrict Z6HgIX3IUbNXHTglkzQNMUWXtLxNBu0YLdaWfF4M47KPTWfhVu7KRdaN2CnYFaZ

