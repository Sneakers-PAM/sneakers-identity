-- Copyright 2026 The Sneakers-PAM Authors
-- SPDX-License-Identifier: Apache-2.0

-- Baseline schema for the identity service. Forward-only from here: later
-- changes are new numbered migrations starting at 0002.

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

CREATE TABLE public.api_tokens (
    id text NOT NULL,
    service_account_id text NOT NULL,
    token_hash text NOT NULL,
    scope text DEFAULT ''::text NOT NULL,
    expires_at timestamp with time zone,
    revoked_at timestamp with time zone,
    last_used_at timestamp with time zone,
    created_by text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);

CREATE TABLE public.group_membership (
    user_id text NOT NULL,
    group_id text NOT NULL,
    added_at timestamp with time zone DEFAULT now() NOT NULL,
    added_by_user_id text
);

CREATE TABLE public.groups (
    id text NOT NULL,
    name text NOT NULL
);

CREATE TABLE public.service_accounts (
    id text NOT NULL,
    name text NOT NULL,
    description text DEFAULT ''::text NOT NULL,
    disabled boolean DEFAULT false NOT NULL,
    created_by text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    oidc_issuer text,
    oidc_subject text,
    oidc_allowed_groups text[] DEFAULT '{}'::text[] NOT NULL
);

CREATE TABLE public.user_email_otp (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    user_id text NOT NULL,
    purpose text NOT NULL,
    code_hash text NOT NULL,
    attempts integer DEFAULT 0 NOT NULL,
    expires_at timestamp with time zone NOT NULL,
    consumed_at timestamp with time zone,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);

CREATE TABLE public.user_tokens (
    id text NOT NULL,
    user_id text NOT NULL,
    token_hash text NOT NULL,
    label text DEFAULT ''::text NOT NULL,
    client_name text DEFAULT ''::text NOT NULL,
    expires_at timestamp with time zone,
    revoked_at timestamp with time zone,
    last_used_at timestamp with time zone,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);

CREATE TABLE public.user_totp (
    user_id text NOT NULL,
    encrypted_secret text NOT NULL,
    confirmed_at timestamp with time zone,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);

CREATE TABLE public.user_webauthn_credentials (
    credential_id text NOT NULL,
    user_id text NOT NULL,
    public_key bytea NOT NULL,
    sign_count bigint DEFAULT 0 NOT NULL,
    aaguid bytea,
    transports text[] DEFAULT '{}'::text[] NOT NULL,
    backup_eligible boolean DEFAULT false NOT NULL,
    backup_state boolean DEFAULT false NOT NULL,
    label text DEFAULT ''::text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    last_used_at timestamp with time zone
);

CREATE TABLE public.users (
    id text NOT NULL,
    name text NOT NULL,
    email text NOT NULL,
    roles text[] DEFAULT '{}'::text[] NOT NULL,
    is_root boolean DEFAULT false NOT NULL,
    subject text DEFAULT ''::text NOT NULL,
    username text DEFAULT ''::text NOT NULL,
    email_verified boolean DEFAULT false NOT NULL,
    disabled_at timestamp with time zone
);

CREATE TABLE public.webauthn_sessions (
    session_id text NOT NULL,
    user_id text NOT NULL,
    purpose text NOT NULL,
    data_json text NOT NULL,
    expires_at timestamp with time zone NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);

ALTER TABLE ONLY public.api_tokens
    ADD CONSTRAINT api_tokens_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.api_tokens
    ADD CONSTRAINT api_tokens_token_hash_key UNIQUE (token_hash);

ALTER TABLE ONLY public.group_membership
    ADD CONSTRAINT group_membership_pkey PRIMARY KEY (user_id, group_id);

ALTER TABLE ONLY public.groups
    ADD CONSTRAINT groups_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.service_accounts
    ADD CONSTRAINT service_accounts_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.user_email_otp
    ADD CONSTRAINT user_email_otp_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.user_tokens
    ADD CONSTRAINT user_tokens_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.user_tokens
    ADD CONSTRAINT user_tokens_token_hash_key UNIQUE (token_hash);

ALTER TABLE ONLY public.user_totp
    ADD CONSTRAINT user_totp_pkey PRIMARY KEY (user_id);

ALTER TABLE ONLY public.user_webauthn_credentials
    ADD CONSTRAINT user_webauthn_credentials_pkey PRIMARY KEY (credential_id);

ALTER TABLE ONLY public.users
    ADD CONSTRAINT users_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.webauthn_sessions
    ADD CONSTRAINT webauthn_sessions_pkey PRIMARY KEY (session_id);

CREATE INDEX api_tokens_sa_idx ON public.api_tokens USING btree (service_account_id);

CREATE INDEX group_membership_group_id_idx ON public.group_membership USING btree (group_id);

CREATE UNIQUE INDEX groups_name_lower_idx ON public.groups USING btree (lower(name));

CREATE INDEX idx_users_username ON public.users USING btree (username) WHERE (username <> ''::text);

CREATE UNIQUE INDEX service_accounts_name_idx ON public.service_accounts USING btree (lower(name));

CREATE UNIQUE INDEX service_accounts_oidc_idx ON public.service_accounts USING btree (oidc_issuer, oidc_subject) WHERE (oidc_subject IS NOT NULL);

CREATE INDEX user_email_otp_user_purpose_idx ON public.user_email_otp USING btree (user_id, purpose, created_at DESC);

CREATE INDEX user_tokens_user_idx ON public.user_tokens USING btree (user_id);

CREATE INDEX user_webauthn_credentials_user_idx ON public.user_webauthn_credentials USING btree (user_id, created_at);

CREATE INDEX users_email_idx ON public.users USING btree (lower(email));

CREATE UNIQUE INDEX users_subject_key ON public.users USING btree (subject) WHERE (subject <> ''::text);

CREATE UNIQUE INDEX users_single_root_idx ON public.users USING btree (is_root) WHERE is_root;

CREATE INDEX webauthn_sessions_user_purpose_idx ON public.webauthn_sessions USING btree (user_id, purpose);

ALTER TABLE ONLY public.api_tokens
    ADD CONSTRAINT api_tokens_service_account_id_fkey FOREIGN KEY (service_account_id) REFERENCES public.service_accounts(id) ON DELETE CASCADE;

ALTER TABLE ONLY public.group_membership
    ADD CONSTRAINT group_membership_added_by_user_id_fkey FOREIGN KEY (added_by_user_id) REFERENCES public.users(id) ON DELETE SET NULL;

ALTER TABLE ONLY public.group_membership
    ADD CONSTRAINT group_membership_group_id_fkey FOREIGN KEY (group_id) REFERENCES public.groups(id) ON DELETE CASCADE;

ALTER TABLE ONLY public.group_membership
    ADD CONSTRAINT group_membership_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE;

ALTER TABLE ONLY public.user_email_otp
    ADD CONSTRAINT user_email_otp_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE;

ALTER TABLE ONLY public.user_tokens
    ADD CONSTRAINT user_tokens_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE;

ALTER TABLE ONLY public.user_totp
    ADD CONSTRAINT user_totp_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE;
