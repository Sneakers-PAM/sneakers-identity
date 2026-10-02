-- Copyright 2026 The Sneakers-PAM Authors
-- SPDX-License-Identifier: Apache-2.0

-- Baseline schema for the identity service. Forward-only from here.

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



CREATE TABLE public.user_ad_groups (
    user_id text NOT NULL,
    ad_group_name text NOT NULL,
    synced_at timestamp with time zone DEFAULT now() NOT NULL
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
    keycloak_subject text DEFAULT ''::text NOT NULL,
    username text DEFAULT ''::text NOT NULL
);



CREATE TABLE public.webauthn_sessions (
    session_id text NOT NULL,
    user_id text NOT NULL,
    purpose text NOT NULL,
    data_json text NOT NULL,
    expires_at timestamp with time zone NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);



ALTER TABLE ONLY public.group_membership
    ADD CONSTRAINT group_membership_pkey PRIMARY KEY (user_id, group_id);



ALTER TABLE ONLY public.groups
    ADD CONSTRAINT groups_pkey PRIMARY KEY (id);



ALTER TABLE ONLY public.user_ad_groups
    ADD CONSTRAINT user_ad_groups_pkey PRIMARY KEY (user_id, ad_group_name);



ALTER TABLE ONLY public.user_email_otp
    ADD CONSTRAINT user_email_otp_pkey PRIMARY KEY (id);



ALTER TABLE ONLY public.user_totp
    ADD CONSTRAINT user_totp_pkey PRIMARY KEY (user_id);



ALTER TABLE ONLY public.user_webauthn_credentials
    ADD CONSTRAINT user_webauthn_credentials_pkey PRIMARY KEY (credential_id);



ALTER TABLE ONLY public.users
    ADD CONSTRAINT users_pkey PRIMARY KEY (id);



ALTER TABLE ONLY public.webauthn_sessions
    ADD CONSTRAINT webauthn_sessions_pkey PRIMARY KEY (session_id);



CREATE INDEX group_membership_group_id_idx ON public.group_membership USING btree (group_id);



CREATE INDEX idx_users_username ON public.users USING btree (username) WHERE (username <> ''::text);



CREATE INDEX user_email_otp_user_purpose_idx ON public.user_email_otp USING btree (user_id, purpose, created_at DESC);



CREATE INDEX user_webauthn_credentials_user_idx ON public.user_webauthn_credentials USING btree (user_id, created_at);



CREATE INDEX users_email_idx ON public.users USING btree (lower(email));



CREATE UNIQUE INDEX users_keycloak_subject_key ON public.users USING btree (keycloak_subject) WHERE (keycloak_subject <> ''::text);



CREATE UNIQUE INDEX users_single_root_idx ON public.users USING btree (is_root) WHERE is_root;



CREATE INDEX webauthn_sessions_user_purpose_idx ON public.webauthn_sessions USING btree (user_id, purpose);



ALTER TABLE ONLY public.group_membership
    ADD CONSTRAINT group_membership_added_by_user_id_fkey FOREIGN KEY (added_by_user_id) REFERENCES public.users(id) ON DELETE SET NULL;



ALTER TABLE ONLY public.group_membership
    ADD CONSTRAINT group_membership_group_id_fkey FOREIGN KEY (group_id) REFERENCES public.groups(id) ON DELETE CASCADE;



ALTER TABLE ONLY public.group_membership
    ADD CONSTRAINT group_membership_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE;



ALTER TABLE ONLY public.user_ad_groups
    ADD CONSTRAINT user_ad_groups_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE;



ALTER TABLE ONLY public.user_email_otp
    ADD CONSTRAINT user_email_otp_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE;



ALTER TABLE ONLY public.user_totp
    ADD CONSTRAINT user_totp_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE;




