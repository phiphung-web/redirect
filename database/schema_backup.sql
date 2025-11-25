--
-- PostgreSQL database dump
--

\restrict cxEfjTZjQ1Pmh36oKtQJgJUBV440XeJnk6RSmUlmnMnnumtTbbDHslfdr2aSLKK

-- Dumped from database version 14.19 (Ubuntu 14.19-0ubuntu0.22.04.1)
-- Dumped by pg_dump version 14.19 (Ubuntu 14.19-0ubuntu0.22.04.1)

SET statement_timeout = 0;
SET lock_timeout = 0;
SET idle_in_transaction_session_timeout = 0;
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
-- Name: campaigns; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.campaigns (
    id integer NOT NULL,
    domain_id integer NOT NULL,
    user_id integer,
    name text NOT NULL,
    target_url text NOT NULL,
    is_active boolean DEFAULT true,
    filters jsonb DEFAULT '{}'::jsonb,
    stats_views integer DEFAULT 0,
    stats_redirects integer DEFAULT 0,
    created_at timestamp without time zone DEFAULT now(),
    rules jsonb DEFAULT '[]'::jsonb,
    param_key text DEFAULT 'q'::text,
    param_value text
);


ALTER TABLE public.campaigns OWNER TO postgres;

--
-- Name: campaigns_id_seq; Type: SEQUENCE; Schema: public; Owner: postgres
--

CREATE SEQUENCE public.campaigns_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE public.campaigns_id_seq OWNER TO postgres;

--
-- Name: campaigns_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: postgres
--

ALTER SEQUENCE public.campaigns_id_seq OWNED BY public.campaigns.id;


--
-- Name: domains; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.domains (
    id integer NOT NULL,
    user_id integer,
    domain_url text NOT NULL,
    status text DEFAULT 'active'::text,
    safe_template text DEFAULT 'news'::text,
    safe_content jsonb DEFAULT '{"title": "Tin Tức 24h", "headline": "Cập nhật mới nhất"}'::jsonb,
    created_at timestamp without time zone DEFAULT now()
);


ALTER TABLE public.domains OWNER TO postgres;

--
-- Name: domains_id_seq; Type: SEQUENCE; Schema: public; Owner: postgres
--

CREATE SEQUENCE public.domains_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE public.domains_id_seq OWNER TO postgres;

--
-- Name: domains_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: postgres
--

ALTER SEQUENCE public.domains_id_seq OWNED BY public.domains.id;


--
-- Name: roles; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.roles (
    id integer NOT NULL,
    name text NOT NULL,
    description text
);


ALTER TABLE public.roles OWNER TO postgres;

--
-- Name: roles_id_seq; Type: SEQUENCE; Schema: public; Owner: postgres
--

CREATE SEQUENCE public.roles_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE public.roles_id_seq OWNER TO postgres;

--
-- Name: roles_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: postgres
--

ALTER SEQUENCE public.roles_id_seq OWNED BY public.roles.id;


--
-- Name: traffic_logs; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.traffic_logs (
    id bigint NOT NULL,
    campaign_id integer,
    domain_id integer,
    ip text,
    country text,
    city text,
    device_type text,
    os_name text,
    browser_name text,
    action text,
    referer text,
    user_agent text,
    created_at timestamp without time zone DEFAULT now()
)
PARTITION BY RANGE (created_at);


ALTER TABLE public.traffic_logs OWNER TO postgres;

--
-- Name: traffic_logs_id_seq; Type: SEQUENCE; Schema: public; Owner: postgres
--

CREATE SEQUENCE public.traffic_logs_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE public.traffic_logs_id_seq OWNER TO postgres;

--
-- Name: traffic_logs_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: postgres
--

ALTER SEQUENCE public.traffic_logs_id_seq OWNED BY public.traffic_logs.id;


--
-- Name: traffic_logs_2024; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.traffic_logs_2024 (
    id bigint DEFAULT nextval('public.traffic_logs_id_seq'::regclass) NOT NULL,
    campaign_id integer,
    domain_id integer,
    ip text,
    country text,
    city text,
    device_type text,
    os_name text,
    browser_name text,
    action text,
    referer text,
    user_agent text,
    created_at timestamp without time zone DEFAULT now()
);


ALTER TABLE public.traffic_logs_2024 OWNER TO postgres;

--
-- Name: traffic_logs_2025; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.traffic_logs_2025 (
    id bigint DEFAULT nextval('public.traffic_logs_id_seq'::regclass) NOT NULL,
    campaign_id integer,
    domain_id integer,
    ip text,
    country text,
    city text,
    device_type text,
    os_name text,
    browser_name text,
    action text,
    referer text,
    user_agent text,
    created_at timestamp without time zone DEFAULT now()
);


ALTER TABLE public.traffic_logs_2025 OWNER TO postgres;

--
-- Name: traffic_logs_default; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.traffic_logs_default (
    id bigint DEFAULT nextval('public.traffic_logs_id_seq'::regclass) NOT NULL,
    campaign_id integer,
    domain_id integer,
    ip text,
    country text,
    city text,
    device_type text,
    os_name text,
    browser_name text,
    action text,
    referer text,
    user_agent text,
    created_at timestamp without time zone DEFAULT now()
);


ALTER TABLE public.traffic_logs_default OWNER TO postgres;

--
-- Name: users; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.users (
    id integer NOT NULL,
    username text NOT NULL,
    password_hash text NOT NULL,
    role_id integer,
    is_active boolean DEFAULT true,
    created_at timestamp without time zone DEFAULT now()
);


ALTER TABLE public.users OWNER TO postgres;

--
-- Name: users_id_seq; Type: SEQUENCE; Schema: public; Owner: postgres
--

CREATE SEQUENCE public.users_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE public.users_id_seq OWNER TO postgres;

--
-- Name: users_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: postgres
--

ALTER SEQUENCE public.users_id_seq OWNED BY public.users.id;


--
-- Name: traffic_logs_2024; Type: TABLE ATTACH; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.traffic_logs ATTACH PARTITION public.traffic_logs_2024 FOR VALUES FROM ('2024-01-01 00:00:00') TO ('2025-01-01 00:00:00');


--
-- Name: traffic_logs_2025; Type: TABLE ATTACH; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.traffic_logs ATTACH PARTITION public.traffic_logs_2025 FOR VALUES FROM ('2025-01-01 00:00:00') TO ('2026-01-01 00:00:00');


--
-- Name: traffic_logs_default; Type: TABLE ATTACH; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.traffic_logs ATTACH PARTITION public.traffic_logs_default DEFAULT;


--
-- Name: campaigns id; Type: DEFAULT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.campaigns ALTER COLUMN id SET DEFAULT nextval('public.campaigns_id_seq'::regclass);


--
-- Name: domains id; Type: DEFAULT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.domains ALTER COLUMN id SET DEFAULT nextval('public.domains_id_seq'::regclass);


--
-- Name: roles id; Type: DEFAULT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.roles ALTER COLUMN id SET DEFAULT nextval('public.roles_id_seq'::regclass);


--
-- Name: traffic_logs id; Type: DEFAULT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.traffic_logs ALTER COLUMN id SET DEFAULT nextval('public.traffic_logs_id_seq'::regclass);


--
-- Name: users id; Type: DEFAULT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.users ALTER COLUMN id SET DEFAULT nextval('public.users_id_seq'::regclass);


--
-- Name: campaigns campaigns_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.campaigns
    ADD CONSTRAINT campaigns_pkey PRIMARY KEY (id);


--
-- Name: domains domains_domain_url_key; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.domains
    ADD CONSTRAINT domains_domain_url_key UNIQUE (domain_url);


--
-- Name: domains domains_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.domains
    ADD CONSTRAINT domains_pkey PRIMARY KEY (id);


--
-- Name: roles roles_name_key; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.roles
    ADD CONSTRAINT roles_name_key UNIQUE (name);


--
-- Name: roles roles_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.roles
    ADD CONSTRAINT roles_pkey PRIMARY KEY (id);


--
-- Name: users users_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.users
    ADD CONSTRAINT users_pkey PRIMARY KEY (id);


--
-- Name: users users_username_key; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.users
    ADD CONSTRAINT users_username_key UNIQUE (username);


--
-- Name: idx_camp_identity; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_camp_identity ON public.campaigns USING btree (domain_id, param_key, param_value);


--
-- Name: idx_camp_rules; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_camp_rules ON public.campaigns USING gin (rules);


--
-- Name: campaigns campaigns_domain_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.campaigns
    ADD CONSTRAINT campaigns_domain_id_fkey FOREIGN KEY (domain_id) REFERENCES public.domains(id) ON DELETE CASCADE;


--
-- Name: campaigns campaigns_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.campaigns
    ADD CONSTRAINT campaigns_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id);


--
-- Name: domains domains_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.domains
    ADD CONSTRAINT domains_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id);


--
-- Name: users users_role_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.users
    ADD CONSTRAINT users_role_id_fkey FOREIGN KEY (role_id) REFERENCES public.roles(id);


--
-- PostgreSQL database dump complete
--

\unrestrict cxEfjTZjQ1Pmh36oKtQJgJUBV440XeJnk6RSmUlmnMnnumtTbbDHslfdr2aSLKK

