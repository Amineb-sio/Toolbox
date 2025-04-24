--
-- PostgreSQL database dump
--

-- Dumped from database version 15.12 (Debian 15.12-1.pgdg120+1)
-- Dumped by pg_dump version 17.4 (Debian 17.4-1+b1)

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
-- Name: nmap_rapports; Type: TABLE; Schema: public; Owner: toolbox_user
--

CREATE TABLE public.nmap_rapports (
    id integer NOT NULL,
    rapport_id integer,
    nombre_hotes integer,
    ports_ouverts jsonb,
    version_nmap character varying(20),
    arguments_scan text
);


ALTER TABLE public.nmap_rapports OWNER TO toolbox_user;

--
-- Name: nmap_rapports_id_seq; Type: SEQUENCE; Schema: public; Owner: toolbox_user
--

CREATE SEQUENCE public.nmap_rapports_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER SEQUENCE public.nmap_rapports_id_seq OWNER TO toolbox_user;

--
-- Name: nmap_rapports_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: toolbox_user
--

ALTER SEQUENCE public.nmap_rapports_id_seq OWNED BY public.nmap_rapports.id;


--
-- Name: owasp_rapports; Type: TABLE; Schema: public; Owner: toolbox_user
--

CREATE TABLE public.owasp_rapports (
    id integer NOT NULL,
    rapport_id integer,
    cibles text,
    nb_alertes integer,
    risques_critiques integer,
    risques_eleves integer,
    risques_moyens integer,
    risques_faibles integer,
    details_vulnerabilites text
);


ALTER TABLE public.owasp_rapports OWNER TO toolbox_user;

--
-- Name: owasp_rapports_id_seq; Type: SEQUENCE; Schema: public; Owner: toolbox_user
--

CREATE SEQUENCE public.owasp_rapports_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER SEQUENCE public.owasp_rapports_id_seq OWNER TO toolbox_user;

--
-- Name: owasp_rapports_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: toolbox_user
--

ALTER SEQUENCE public.owasp_rapports_id_seq OWNED BY public.owasp_rapports.id;


--
-- Name: rapports; Type: TABLE; Schema: public; Owner: toolbox_user
--

CREATE TABLE public.rapports (
    id integer NOT NULL,
    module character varying(50) NOT NULL,
    format character varying(10) NOT NULL,
    date_creation timestamp without time zone NOT NULL,
    taille_fichier integer NOT NULL,
    chemin_fichier text NOT NULL,
    metadata jsonb
);


ALTER TABLE public.rapports OWNER TO toolbox_user;

--
-- Name: rapports_id_seq; Type: SEQUENCE; Schema: public; Owner: toolbox_user
--

CREATE SEQUENCE public.rapports_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER SEQUENCE public.rapports_id_seq OWNER TO toolbox_user;

--
-- Name: rapports_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: toolbox_user
--

ALTER SEQUENCE public.rapports_id_seq OWNED BY public.rapports.id;


--
-- Name: sqlmap_rapports; Type: TABLE; Schema: public; Owner: toolbox_user
--

CREATE TABLE public.sqlmap_rapports (
    id integer NOT NULL,
    rapport_id integer,
    url_cible text,
    nb_injections_trouvees integer,
    type_injections text,
    db_type character varying(50),
    tables_trouvees text,
    details_exploitation text
);


ALTER TABLE public.sqlmap_rapports OWNER TO toolbox_user;

--
-- Name: sqlmap_rapports_id_seq; Type: SEQUENCE; Schema: public; Owner: toolbox_user
--

CREATE SEQUENCE public.sqlmap_rapports_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER SEQUENCE public.sqlmap_rapports_id_seq OWNER TO toolbox_user;

--
-- Name: sqlmap_rapports_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: toolbox_user
--

ALTER SEQUENCE public.sqlmap_rapports_id_seq OWNED BY public.sqlmap_rapports.id;


--
-- Name: statistiques_utilisation; Type: TABLE; Schema: public; Owner: toolbox_user
--

CREATE TABLE public.statistiques_utilisation (
    id integer NOT NULL,
    module character varying(50) NOT NULL,
    date_utilisation timestamp without time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
    utilisateur character varying(100),
    duree_utilisation integer,
    details json
);


ALTER TABLE public.statistiques_utilisation OWNER TO toolbox_user;

--
-- Name: statistiques_utilisation_id_seq; Type: SEQUENCE; Schema: public; Owner: toolbox_user
--

CREATE SEQUENCE public.statistiques_utilisation_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER SEQUENCE public.statistiques_utilisation_id_seq OWNER TO toolbox_user;

--
-- Name: statistiques_utilisation_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: toolbox_user
--

ALTER SEQUENCE public.statistiques_utilisation_id_seq OWNED BY public.statistiques_utilisation.id;


--
-- Name: wireshark_rapports; Type: TABLE; Schema: public; Owner: toolbox_user
--

CREATE TABLE public.wireshark_rapports (
    id integer NOT NULL,
    rapport_id integer,
    nombre_paquets integer,
    protocoles jsonb,
    interface_capture character varying(50),
    duree_capture character varying(20)
);


ALTER TABLE public.wireshark_rapports OWNER TO toolbox_user;

--
-- Name: wireshark_rapports_id_seq; Type: SEQUENCE; Schema: public; Owner: toolbox_user
--

CREATE SEQUENCE public.wireshark_rapports_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER SEQUENCE public.wireshark_rapports_id_seq OWNER TO toolbox_user;

--
-- Name: wireshark_rapports_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: toolbox_user
--

ALTER SEQUENCE public.wireshark_rapports_id_seq OWNED BY public.wireshark_rapports.id;


--
-- Name: nmap_rapports id; Type: DEFAULT; Schema: public; Owner: toolbox_user
--

ALTER TABLE ONLY public.nmap_rapports ALTER COLUMN id SET DEFAULT nextval('public.nmap_rapports_id_seq'::regclass);


--
-- Name: owasp_rapports id; Type: DEFAULT; Schema: public; Owner: toolbox_user
--

ALTER TABLE ONLY public.owasp_rapports ALTER COLUMN id SET DEFAULT nextval('public.owasp_rapports_id_seq'::regclass);


--
-- Name: rapports id; Type: DEFAULT; Schema: public; Owner: toolbox_user
--

ALTER TABLE ONLY public.rapports ALTER COLUMN id SET DEFAULT nextval('public.rapports_id_seq'::regclass);


--
-- Name: sqlmap_rapports id; Type: DEFAULT; Schema: public; Owner: toolbox_user
--

ALTER TABLE ONLY public.sqlmap_rapports ALTER COLUMN id SET DEFAULT nextval('public.sqlmap_rapports_id_seq'::regclass);


--
-- Name: statistiques_utilisation id; Type: DEFAULT; Schema: public; Owner: toolbox_user
--

ALTER TABLE ONLY public.statistiques_utilisation ALTER COLUMN id SET DEFAULT nextval('public.statistiques_utilisation_id_seq'::regclass);


--
-- Name: wireshark_rapports id; Type: DEFAULT; Schema: public; Owner: toolbox_user
--

ALTER TABLE ONLY public.wireshark_rapports ALTER COLUMN id SET DEFAULT nextval('public.wireshark_rapports_id_seq'::regclass);


--
-- Name: nmap_rapports nmap_rapports_pkey; Type: CONSTRAINT; Schema: public; Owner: toolbox_user
--

ALTER TABLE ONLY public.nmap_rapports
    ADD CONSTRAINT nmap_rapports_pkey PRIMARY KEY (id);


--
-- Name: owasp_rapports owasp_rapports_pkey; Type: CONSTRAINT; Schema: public; Owner: toolbox_user
--

ALTER TABLE ONLY public.owasp_rapports
    ADD CONSTRAINT owasp_rapports_pkey PRIMARY KEY (id);


--
-- Name: rapports rapports_chemin_fichier_key; Type: CONSTRAINT; Schema: public; Owner: toolbox_user
--

ALTER TABLE ONLY public.rapports
    ADD CONSTRAINT rapports_chemin_fichier_key UNIQUE (chemin_fichier);


--
-- Name: rapports rapports_pkey; Type: CONSTRAINT; Schema: public; Owner: toolbox_user
--

ALTER TABLE ONLY public.rapports
    ADD CONSTRAINT rapports_pkey PRIMARY KEY (id);


--
-- Name: sqlmap_rapports sqlmap_rapports_pkey; Type: CONSTRAINT; Schema: public; Owner: toolbox_user
--

ALTER TABLE ONLY public.sqlmap_rapports
    ADD CONSTRAINT sqlmap_rapports_pkey PRIMARY KEY (id);


--
-- Name: statistiques_utilisation statistiques_utilisation_pkey; Type: CONSTRAINT; Schema: public; Owner: toolbox_user
--

ALTER TABLE ONLY public.statistiques_utilisation
    ADD CONSTRAINT statistiques_utilisation_pkey PRIMARY KEY (id);


--
-- Name: wireshark_rapports wireshark_rapports_pkey; Type: CONSTRAINT; Schema: public; Owner: toolbox_user
--

ALTER TABLE ONLY public.wireshark_rapports
    ADD CONSTRAINT wireshark_rapports_pkey PRIMARY KEY (id);


--
-- Name: nmap_rapports nmap_rapports_rapport_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: toolbox_user
--

ALTER TABLE ONLY public.nmap_rapports
    ADD CONSTRAINT nmap_rapports_rapport_id_fkey FOREIGN KEY (rapport_id) REFERENCES public.rapports(id) ON DELETE CASCADE;


--
-- Name: wireshark_rapports wireshark_rapports_rapport_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: toolbox_user
--

ALTER TABLE ONLY public.wireshark_rapports
    ADD CONSTRAINT wireshark_rapports_rapport_id_fkey FOREIGN KEY (rapport_id) REFERENCES public.rapports(id) ON DELETE CASCADE;


--
-- PostgreSQL database dump complete
--

