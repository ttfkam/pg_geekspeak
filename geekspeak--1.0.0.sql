-- ===========================================================================
-- geekspeak PostgreSQL extension
-- Miles Elam <miles@geekspeak.org>
--
-- Depends on btree_gist, isn, multicorn, pgcrypto plpgsql
-- ---------------------------------------------------------------------------

-- complain if script is sourced in psql, rather than via CREATE EXTENSION
\echo Use "CREATE EXTENSION geekspeak" to load this file. \quit

CREATE TABLE entities (
    created timestamptz DEFAULT now() NOT NULL,
    modified timestamptz DEFAULT now() NOT NULL
);

COMMENT ON TABLE entities IS
'Common features of tables related to modification and creation times.';

COMMENT ON COLUMN entities.created IS
'When the entity was created, relative to the US Pacific timezone.';

COMMENT ON COLUMN entities.modified IS
'When the entity was last updated, relative to the US Pacific timezone. When the entity is first
 created, it holds the same value as "created".';

--
-- Created as a domain to make it easier to identify when being used
--
CREATE DOMAIN episode_num AS smallint;

--
-- Show roles. Some are defunct due to the loss of KUSP, but kept for historical lookup.
--
CREATE TYPE role AS ENUM (
    'authenticated',
    'superuser',
    'host',
    'board',
    'onair',
    'offair',
    'guest',
    'screener',
    'patron'
);

COMMENT ON TYPE role IS
'Show roles. Some are defunct due to the loss of KUSP, but kept for historical lookup.';

--
-- Formerly known as users. Using the term "people" and "person" since "user" is overloaded.
--
CREATE TABLE people (
    id serial NOT NULL PRIMARY KEY,
    email character varying(126) NOT NULL UNIQUE,
    encrypted_password character(60) CHECK (length(encrypted_password) = 60),
    display_name character varying(126),
    bio text,
    description character varying(126),
    acls role[]
) INHERITS (entities) WITH (OIDS = FALSE);

COMMENT ON TABLE people IS
'Formerly known as users. Using the term "people" and "person" since not all those listed will
 directly access the system. Also "user" is such an overloaded term, it does not hurt to avoid
 keyword collisions. To prevent someone from logging in without deleting their account, set the
 acls array to NULL.';

COMMENT ON COLUMN people.encrypted_password IS
'Salted Blowfish. Access through login(email, password, IP, user agent), not directly.';

COMMENT ON COLUMN people.display_name IS
'How you want to be known to the world.';

COMMENT ON COLUMN people.description IS
'How you want to be introduced on the show';

--
-- Logins and persistent sessions
--
CREATE TABLE sessions (
    nonce uuid NOT NULL PRIMARY KEY,
    person integer NOT NULL REFERENCES people(id) ON UPDATE CASCADE ON DELETE RESTRICT,
    expires timestamptz
        DEFAULT (now() + (current_setting('session_duration'::text))::interval) NOT NULL,
    for_reset boolean DEFAULT false NOT NULL,
    ips inet[] NOT NULL,
    user_agent character varying DEFAULT ''::character varying NOT NULL
) INHERITS (entities) WITH (OIDS = FALSE);

ALTER TABLE ONLY sessions
    ADD CONSTRAINT sessions_similarity_gist EXCLUDE
        USING gist (person WITH =, user_agent WITH =, tstzrange(created, expires) WITH &&);

COMMENT ON TABLE sessions IS
'Logins and persistent sessions. Note: not all entries are current. Be sure to check the "expires"
 column for validity. To see just current logins, use the view "user_sessions" instead.';

COMMENT ON COLUMN sessions.nonce IS
'Unique 128-bit session ID';

COMMENT ON COLUMN sessions.for_reset IS
'If this session is for password reset and recovery or for a standard login.';

COMMENT ON COLUMN sessions.ips IS
'IPs the user used to access priviledged portions of the site—e.g., admin, commenting,
 etc.—anything that required credentials.';

COMMENT ON COLUMN sessions.user_agent IS
'The client used to login to the site.';

--
-- Current logins
--
CREATE VIEW active_sessions AS
  SELECT p.id AS user_id, s.nonce, p.email, p.created AS user_registered,
         s.created AS session_created, s.expires AS session_expires,
         (now() - (s.created)::timestamptz) AS logged_in_time, s.for_reset,
         p.display_name, p.bio, p.description, p.acls, s.ips AS session_ips, s.user_agent,
         (p.encrypted_password IS NOT NULL) AS has_password
    FROM people p
    LEFT JOIN sessions s ON ((p.id = s.person))
    WHERE ((s.expires > now()) AND (p.acls IS NOT NULL));

COMMENT ON VIEW active_sessions IS
'Simplified view to see who is logged in, how long they''ve been logged in, and what client
 they''re using. Password and ACLs omitted.';

--
-- Recording locations
--
CREATE TABLE locations (
    id smallserial NOT NULL PRIMARY KEY,
    summary character varying NOT NULL,
    geo point NOT NULL,
    nickname character varying(126) NOT NULL
);

COMMENT ON TABLE locations IS
'Technically just a location with a simple name, but pragmatically where we record our shows.';

COMMENT ON COLUMN locations.id IS
'Unique id with a smallint due to limited number of venues.';

COMMENT ON COLUMN locations.summary IS
'Description of the venue.';

COMMENT ON COLUMN locations.geo IS
'May not be exact lat/lng due to privacy.';

COMMENT ON COLUMN locations.nickname IS
'Short name for easy identification. I.e., see dictionary definition of "nickname"';

--
-- Radio show and podcast episodes
--
CREATE TABLE episodes (
    id serial NOT NULL PRIMARY KEY,
    published timestamptz,
    recorded tstzrange NOT NULL,
    location smallint NOT NULL REFERENCES locations(id) ON UPDATE CASCADE ON DELETE RESTRICT,
    num episode_num NOT NULL UNIQUE,
    guid_override uuid,
    title character varying(126),
    promo text,
    description text,
    transcript text,
    tags character varying(45)[],
    fts tsvector NOT NULL,
    bit_order integer[],
    content text
) INHERITS (entities) WITH (OIDS = FALSE);

COMMENT ON TABLE episodes IS
'Radio show and podcast episodes.';

COMMENT ON COLUMN episodes.title IS
'The episode title or topic.';

COMMENT ON COLUMN episodes.promo IS
'Forward promotion. No longer used, but useful for historial lookup and may be used again.';

COMMENT ON COLUMN episodes.description IS
'General description of the episode, formerly known as the abstract.';

COMMENT ON COLUMN episodes.num IS
'Season and episode number. See: episode_num(season, episode), episode_num(airdate),
 record(episode_num), and text(episode_num)';

COMMENT ON COLUMN episodes.transcript IS
'Hopefully text-to-speech will improve enough for this to become viable and incorporated into
 search and audio files.';

--
-- The people involved in the making, editing, and publishing of an episode.
--
CREATE TABLE participants (
    id smallserial NOT NULL PRIMARY KEY,
    episode integer NOT NULL REFERENCES episodes(id) ON UPDATE CASCADE ON DELETE CASCADE,
    person integer NOT NULL REFERENCES people(id) ON UPDATE CASCADE ON DELETE RESTRICT,
    roles role[] NOT NULL,
    UNIQUE(episode, person)
) INHERITS (entities) WITH (OIDS = FALSE);

CREATE INDEX episodes_published_idx ON episodes USING btree (published DESC NULLS LAST);

CREATE INDEX sessions_expires_for_reset_idx ON sessions
USING btree (expires DESC NULLS LAST, for_reset NULLS FIRST);

CREATE TABLE headlines (
    id serial NOT NULL PRIMARY KEY,
    source character varying(126),
    author character varying(126),
    https boolean DEFAULT false NOT NULL,
    url text NOT NULL UNIQUE,
    locale character varying(5) NOT NULL DEFAULT 'en',
    title character varying(126) NOT NULL DEFAULT 'UNTITLED',
    description text,
    metadata jsonb NOT NULL,
    discussion text,
    labels character varying(50)[],
    added timestamptz DEFAULT now() NOT NULL,
    fts tsvector,
    archived timestamp,
    teaser_image text,
    content text,
    content_type character varying(15) DEFAULT 'article',
    summary text,
    favicon text
);

COMMENT ON TABLE headlines IS
'Raw article information. Should be purged if deemed sufficiently old and not incorporated into an
 episode.';

COMMENT ON COLUMN headlines.source IS
'e.g., New York Times, Wired, BBC';

COMMENT ON COLUMN headlines.url IS
'URL without a protocol so that an https:// link is not considered distinct from http://.';

COMMENT ON COLUMN headlines.title IS
'Headline title.';

COMMENT ON COLUMN headlines.description IS
'Headline description; a summary of the content.';

COMMENT ON COLUMN headlines.discussion IS
'Link to conversation about the topic if anyone needs some perspective.';

COMMENT ON COLUMN headlines.fts IS
'Full Text Search vector';

COMMENT ON COLUMN headlines.archived IS
'If a link goes dead, reference the last archive.org grab.';

COMMENT ON COLUMN headlines.metadata IS
'Raw headline information. Dumping ground for any extra info that doesn''t need direct reference
 from queries.';

COMMENT ON COLUMN headlines.https IS
'Whether a secure URL is available';

COMMENT ON COLUMN headlines.teaser_image IS
'Article-supplied thumbnail image';

COMMENT ON COLUMN headlines.content IS
'Page content; used for search.';

COMMENT ON COLUMN headlines.summary IS
'Not used currently. Placeholder for Chandler''s article summary algorithm.';

COMMENT ON COLUMN headlines.favicon IS
'Used for headline display to help differentiate sources easily.';

CREATE INDEX added_idx ON headlines USING btree (added DESC NULLS LAST);

CREATE INDEX fts_idx ON headlines USING gin (fts);

CREATE TABLE bit_templates (
    id smallserial NOT NULL PRIMARY KEY,
    title character varying(126) NOT NULL,
    description text,
    read_only_message text,
    "order" real DEFAULT 0 NOT NULL
) INHERITS (entities) WITH (OIDS = FALSE);

COMMENT ON TABLE bit_templates IS
'Some of the bits are recurrent parts of the script and thus need to be reproduced and updated for
 each episode. The title and description may be Mustache templates, e.g., {{some_value}}.';

COMMENT ON COLUMN bit_templates.title IS
'Script header.';

COMMENT ON COLUMN bit_templates.description IS
'Script content.';

COMMENT ON COLUMN bit_templates.read_only_message IS
'Script immutable content.';

COMMENT ON COLUMN bit_templates."order" IS
'Script content order.';

CREATE TABLE bits (
    id serial NOT NULL PRIMARY KEY,
    title character varying(126),
    description text,
    headline integer REFERENCES headlines(id) ON UPDATE CASCADE ON DELETE RESTRICT,
    owner integer NOT NULL REFERENCES people(id) ON UPDATE CASCADE ON DELETE RESTRICT,
    episode integer REFERENCES episodes(id) ON UPDATE CASCADE ON DELETE RESTRICT,
    isbn public.ean13,
    public boolean DEFAULT true NOT NULL,
    reference_default smallint REFERENCES bit_templates(id) ON UPDATE CASCADE ON DELETE SET NULL,
    fts tsvector
) INHERITS (entities) WITH (OIDS = FALSE);

COMMENT ON TABLE bits IS
'Bits of an episodes ranging from show script items to blurbs to news headlines.';

COMMENT ON COLUMN bits.headline IS
'Reference to an aggregator headline for show news. If it is missing, it''s assumed to be a blurb
 or, in the case of non-public items, part of the show''s script.';

COMMENT ON COLUMN bits.isbn IS
'Easy method of uniquely referencing printed and media materials.';

COMMENT ON COLUMN bits.public IS
'Whether the info is for public display or just for show notes.';

COMMENT ON COLUMN bits.reference_default IS
'Reference to the bit template so that it can be updated automatically, such as when a new show
 participant joins.';

COMMENT ON COLUMN bits.fts IS
'Full text search (FTS) vector to be used as a base for indexing and searching. When querying from
 the website, don''t forget to limit to public items.';

CREATE UNIQUE INDEX episode_headline_udx ON bits
  USING btree (episode DESC NULLS LAST, headline DESC NULLS LAST);

CREATE OR REPLACE VIEW user_sessions AS
 SELECT p.id AS user_id,
    s.nonce,
    p.email,
    p.created AS user_registered,
    s.created AS session_created,
    s.expires AS session_expires,
    now() - s.created::timestamptz AS logged_in_time,
    s.for_reset,
    p.display_name,
    p.bio,
    p.description,
    p.acls,
    s.ips AS session_ips,
    s.user_agent,
    p.encrypted_password IS NOT NULL AS has_password
   FROM people p
     LEFT JOIN sessions s ON p.id = s.person
  WHERE s.expires > now() AND p.acls IS NOT NULL;

COMMENT ON VIEW user_sessions IS
'Simplified view to see who is logged in, how long they''ve been logged in, and what client
 they''re using. Password and ACLs omitted.';

CREATE FUNCTION source(source text, url text) RETURNS text
LANGUAGE sql IMMUTABLE LEAKPROOF AS $$
  SELECT coalesce(source, regexp_replace(url, '^(?:https?:)?//(?:www\.)?([^/]+)/.+$', '\1'));
$$;

COMMENT ON FUNCTION source(source text, url text) IS
'Provide a headline''s source either by explicit value or by using the domain name.';

CREATE FUNCTION add_headline_bit(article json, submitter integer) RETURNS integer
LANGUAGE sql STRICT LEAKPROOF AS $$
  WITH hl AS (
    INSERT INTO headlines (source, url, title, description, labels, metadata, https,
                           teaser_image, content, favicon)
      VALUES(source(article->>'source', article->>'url'),
           regexp_replace(coalesce(article->>'canonical', article->>'url'), '^https?:(.+)$', '\1'),
           coalesce(article->>'og_title', article->>'title', article->>'twitter_title',
                               article->>'url'),
           article->>'description',
           coalesce(string_to_array(article->>'keywords', ',', '')::varchar[], '{}'::varchar[]),
           jsonb_object('{type,locale}'::text[],
                    array[
                      coalesce(article->>'og_type', 'article'::text),
                      coalesce(article->>'og_locale', article->>'locale', 'en'::text)]),
           position('https://' in coalesce(article->>'canonical', article->>'url')) = 0,
           coalesce(article->>'og_image', article->>'twitter_image', article->>'shortcut_icon',
                    '/favicon.ico'::text),
           article->>'content',
           coalesce(article->>'shortcut_icon', '/favicon.ico'))
      RETURNING id)
  INSERT INTO bits (headline, owner, public)
    (SELECT hl.id, submitter, true from hl)
    RETURNING id
$$;

COMMENT ON FUNCTION add_headline_bit(article json, submitter integer) IS
'Add a bit with a link, specifying the submitter by user ID.';

CREATE FUNCTION add_headline_bit(article json, nonce uuid) RETURNS integer
LANGUAGE sql STABLE STRICT LEAKPROOF AS $$
  SELECT add_headline_bit(article, person)
    FROM (SELECT person FROM sessions WHERE nonce = nonce AND expires > now()) sessions;
$$;

COMMENT ON FUNCTION add_headline_bit(article json, nonce uuid) IS
'Add a bit with a link, specifying the submitter by nonce (session ID).';

CREATE FUNCTION add_ip(ips inet[], ip inet) RETURNS inet[]
LANGUAGE sql IMMUTABLE STRICT LEAKPROOF AS $$
  SELECT CASE WHEN ips[array_upper(ips, 1)] = ip THEN ips ELSE ips || ARRAY[ip] END;
$$;

COMMENT ON FUNCTION add_ip(ips inet[], ip inet) IS
'Appends a new IP address to a list if the last entry is not the same IP. Note: IPv6-safe.';

CREATE FUNCTION authorize(
                  session_id uuid, ip inet, client text,
                  requirement role DEFAULT 'authenticated'::role, OUT authorized boolean,
                  OUT new_expires timestamptz) RETURNS record
LANGUAGE sql STRICT LEAKPROOF AS $$-- Keep the session going either way
  UPDATE sessions
    SET expires = now() + (current_setting('session_duration'))::interval,
        ips = add_ip(ips, ip)
    WHERE nonce = session_id AND user_agent = client AND for_reset = false AND expires > now()
        AND expires > (now() - (current_setting('session_duration')::interval / 2));

  -- Find out if authorized and when the session goes away
  SELECT (acls IS NOT NULL
             AND (acls || '{authenticated}'::role[])
                 && ARRAY['superuser'::role,requirement]) AS authorized,
      nullif(session_expires, now() + current_setting('session_duration')::interval)
          AS new_expires
    FROM user_sessions;
$$;

CREATE FUNCTION reify_url(https boolean, url character varying) RETURNS character varying
LANGUAGE sql IMMUTABLE STRICT LEAKPROOF AS $$
  SELECT CASE WHEN https THEN 'https:' ELSE 'http:' END || url;
$$;

COMMENT ON FUNCTION reify_url(https boolean, url character varying) IS
'Add protocol to a URL. This is necessary because we want http and https to be considered
 equivalent when determining unique headlines.';

CREATE FUNCTION bits(ordered_bits integer[], OUT id integer, OUT source character varying,
                     OUT title character varying, OUT description text,
                     OUT labels character varying[], OUT url character varying,
                     OUT teaser_image character varying, OUT isbn public.ean13,
                     OUT owner character varying) RETURNS SETOF record
LANGUAGE sql STABLE STRICT LEAKPROOF AS $$
  SELECT b.id, h.source, coalesce(b.title, h.metadata->>'title'),
      coalesce(b.description, h.metadata->>'description'), h.labels,
      reify_url(h.https, h.url) AS url, h.teaser_image, b.isbn, p.email
    FROM (SELECT unnest(ordered_bits) AS bit,
                 generate_series(1,array_length(ordered_bits, 1)) as row_num) AS bo,
        bits AS b
    LEFT JOIN headlines as h ON (b.headline = h.id)
    LEFT JOIN people as p on (b.owner = p.id)
    WHERE b.id = bo.bit
    ORDER BY bo.row_num ASC NULLS LAST;
$$;

CREATE FUNCTION bits_as_json(ordered_bits integer[]) RETURNS jsonb
LANGUAGE sql STABLE STRICT LEAKPROOF AS $$
  SELECT jsonb_agg(bits)
    FROM bits(ordered_bits) AS bits;
$$;

CREATE FUNCTION clean_query(query text) RETURNS text
LANGUAGE sql IMMUTABLE STRICT LEAKPROOF AS $$
  WITH raw_query AS
    (SELECT regexp_matches(replace(replace(replace(query, ':title', ':A'), ':description', ':B'), ':content', ':D'), '(\(?)\s*(''[^'']+''|"[^"]+"|[-''a-z0-9]+)\s*(\)?)(:\w)?\s*([&|]?)\s*', 'g') AS tokens)
  SELECT rtrim(string_agg(concat(tokens[1], tokens[2], tokens[3], coalesce(nullif(tokens[4], ''), '&')),''),'&')
    FROM raw_query;
$$;

COMMENT ON FUNCTION clean_query(query text) IS
'Convert the user search query into something the full text search query engine can handle.';

CREATE FUNCTION validate_password(pass text) RETURNS boolean
LANGUAGE sql IMMUTABLE STRICT LEAKPROOF AS $$
  SELECT length(trim(pass)) >= 8
         AND pass ~ '[a-z]'
         AND pass ~ '[A-Z]'
         AND pass ~ '[0-9]'
         AND pass ~ '[^a-zA-Z0-9]'
$$;

COMMENT ON FUNCTION validate_password(pass text) IS
'Verifies the passwords meets or exceeds minimum strength requirements.';

CREATE FUNCTION confirm(nonce uuid, plain_password text, ip inet)
    RETURNS TABLE(person jsonb, nonce uuid)
LANGUAGE sql STRICT AS $$
  -- Set the new password, but only if we're expecting confirmation
  UPDATE people SET encrypted_password = crypt(plain_password, gen_salt('bf', 10))
    WHERE id = (SELECT person
                  FROM sessions
                  WHERE validate_password(plain_password)
                      AND nonce = nonce
                      AND for_reset = true
                      AND expires > now()
                      AND ips[1] = ip)
       AND acls IS NOT NULL;

  -- Extend the session timeout and return the user data, but keep the nonce separate since it is
  -- a session id, not data
  WITH sess AS (
    UPDATE sessions SET nonce = gen_random_uuid(),
                        expires = now() + current_setting('session_duration')::interval,
                        for_reset = false
      WHERE nonce = nonce AND ips[1] = ip
      RETURNING nonce, person, ips[1] = ip AS valid_ip)
  SELECT to_jsonb(userdata) - 'nonce', nonce
    FROM (SELECT email, display_name, description, bio, s.nonce
            FROM people p, sess s
            WHERE nonce = nonce AND p.id = s.person) userdata
  UNION ALL
  SELECT to_jsonb(errors), NULL
    FROM (SELECT validate_password(plain_password) AS valid_password
            WHERE NOT validate_password(plain_password)) errors;
$$;

COMMENT ON FUNCTION confirm(nonce uuid, plain_password text, ip inet) IS
'Confirming valid email address and setting new password. Session is marked no longer for reset,
 and the expiry is pushed out.';

CREATE FUNCTION participants_as_json(episode_num episode_num) RETURNS jsonb
LANGUAGE sql STABLE STRICT LEAKPROOF AS $$
  SELECT jsonb_agg(jsonb_build_object('person', u.display_name, 'description', u.description,
                                      'roles', p.roles))
    FROM participants as p
    LEFT JOIN people as u on (p.person = u.id)
    LEFT JOIN episodes as e on (p.episode = e.id)
    WHERE e.num = episode_num
$$;

CREATE FUNCTION episode_as_json(episode episode_num, lastmod timestamptz,
                                OUT json jsonb, OUT modified timestamptz)
                                RETURNS record
LANGUAGE sql STABLE LEAKPROOF AS $$
  (SELECT jsonb_build_object('episode', num, 'title', title, 'promo', promo,
                             'description', description, 'transcript', transcript,
                             'published', published, 'labels', tags,
                             'bits', bits_as_json(bit_order), 'content', content,
                             'participants', participants_as_json(episode)) AS json,
          modified
    FROM episodes
    WHERE num = episode AND (lastmod IS NULL OR date_trunc('second', modified) <> lastmod)
  UNION ALL
  SELECT NULL::jsonb, lastmod)
  LIMIT 1;
$$;

CREATE FUNCTION episode_num(airdate date DEFAULT ('now'::text)::date) RETURNS episode_num
LANGUAGE sql IMMUTABLE STRICT LEAKPROOF AS $$
  SELECT (((extract(YEAR FROM airdate)::smallint
         + (extract(week from airdate)::smallint / 53) - 2000) << 9)
         + (extract(week from airdate)::smallint % 53))::episode_num;
$$;

COMMENT ON FUNCTION episode_num(airdate date) IS
'Converts a date to a season and episode number.';

CREATE FUNCTION episode_num(season integer, episode integer) RETURNS episode_num
LANGUAGE sql IMMUTABLE STRICT LEAKPROOF AS $$
  SELECT ((season << 9) + episode)::episode_num;
$$;

COMMENT ON FUNCTION episode_num(season integer, episode integer) IS
'Encodes the season and episode into an episode_num (smallint)';

CREATE FUNCTION episodes_fts() RETURNS trigger
LANGUAGE plpgsql AS $$
  BEGIN
  NEW.fts :=
    setweight(to_tsvector((new.title)::text), 'A') ||
    setweight(to_tsvector(coalesce((new.description)::text, '')), 'B') ||
    setweight(to_tsvector((new.content)::text), 'C');
  return NEW;
  END
$$;

COMMENT ON FUNCTION episodes_fts() IS
'Make sure the full text search (FTS) vector is updated for the search index whenever a change is
 made to the episode.';

CREATE FUNCTION favicon() RETURNS TRIGGER
LANGUAGE plpgsql AS $$
  BEGIN
  IF NEW.favicon IS NULL OR NEW.favicon IN ('', 'favicon.ico') THEN
    NEW.favicon := array_to_string(regexp_matches(reify_url(NEW.https, NEW.url)::text,
        '^https?://[^/]+/')::text[], ''::text) || 'favicon.ico';
  END IF;
  return NEW;
  END
$$;

COMMENT ON FUNCTION favicon() IS
'Convert relative favicon URLs to fully qualified URLs.';

CREATE FUNCTION format_query(query text, dict regconfig DEFAULT 'english'::regconfig)
RETURNS tsquery
LANGUAGE sql IMMUTABLE STRICT LEAKPROOF AS $$
  WITH raw_query AS
    (SELECT regexp_matches(replace(replace(replace(replace(query, 'title:', 'A:'), 'description:', 'B:'), 'site:', 'C:'), 'content:', 'D:'), '(\(?)\s*(?:(\w):)?(-?)([a-z0-9][-a-z0-9]+)\s*(\)?)\s*([&|]{0,2})\s*', 'ig') as tokens)
  SELECT to_tsquery(dict,
                    rtrim(string_agg(concat(tokens[1],coalesce(nullif(tokens[3],'-'),'!'),
                                            tokens[4],':',coalesce(nullif(tokens[2],''),'ABCD'),
                                            tokens[5],coalesce(nullif(tokens[6],''),'&')),''),'&'))
    FROM raw_query;
$$;

COMMENT ON FUNCTION format_query(query text, dict regconfig) IS
'Sanitizes input to allow easier boolean searches. Takes an optional dictionary configuration.';

CREATE FUNCTION rank_modifier(age interval) RETURNS real
LANGUAGE sql IMMUTABLE STRICT LEAKPROOF AS $$
  -- 60 seconds * 60 minutes * 24 hours * 7 days
  SELECT (1 / ceil(extract(epoch from age) / 604800))::real;
$$;

COMMENT ON FUNCTION rank_modifier(age interval) IS
'Older stuff should be less likely to show up in search results.';

CREATE FUNCTION rank_modifier(moment timestamptz DEFAULT now()) RETURNS real
LANGUAGE sql IMMUTABLE STRICT LEAKPROOF AS $$
  SELECT rank_modifier(now() - moment);
$$;

COMMENT ON FUNCTION rank_modifier(moment timestamptz) IS
'Older stuff should be less likely to show up in search results.';

CREATE FUNCTION headlines(since interval DEFAULT '7 days'::interval,
                          querytext text DEFAULT ''::text,
                          min_rank real DEFAULT 0.1,
                          lim integer DEFAULT 2000,
                          oset integer DEFAULT 0)
            RETURNS TABLE(id integer, rank real, added date, type character varying,
                          source character varying, title character varying, url text,
                          description text, discussion text, locale character varying,
                          teaser_image text, favicon text, tags character varying[])
LANGUAGE sql STABLE STRICT LEAKPROOF AS $$
  WITH ts AS (SELECT length(querytext) > 0 AS has_query,
                     format_query(querytext) AS query,
                     now() - since AS cutoff)
  (SELECT id, ts_rank(fts, ts.query) * rank_modifier(added) as rank, added::date,
          metadata->>'type', source, title, reify_url(https, url), description, discussion,
          metadata->>'locale', teaser_image, favicon, labels
     FROM headlines h, ts
     WHERE ts.has_query = true AND added > cutoff AND fts @@ ts.query
           AND ts_rank(fts, ts.query) * rank_modifier(added) >= min_rank
     ORDER BY rank DESC, id DESC
     LIMIT lim
     OFFSET oset)
  UNION ALL
  (SELECT id, 10.0 AS rank, added::date, metadata->>'type', source,
          title, reify_url(https, url), description, discussion, metadata->>'locale',
          teaser_image, favicon, labels
     FROM headlines h, ts
     WHERE ts.has_query = false AND added > cutoff
     ORDER BY id DESC
     LIMIT lim
     OFFSET oset)
  ORDER BY rank DESC, id DESC;
$$;

COMMENT ON FUNCTION headlines(since interval, querytext text, min_rank real, lim integer,
                              oset integer) IS
'Browse and search incoming news headlines.';

CREATE FUNCTION headlines_as_json(since interval DEFAULT '7 days'::interval,
                                  query text DEFAULT ''::text, min_rank real DEFAULT 1.0,
                                  lim integer DEFAULT 2000, oset integer DEFAULT 0) RETURNS jsonb
LANGUAGE sql STABLE STRICT LEAKPROOF AS $$
  SELECT coalesce(jsonb_agg(headlines), '[]'::jsonb)
    FROM headlines(since, query, min_rank, lim, oset) as headlines;
$$;

COMMENT ON FUNCTION headlines_as_json(since interval, query text, min_rank real, lim integer,
                                      oset integer) IS
'Browse and search incoming news headlines, returning them as JSON.';

CREATE FUNCTION headlines_fts() RETURNS trigger
LANGUAGE plpgsql AS $$
  BEGIN
  NEW.fts :=
    setweight(to_tsvector((new.title)::text), 'A') ||
    setweight(to_tsvector(coalesce((new.description)::text, '')), 'B') ||
    setweight(to_tsvector((new.source)::text), 'C') ||
    setweight(to_tsvector(coalesce(new.content, '')), 'D');
  return NEW;
  END
$$;

COMMENT ON FUNCTION headlines_fts() IS
'Make sure the full text search (FTS) vector is updated for the search index whenever a change is
 made to the headline.';

CREATE FUNCTION http(ts timestamptz) RETURNS text
LANGUAGE sql IMMUTABLE STRICT LEAKPROOF AS $$
  SELECT http(ts::timestamp);
$$;

CREATE FUNCTION http(ts timestamp) RETURNS text
LANGUAGE sql IMMUTABLE STRICT LEAKPROOF AS $$
  SELECT to_char(ts, 'Dy, DD Mon YYYY HH24:MI:SS');
$$;

CREATE FUNCTION http(ts text) RETURNS timestamp
LANGUAGE sql IMMUTABLE STRICT LEAKPROOF AS $$
  SELECT to_timestamp(ts, 'Dy, DD Mon YYYY HH24:MI:SS')::timestamp;
$$;

CREATE FUNCTION login(email text, plain_password text, ip inet, agent text) RETURNS uuid
LANGUAGE sql STRICT LEAKPROOF AS $$
  -- Create a new session
  WITH auth AS
    (INSERT INTO sessions (nonce, person, ips, user_agent)
      (SELECT coalesce(s.nonce, gen_random_uuid()), id, ARRAY[ip], agent
         FROM people AS p
         LEFT JOIN (SELECT nonce, person
                      FROM sessions
                      WHERE expires > now() AND user_agent = agent) AS s ON p.id = s.person
         WHERE email = email AND acls IS NOT NULL
               AND encrypted_password = crypt(plain_password, encrypted_password))
      ON CONFLICT (nonce) DO UPDATE
          SET ips = add_ip(sessions.ips, ip),
              expires = now() + (current_setting('session_duration'::text))::interval
      RETURNING nonce)
  -- Return the session id to the user
  SELECT nonce
    FROM auth;
$$;

COMMENT ON FUNCTION login(email text, plain_password text, ip inet, agent text) IS
'Authenticate the user by email, password. IP address and user agent are saved as part of the
 session. Return a session ID/nonce on successful login. Logins from the same user on the
 same browser will reuse an existing valid session to avoid session bloat.';

CREATE FUNCTION logout(nonce uuid, ip inet) RETURNS void
LANGUAGE sql STRICT LEAKPROOF AS $$
  UPDATE sessions SET expires = now() - interval '1 second', ips = add_ip(ips, ip)
    WHERE nonce = nonce;
$$;

COMMENT ON FUNCTION logout(nonce uuid, ip inet) IS 'Invalidate the current session.';

CREATE FUNCTION mime_type(file_ext text) RETURNS character varying
LANGUAGE sql IMMUTABLE LEAKPROOF AS $$
  SELECT CASE
  -- images
  WHEN file_ext = 'png' THEN 'image/png'
  WHEN file_ext = 'jpg' THEN 'image/jpeg'
  WHEN file_ext = 'jpeg' THEN 'image/jpeg'
  WHEN file_ext = 'gif' THEN 'image/gif'
  WHEN file_ext = 'tiff' THEN 'image/tiff'
  WHEN file_ext = 'bng' THEN 'image/png'
  WHEN file_ext = 'svg' THEN 'image/xml+svg'
  WHEN file_ext = 'svgz' THEN 'image/xml+svg'
  WHEN file_ext = 'svgb' THEN 'image/xml+svg'
  -- audio
  WHEN file_ext = 'mp3' THEN 'audio/mpeg'
  WHEN file_ext = 'aac' THEN 'audio/mp4'
  WHEN file_ext = 'ogg' THEN 'audio/ogg'
  WHEN file_ext = 'opus' THEN 'audio/ogg'
  WHEN file_ext = 'wav' THEN 'audio/wav'
  WHEN file_ext = 'flac' THEN 'audio/flac'
  --video
  WHEN file_ext = 'mp4' THEN 'video/mp4'
  WHEN file_ext = 'm4v' THEN 'video/mp4'
  WHEN file_ext = 'ogv' THEN 'video/ogg'
  WHEN file_ext = 'webm' THEN 'video/webm'
  -- fallthrough
  ELSE 'application/x-binary'
END $$;


COMMENT ON FUNCTION mime_type(file_ext text) IS
'Get the MIME type from the file extension.';

CREATE FUNCTION modified() RETURNS trigger
LANGUAGE plpgsql AS $$
  BEGIN
  NEW.modified = now();
  RETURN NEW;
  END;
$$;

CREATE FUNCTION episode_part_modified() RETURNS trigger
LANGUAGE plpgsql AS $$
  BEGIN
  UPDATE episodes SET modified = now() WHERE id = OLD.episode OR id = NEW.episode;
  RETURN NEW;
  END;
$$;

CREATE FUNCTION person(nonce uuid, ip inet) RETURNS jsonb
LANGUAGE plpgsql STRICT LEAKPROOF AS $$
  DECLARE
  result jsonb := null;

  BEGIN
  SELECT to_jsonb(userdata)
    INTO STRICT result
    FROM (SELECT email, display_name, description, bio
            FROM people p, sessions s
            WHERE nonce = nonce AND p.id = s.person AND expires > now()
                  AND p.acls IS NOT NULL) userdata;

  IF result IS NOT NULL THEN
    UPDATE sessions
      SET expires = now() + current_setting('session_duration')::interval, ips = add_ip(ips, ip)
      WHERE nonce = nonce AND expires > now();
  END IF;

  RETURN result;
  END;
$$;

COMMENT ON FUNCTION person(nonce uuid, ip inet) IS
'Get the person info as json, sanitized for security. This also updates the session info to extend
 the session expiration and record the current ip address.';

CREATE FUNCTION record(id episode_num) RETURNS TABLE(season smallint, episode smallint)
LANGUAGE sql IMMUTABLE STRICT LEAKPROOF AS $$
  SELECT (id >> 9)::smallint, (id & 511)::smallint;
$$;

COMMENT ON FUNCTION record(id episode_num) IS 'Passing in a value as an episode number
 (episode_no/smallint), the value is parsed and returned as a table row with separate season
 (2016 = 16, 1999 = -1) and episode (usually week number)—all as smallint.

Currently handles:

  seasons -64 through 63 (seven bits including a sign bit)
  episodes 0 - 511 (nine bits, unsigned)
';

CREATE FUNCTION recover(email text, ip inet, user_agent text) RETURNS void
LANGUAGE sql STABLE STRICT AS $$
  INSERT INTO sessions (nonce, person, for_reset, ips)
    (SELECT gen_random_uuid(), id, true, array[ip]
       FROM people
       WHERE email = email and acls IS NOT NULL);
$$;

COMMENT ON FUNCTION recover(email text, ip inet, user_agent text) IS
'Allows password recovery given a person''s email address, IP address, and user agent.';

CREATE FUNCTION register(email text, ip inet, user_agent text)
    RETURNS void
LANGUAGE sql AS $$
  INSERT into people (email, encrypted_password, display_name)
    VALUES(email, '', regexp_replace(email, '@.+$', ''));

  INSERT INTO sessions (nonce, person, for_reset, ips, expires, user_agent)
    VALUES(gen_random_uuid(), lastval(), true, ARRAY[ip], now() + interval '1 hour', user_agent);
$$;

COMMENT ON FUNCTION register(email text, ip inet, user_agent text) IS
'Register a new person with the system. It is expected that the new session ID/nonce will be
 emailed and used to call confirm(nonce, password, ip_address) to enable access.

Note: the person must be given the correct ACLs to perform most actions.';

CREATE FUNCTION text(id episode_num) RETURNS text
LANGUAGE sql IMMUTABLE STRICT LEAKPROOF AS $$
  SELECT 's' || lpad(season::text, 2, '0')
      || 'e' || lpad(episode::text, 2, '0')
    FROM record(id);
$$;

COMMENT ON FUNCTION text(id episode_num) IS
'Converts an encoded episode number (episode_no/smallint) to a user-readable string in the form
 "s16e04b" where the previous signifies season 16 (2016), episode 4 (week 4), slot b (third slot).';

CREATE FUNCTION update_password(email_addr text, old_pass text, new_pass text) RETURNS text
LANGUAGE sql STABLE STRICT LEAKPROOF AS $$
  UPDATE people
    SET encrypted_password = crypt(new_pass, gen_salt('bf', 10))
    WHERE email = email_addr AND encrypted_password = crypt(old_pass, encrypted_password)
          AND validate_password(new_pass)
    RETURNING email;
$$;

COMMENT ON FUNCTION update_password(email_addr text, old_pass text, new_pass text) IS
'Update the password by successfully authenticating with email and old password first. New password
 is subject to password validation as well.';

CREATE SERVER gs_multicorn
  FOREIGN DATA WRAPPER multicorn
  OPTIONS (wrapper 'multicorn.fsfdw.FilesystemFdw');

CREATE FOREIGN TABLE episode_audio_fdt (
    season smallint NOT NULL,
    episode episode_num NOT NULL,
    filename character varying NOT NULL)
  SERVER gs_multicorn
  OPTIONS (
    filename_column 'filename',
    pattern 's{season}e{episode}.mp3',
    root_dir '/var/www/html/media');

CREATE MATERIALIZED VIEW episode_audio AS
  SELECT episode_num(episode_audio_fdt.season,
         (episode_audio_fdt.episode)::smallint) AS episode_num,
         'audio/mpeg'::character varying AS mime_type
    FROM episode_audio_fdt
  WITH NO DATA;

CREATE FOREIGN TABLE episode_files_fdt (
    season character(2) NOT NULL,
    episode character(2) NOT NULL,
    name character varying NOT NULL,
    ext character varying(4) NOT NULL,
    filename character varying NOT NULL,
    content bytea NOT NULL)
  SERVER gs_multicorn
  OPTIONS (
    content_column 'content',
    filename_column 'filename',
    pattern 's{season}e{episode}-{name}.{ext}',
    root_dir '/var/www/html/media');

CREATE FOREIGN TABLE episode_intrinsics_fdt (
    season smallint NOT NULL,
    episode episode_num NOT NULL,
    filename character varying NOT NULL,
    filetype character varying(4) NOT NULL,
    content bytea NOT NULL)
  SERVER gs_multicorn
  OPTIONS (
    content_column 'content',
    filename_column 'filename',
    pattern 's{season}e{episode}.{filetype}',
    root_dir '/var/www/html/media');

CREATE FOREIGN TABLE episode_media_fdt (
    basename character varying NOT NULL,
    filename character varying NOT NULL,
    filetype character varying(4) NOT NULL,
    content bytea NOT NULL)
  SERVER gs_multicorn
  OPTIONS (
    content_column 'content',
    filename_column 'filename',
    pattern '{basename}.{filetype}',
    root_dir '/var/www/html/media');

CREATE TRIGGER headlines_fulltextsearch BEFORE UPDATE ON headlines
  FOR EACH ROW EXECUTE PROCEDURE headlines_fts();

CREATE TRIGGER episodes_fulltextsearch BEFORE UPDATE ON headlines
  FOR EACH ROW EXECUTE PROCEDURE episodes_fts();

CREATE TRIGGER bit_templates_modified BEFORE UPDATE ON bit_templates
  FOR EACH ROW EXECUTE PROCEDURE modified();

CREATE TRIGGER bits_episode_modified AFTER INSERT OR DELETE OR UPDATE ON bits
  FOR EACH ROW EXECUTE PROCEDURE episode_part_modified();

CREATE TRIGGER bits_modified BEFORE UPDATE ON bits FOR EACH ROW EXECUTE PROCEDURE modified();

CREATE TRIGGER episodes_modified BEFORE UPDATE ON episodes
  FOR EACH ROW EXECUTE PROCEDURE modified();

CREATE TRIGGER locations_modified BEFORE UPDATE ON locations
  FOR EACH ROW EXECUTE PROCEDURE modified();

CREATE TRIGGER participants_episode_modified AFTER INSERT OR DELETE OR UPDATE ON participants
  FOR EACH ROW EXECUTE PROCEDURE episode_part_modified();

CREATE TRIGGER participants_modified BEFORE UPDATE ON participants
  FOR EACH ROW EXECUTE PROCEDURE modified();

CREATE TRIGGER people_modified BEFORE UPDATE ON people
  FOR EACH ROW EXECUTE PROCEDURE modified();
