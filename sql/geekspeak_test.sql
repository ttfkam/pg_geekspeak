--
--  Test geekspeak extension
--

--CREATE EXTENSION geekspeak;  -- fail, must install plpgsql first
--CREATE EXTENSION plpgsql;
CREATE EXTENSION geekspeak;

--
-- Register a user with the system
--

SELECT register('test@example.com', '10.11.12.13', 'Test Agent');

--
-- Faulty confirmation: wrong nonce
--

SELECT person, nonce IS NOT NULL
  FROM confirm(gen_random_uuid(), 'TestPassword1', '10.11.12.13');

--
-- Faulty confirmation: wrong IP
--

WITH cte AS (SELECT nonce FROM sessions WHERE for_reset = true LIMIT 1)
SELECT person, nonce IS NOT NULL
  FROM confirm(cte.nonce, 'TestPassword1', '10.11.12.14');

--
-- Confirm account
--

WITH cte AS (SELECT nonce FROM sessions WHERE for_reset = true LIMIT 1)
SELECT person, nonce IS NOT NULL
  FROM confirm(cte.nonce, 'TestPassword1', '10.11.12.13');

--
-- Verify active logins
--

SELECT count(*)
  FROM sessions
  WHERE for_reset = true OR expires < now();

SELECT count(*)
  FROM sessions
  WHERE for_reset = false AND expires > now();

--
-- Bad login: wrong password
--

SELECT login('test@example.com', 'WrongPassword0', '10.1.2.3', 'Test Agent') IS NOT NULL;

--
-- Successful login
--

SELECT login('test@example.com', 'TestPassword1', '10.1.2.3', 'Test Agent') IS NOT NULL;

--
-- Logout
--

SELECT logout(nonce, '10.1.2.3')
  FROM sessions WHERE for_reset = false AND ips[1] = '10.1.2.3';

--
-- Verify active logins
--

SELECT count(*)
  FROM sessions
  WHERE for_reset = true OR expires < now();

SELECT count(*)
  FROM sessions
  WHERE for_reset = false AND expires > now();

--
-- Add news items
--

SELECT add_headline_bit(
'{
   "source": "Test Framework",
   "url": "https://www.example.com/article/test?id=12345",
   "canonical": "https://www.example.com/a12345",
   "title": "Article 12345",
   "description": "Article 12345 is a test for basic extension functionality.",
   "keywords": "testing,article,extension",
   "og_type": "article",
   "og_locale": "en-US",
   "shortcut_icon": "/favicon.png"
 }'::json,
 (SELECT max(id) FROM people));

SELECT add_headline_bit(
'{
   "source": "Test Framework",
   "url": "https://www.example.com/article/test?id=54321",
   "canonical": "https://www.example.com/a54321",
   "title": "Article 54321",
   "description": "Article 54321 is a followup test for basic extension functionality.",
   "keywords": "testing,article,extension",
   "og_type": "article",
   "og_locale": "en-US",
   "shortcut_icon": "/favicon.png"
 }'::json,
 (SELECT nonce FROM sessions LIMIT 1));

--
-- Utility functions used by clients
--

SELECT http('2016-04-01 16:20'::timestamp);

SELECT http('Fri, 01 Apr 2016 16:20:00');

--
-- Utility functions used internally
--

SELECT add_ip('{"127.0.0.1", "127.0.0.2", "127.0.0.3"}'::inet[], '127.0.0.1'::inet);

SELECT add_ip('{"127.0.0.1", "127.0.0.2", "127.0.0.3"}'::inet[], '127.0.0.4'::inet);

SELECT episode_num('2016-04-01'::date);

SELECT episode_num(16, 12);

SELECT mime_type('png'), mime_type('jpg'), mime_type('svgz'), mime_type('mp3');

SELECT record(8204::episode_num);

SELECT reify_url(true, '//www.example.com/test/https');

SELECT reify_url(false, '//www.example.com/test/http');

SELECT source('New York Times', 'https://www.nytimes.com/articles/testing');

SELECT source(NULL::varchar, 'https://www.nytimes.com/articles/testing');

SELECT source(NULL::varchar, NULL::varchar);

SELECT episode_as_text(8204::episode_num);

SELECT validate_password('password'), validate_password('PASSWORD'), validate_password('pAsSwOrD'),
       validate_password('passwd'), validate_password('Password9'), validate_password('pA$$w0rd');

